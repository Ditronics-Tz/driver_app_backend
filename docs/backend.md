# ⚙️ Backend Implementation Spec
## Ride-Hailing Platform — Superadmin & Support Control Panel API

> **Audience:** Backend Team  
> **Stack:** Django + DRF (existing stack), PostgreSQL, Redis, Celery, WebSocket (Django Channels)  
> **No code snippets — clear intent and structure only**

---

## 🧱 ARCHITECTURE OVERVIEW

The backend is a Django REST API serving the superadmin/support frontend. It shares the same Django project as the driver/passenger-facing ride app but adds a separate set of admin-scoped endpoints under `/api/admin/v1/`.

All admin endpoints require:
- A valid JWT access token
- The token must carry a role claim: one of `superadmin`, `support_agent`, `finance`, `ops_manager`
- Role-based permission checks happen at the view layer — not just authentication, but authorization per action

WebSocket support (Django Channels) handles real-time events: driver location updates, alert pushes, ticket messages.

---

## 🔐 AUTH & ROLE SYSTEM

### What to implement

Design the authentication system so that admin users are a **separate user model** (or at minimum a separate profile type) from passengers and drivers. Admin accounts are created only by a superadmin — never through self-registration.

Each admin user has exactly one role. Roles are stored in the database and embedded in the JWT payload at login time.

### Roles and their intent
- **superadmin** — full access to everything, including creating other admins and modifying system settings
- **support_agent** — access to user management (view + suspend), ride details, support tickets, claims, notifications
- **finance** — access to payments, payouts, refunds, analytics, reports
- **ops_manager** — access to live ops map, rides, alerts, analytics, user view-only

### Permission enforcement
Create a custom DRF permission class that reads the role from the JWT and enforces it per view method. The permission matrix is in the frontend spec — the backend must enforce the same rules at the API layer regardless of what the frontend does. Never trust the frontend to enforce security.

### MFA (Optional)
If MFA is implemented, use TOTP. After password validation, issue a short-lived intermediate token. The user submits the TOTP code with the intermediate token and receives the full access + refresh token pair.

### Token Management
- Access token TTL: 15 minutes
- Refresh token TTL: 7 days
- On logout: blacklist the refresh token (use `djangorestframework-simplejwt` blacklist app or equivalent)
- On password change: invalidate all active refresh tokens for that admin user

### Audit on Auth
Every login attempt (success or failure) must be recorded in the audit log with IP address and timestamp. Failed logins for the same account beyond a threshold should trigger a temporary lockout.

---

## 📦 DATA MODELS (What to design — not the code)

These are the admin-specific models or extensions needed. Assume the core ride app already has: `User` (passenger/driver), `Ride`, `Payment`, `DriverProfile`, `VehicleProfile`.

### AdminUser
Represents a back-office user. Fields needed: name, email, hashed password, role, status (active/inactive), last login, created by (FK to another AdminUser), created at, MFA secret (if using TOTP).

### SupportTicket
Fields: ticket ID, subject, body, user (FK — can be passenger or driver), ride (FK, optional), priority (low/medium/high/critical), status (open/in_progress/resolved/closed/escalated), assigned_to (FK to AdminUser), created at, updated at.

### TicketMessage
Fields: ticket (FK), sender type (user or admin), sender ID, body, is_internal (boolean — admin-only notes), attachments (file references), timestamp.

### Claim
Fields: claim ID, type (overcharge/accident/lost_item/driver_misconduct/fraud), filed by (FK to User), against_driver (FK, optional), ride (FK), amount claimed, description, evidence (file references), status (open/under_review/resolved/rejected), resolution type, resolution notes, resolved by (FK to AdminUser), created at, updated at.

### Alert
Fields: alert ID, type (fraud/sos/payment_failure/system_error/driver_misbehavior), severity (info/warning/critical), description, linked entity type (ride/user/driver), linked entity ID, status (active/acknowledged/resolved), acknowledged by (FK), resolved by (FK), created at.

### AuditLog
Fields: log ID, admin user (FK), action (string — e.g. "SUSPEND_DRIVER"), target entity type, target entity ID, old value (JSON), new value (JSON), IP address, timestamp. This table is insert-only — no updates or deletes are ever allowed on audit logs.

### Notification
Fields: notification ID, title, body, target type (all_users/all_drivers/specific_user/all_admins), target ID (nullable), channel (push/sms/email, stored as multi-select), scheduled at (nullable), sent at, status (pending/sent/failed), sent by (FK to AdminUser).

### SystemSetting
Key-value store for all configurable system settings. Fields: key (unique string), value (JSON field), updated by (FK to AdminUser), updated at. Settings are never deleted — only updated.

### InternalChatThread (Optional)
Fields: title, created by, members (M2M to AdminUser), linked ticket (FK, optional), created at.

### InternalChatMessage (Optional)
Fields: thread (FK), sender (FK to AdminUser), body, attachments, timestamp.

---

## 🛣️ API ENDPOINTS

All endpoints are prefixed with `/api/admin/v1/`. All require authentication. All write operations require the appropriate role.

---

### AUTH

**POST `/auth/login/`**  
Accept email + password. Validate credentials. Return access token + refresh token. Log the login attempt.

**POST `/auth/refresh/`**  
Accept refresh token. Return new access token.

**POST `/auth/logout/`**  
Accept refresh token. Blacklist it.

**POST `/auth/forgot-password/`**  
Accept email. If admin user exists, send password reset email with time-limited token link.

**POST `/auth/reset-password/`**  
Accept token + new password. Validate token not expired + not used. Set new password, invalidate all sessions.

**POST `/auth/verify-mfa/`** (if MFA enabled)  
Accept intermediate token + TOTP code. Return full access + refresh tokens.

---

### DASHBOARD

**GET `/dashboard/stats/`**  
Return: active ride count, online driver count, revenue today, new registrations today, open ticket count, unresolved alert count. These numbers must be computed live (from DB or Redis counters). Avoid heavy aggregation — pre-aggregate daily revenue in a Celery task if needed.

**GET `/dashboard/recent-alerts/`**  
Return last 10 unresolved alerts, ordered by created_at desc.

**GET `/dashboard/active-rides/`**  
Return last 20 currently active rides with passenger, driver, pickup zone, status.

**GET `/dashboard/revenue-chart/`**  
Query param: `range` (7d / 30d). Return array of `{date, total_revenue}` for each day in range.

**GET `/dashboard/ride-chart/`**  
Query param: `range`. Return array of `{date, completed, cancelled}`.

---

### USERS — PASSENGERS

**GET `/users/passengers/`**  
List all passengers. Supports query params: `search` (name/email/phone), `status` (active/suspended/banned), `ordering` (registered_date/ride_count), `page`, `page_size`.

**GET `/users/passengers/:id/`**  
Single passenger detail: profile info, wallet balance, total rides, last seen, device info.

**GET `/users/passengers/:id/rides/`**  
Paginated ride history for this passenger.

**GET `/users/passengers/:id/wallet/`**  
Wallet transaction history for this passenger.

**POST `/users/passengers/:id/suspend/`**  
Body: `{reason}`. Set user status to suspended. Write audit log entry.

**POST `/users/passengers/:id/ban/`**  
Body: `{reason}`. Permanent ban. Write audit log.

**POST `/users/passengers/:id/activate/`**  
Reactivate a suspended/banned user. Write audit log.

**POST `/users/passengers/:id/notify/`**  
Body: `{title, body, channel}`. Send targeted notification to this user.

---

### USERS — DRIVERS

**GET `/users/drivers/`**  
List all drivers. Supports: `search`, `kyc_status`, `account_status`, `ordering`, `page`, `page_size`.

**GET `/users/drivers/:id/`**  
Driver detail: profile, vehicle info, KYC status, online status, rating, total trips.

**GET `/users/drivers/:id/kyc/`**  
Return KYC document file references (presigned URLs if using object storage).

**POST `/users/drivers/:id/kyc/approve/`**  
Approve KYC. Set KYC status = approved. Write audit log. Trigger notification to driver.

**POST `/users/drivers/:id/kyc/reject/`**  
Body: `{reason}`. Set KYC status = rejected. Write audit log. Trigger notification.

**GET `/users/drivers/:id/rides/`**  
Paginated ride history for this driver.

**GET `/users/drivers/:id/earnings/`**  
Earnings breakdown: gross, commission deducted, payouts made, pending balance.

**POST `/users/drivers/:id/suspend/`**  
Body: `{reason}`. Write audit log.

**POST `/users/drivers/:id/activate/`**  
Reactivate driver. Write audit log.

---

### RIDES

**GET `/rides/`**  
List all rides. Filters: `status`, `date_from`, `date_to`, `search` (ride ID / passenger name / driver name), `ordering`, `page`, `page_size`.

**GET `/rides/live/`**  
Return all currently active rides with driver current coordinates, passenger info, ETA. Cache in Redis and refresh every 10s via Celery beat.

**GET `/rides/:id/`**  
Full ride detail: route coordinates (polyline points), passenger, driver, timeline events, fare breakdown, payment status.

**POST `/rides/:id/cancel/`**  
Body: `{reason}`. Cancel a live ride. Write audit log. Trigger notifications to both parties.

**POST `/rides/:id/reassign/`**  
Body: `{new_driver_id, reason}`. Reassign an active ride to another driver. Write audit log.

**POST `/rides/:id/refund/`**  
Body: `{amount, reason}`. Issue a refund for this ride. Creates refund record. Write audit log.

**POST `/rides/:id/flag/`**  
Body: `{reason}`. Flag ride for review. Creates an alert.

**GET `/rides/export/`**  
Query params: all filter params above. Return CSV stream with matching rides.

---

### PAYMENTS — TRANSACTIONS

**GET `/payments/transactions/`**  
List all transactions. Filters: `type`, `status`, `date_from`, `date_to`, `search` (transaction ID / user name), `page`.

**GET `/payments/transactions/export/`**  
Same filters, return CSV stream.

---

### PAYMENTS — PAYOUTS

**GET `/payments/payouts/`**  
List all driver payout requests. Filters: `status`, `date_from`, `date_to`, `driver_id`.

**POST `/payments/payouts/:id/approve/`**  
Approve payout. Trigger payout to driver via payment provider (queue Celery task). Write audit log.

**POST `/payments/payouts/:id/reject/`**  
Body: `{reason}`. Reject payout request. Write audit log. Notify driver.

**POST `/payments/payouts/bulk-approve/`**  
Body: `{payout_ids: []}`. Approve multiple payouts. Queue each as individual Celery task.

---

### PAYMENTS — REFUNDS

**GET `/payments/refunds/`**  
List all refund records. Filters: `status`, `date_from`, `date_to`.

**POST `/payments/refunds/:id/approve/`**  
Approve refund request. Queue refund via payment provider. Write audit log.

**POST `/payments/refunds/:id/reject/`**  
Body: `{reason}`. Write audit log. Notify user.

**POST `/payments/refunds/manual/`**  
Body: `{user_id, ride_id, amount, reason}`. Create and immediately process a manual refund. Write audit log.

---

### SUPPORT TICKETS

**GET `/support/tickets/`**  
List all tickets. Filters: `status`, `priority`, `assigned_to`, `date_from`, `date_to`, `search`. Supports `page`.

**POST `/support/tickets/`**  
Body: `{subject, body, user_id, ride_id (optional), priority}`. Create ticket (admin-created on behalf of user or system-generated).

**GET `/support/tickets/:id/`**  
Full ticket detail with all messages (excluding internal notes unless requester is admin).

**PATCH `/support/tickets/:id/`**  
Update ticket: status, priority, assigned_to. Write audit log on status change.

**GET `/support/tickets/:id/messages/`**  
List all messages for this ticket. Query param `internal=true` to include internal notes (admin only).

**POST `/support/tickets/:id/messages/`**  
Body: `{body, is_internal, attachments}`. Send a message or internal note. Triggers WebSocket event to connected admin clients viewing this ticket.

**POST `/support/tickets/:id/assign/`**  
Body: `{admin_user_id}`. Assign ticket to an admin user.

**POST `/support/tickets/:id/escalate/`**  
Body: `{reason}`. Set status to escalated, set priority to critical, notify all support supervisors.

**POST `/support/tickets/:id/close/`**  
Close the ticket. Write audit log.

---

### CLAIMS

**GET `/support/claims/`**  
List all claims. Filters: `type`, `status`, `date_from`, `date_to`, `search`.

**POST `/support/claims/`**  
Body: `{type, filed_by_user_id, against_driver_id (optional), ride_id, amount_claimed, description}`. Create a claim.

**GET `/support/claims/:id/`**  
Full claim detail with evidence file references.

**POST `/support/claims/:id/resolve/`**  
Body: `{resolution_type, resolution_notes}`. Resolve the claim. If resolution_type is `refund` → auto-create refund record. If `driver_suspension` → auto-suspend driver. Write audit log.

**POST `/support/claims/:id/reject/`**  
Body: `{reason}`. Write audit log.

**POST `/support/claims/:id/escalate/`**  
Body: `{reason}`. Escalate claim to critical status.

---

### LIVE OPERATIONS

**GET `/operations/drivers/live/`**  
Return all online drivers with last known coordinates, status (idle/on_trip), current ride ID if on trip.

**GET `/operations/zones/stats/`**  
Return per-zone stats: active rides in zone, idle drivers in zone, demand level, surge multiplier.

**GET `/operations/heatmap/`**  
Return demand heatmap data: array of coordinate clusters with intensity weights, based on ride requests in the last 30 minutes.

---

### ALERTS

**GET `/alerts/`**  
List all alerts. Filters: `type`, `severity`, `status`, `date_from`, `date_to`.

**POST `/alerts/:id/acknowledge/`**  
Mark alert as acknowledged. Record which admin acknowledged it. Write audit log.

**POST `/alerts/:id/resolve/`**  
Body: `{resolution_notes}`. Mark resolved. Write audit log.

**GET `/alerts/sos/`**  
Return all active SOS alerts only.

**POST `/alerts/sos/:id/mark-safe/`**  
Mark SOS as safe (resolved). Write audit log.

---

### ANALYTICS

All analytics endpoints accept `date_from` and `date_to` query params. Heavy queries must be pre-aggregated by Celery daily tasks where possible — do not run raw aggregation on every request.

**GET `/analytics/revenue/`** — daily revenue totals + breakdown

**GET `/analytics/user-growth/`** — new passengers + new drivers per day

**GET `/analytics/ride-trends/`** — completed vs cancelled per day, cancellation rate

**GET `/analytics/driver-performance/`** — top and bottom drivers by rating, trips, earnings

**GET `/analytics/cancellation-analysis/`** — cancellations by reason, by time-of-day

**GET `/analytics/payment/`** — success rate, failed payment reasons breakdown

**GET `/analytics/support/`** — tickets opened vs resolved per day, avg resolution time

**GET `/analytics/export/`**  
Query params: `report_type`, `date_from`, `date_to`, `format` (csv/pdf). For large ranges, queue as async Celery task, return a job ID. Client polls `/analytics/export/status/:job_id/` until done, then downloads from `/analytics/export/download/:job_id/`.

---

### ADMIN MANAGEMENT

**GET `/admin/users/`**  
List all admin users.

**POST `/admin/users/`**  
Body: `{name, email, role}`. Create admin user. Auto-generate a temporary password, send via email. Write audit log.

**PATCH `/admin/users/:id/`**  
Update name, role, status. Superadmin only. Cannot modify own role. Write audit log.

**DELETE `/admin/users/:id/`**  
Deactivate (soft delete) admin user. Write audit log.

**GET `/admin/roles/`**  
List all roles with their permission matrices.

**PATCH `/admin/roles/:role/permissions/`**  
Body: `{permissions: {module: {action: bool}}}`. Update permission matrix for a role. Write audit log.

**GET `/admin/audit-logs/`**  
List audit logs. Filters: `admin_user_id`, `action`, `date_from`, `date_to`, `search` (target entity ID). Read-only. No create/update/delete on this endpoint.

**GET `/admin/audit-logs/export/`**  
CSV export of filtered audit logs.

---

### SYSTEM SETTINGS

**GET `/settings/`**  
Return all system settings as key-value pairs.

**PATCH `/settings/`**  
Body: `{key: value, ...}`. Superadmin only. For each key changed, write an audit log entry with old and new value.

Settings keys to support (at minimum):
- `base_fare`, `per_km_rate`, `per_minute_rate`, `minimum_fare`, `booking_fee`
- `platform_commission_percent` (can be per vehicle type)
- `surge_enabled` (boolean), `surge_max_multiplier`, `surge_trigger_ratio`
- `feature_otp_login`, `feature_wallet_topup`, `feature_tipping`, `feature_in_app_chat`, `feature_referral`
- `support_contact_number`, `app_display_name`, `currency`, `timezone`, `terms_url`, `privacy_url`

---

### NOTIFICATIONS

**GET `/notifications/`**  
List all notification records. Filters: `target_type`, `status`, `date_from`, `date_to`.

**POST `/notifications/send/`**  
Body: `{target_type, target_id (if specific user), channels, title, body, scheduled_at (optional)}`.  
If `scheduled_at` is null → send immediately via Celery task.  
If `scheduled_at` is set → schedule Celery task for that time.  
Write notification record.

**GET `/notifications/:id/`**  
Notification detail with delivery status.

---

### INTERNAL CHAT (Optional)

**GET `/chat/threads/`**  
List all threads the current admin is a member of.

**POST `/chat/threads/`**  
Body: `{title, member_ids, linked_ticket_id (optional)}`. Create thread.

**GET `/chat/threads/:id/messages/`**  
List messages in thread.

**POST `/chat/threads/:id/messages/`**  
Body: `{body, attachments}`. Post message. Triggers WebSocket event to all thread members.

---

## 🔄 REAL-TIME (Django Channels + WebSocket)

### Channels to implement

**`admin.alerts`**  
Broadcast to all connected admin clients when a new alert is created. Payload: alert ID, type, severity, short description.

**`admin.dashboard`**  
Broadcast updated dashboard stat counters every 30 seconds. Celery beat task computes them and pushes to channel layer.

**`ticket.{ticket_id}`**  
Per-ticket channel. When a new message is posted to ticket X, push to all admin clients viewing ticket X. Payload: message content, sender info, timestamp.

**`driver.location`**  
High-frequency channel. Driver app sends location updates → Django Channels consumer receives → stores latest position in Redis → broadcasts to admin clients subscribed to live ops map. Do not write every location update to PostgreSQL — only write to Redis. Persist to DB at ride end or every 60 seconds as a snapshot.

**`sos.alerts`**  
Dedicated channel for SOS events only. When SOS is triggered → push immediately to all admins regardless of their current page. Frontend shows a persistent banner/modal.

### WebSocket Authentication
Every WebSocket connection must authenticate on connect. The client sends the JWT access token in the connection handshake (query param or first message). The Channels consumer validates the token before allowing subscription to any channel.

---

## 📤 FILE UPLOADS & STORAGE

- KYC documents, claim evidence, and ticket attachments must be stored in object storage (S3 or compatible — e.g., Cloudflare R2 or MinIO for self-hosted)
- Never serve uploaded files through Django in production
- Generate presigned URLs with short TTL (15 minutes) when the frontend requests a KYC document or evidence file
- Validate file types on upload: images (jpg, png, webp), PDFs only
- Enforce max file size per upload: 10MB

---

## 🔁 BACKGROUND TASKS (Celery)

| Task | Trigger | Description |
|---|---|---|
| `aggregate_daily_revenue` | Daily at midnight | Sum all completed ride payments for the day, store in analytics table |
| `aggregate_daily_rides` | Daily at midnight | Count completed/cancelled rides per day |
| `send_scheduled_notification` | ETA time of scheduled notification | Dispatch push/SMS/email for scheduled notifications |
| `process_payout` | On payout approval | Call payment provider API to transfer funds to driver |
| `process_refund` | On refund approval | Call payment provider API to issue refund |
| `export_report` | On analytics export request | Generate CSV or PDF, upload to object storage, mark job done |
| `detect_fraud_patterns` | Every 15 minutes | Run fraud detection heuristics on recent rides/payments, create alerts if anomalies found |
| `driver_location_snapshot` | Every 60 seconds | Persist latest Redis driver positions to PostgreSQL for audit trail |
| `close_stale_tickets` | Daily | Auto-close tickets that have been Resolved for more than 7 days with no response |
| `send_dashboard_stats` | Every 30 seconds | Compute dashboard counters and push to Channels layer |

Use Celery with Redis as the broker. Use Celery Beat for scheduled tasks. All tasks should be idempotent where possible.

---

## 📊 PERFORMANCE & CACHING

- Cache dashboard stats in Redis with 30-second TTL — never compute them on every request
- Cache driver online status and last known location in Redis — do not query PostgreSQL for live map
- Use database indexes on: user status, ride status, ticket status + assigned_to, payment status + type, alert status + severity, audit log timestamp + admin user
- For analytics endpoints with date ranges longer than 30 days, require pre-aggregated data from analytics tables populated by Celery tasks. Do not run ad-hoc GROUP BY on the main rides/payments tables for large date ranges
- Use `select_related` and `prefetch_related` on all list endpoints that join across multiple models
- Paginate all list endpoints — default page size 20, max 100

---

## 🛡️ SECURITY REQUIREMENTS

- All admin endpoints must enforce HTTPS in production — reject HTTP connections at reverse proxy level
- Rate limit login endpoint: max 5 attempts per minute per IP, then 429 response
- Rate limit all admin API endpoints: 300 requests per minute per authenticated admin user
- Validate and sanitize all user inputs. Never trust client-provided IDs to skip authorization checks
- CORS: allow only the admin frontend domain, no wildcard origins
- Audit log every state-changing action — no exceptions. The audit log is your compliance and incident response tool
- When an admin account is deactivated, immediately invalidate all their active refresh tokens
- Do not expose internal error details in API responses in production — log internally, return generic error to client

---

## 🧪 TESTING EXPECTATIONS

- Unit tests for all permission classes — verify each role can and cannot access each endpoint
- Integration tests for the core flows: login, suspend user, approve payout, create ticket, resolve claim
- Load test the live ops map endpoint — it must handle 100+ concurrent WebSocket connections
- Test audit log writes on every state-changing action
- Test Celery tasks in isolation with mocked external payment provider calls

---

## 📝 API RESPONSE CONVENTIONS

All endpoints must follow consistent response shapes:

**Success list response:**  
```
{count, next (URL or null), previous (URL or null), results: [...]}
```

**Success single object:** The object directly, with all fields.

**Error response:**  
```
{error: {code: "ERROR_CODE", message: "Human readable message", details: {...} (optional)}}
```

**Common error codes to standardize:**  
`AUTH_REQUIRED`, `PERMISSION_DENIED`, `NOT_FOUND`, `VALIDATION_ERROR`, `RATE_LIMITED`, `CONFLICT`, `INTERNAL_ERROR`

All timestamps must be returned as ISO 8601 UTC strings.  
All monetary amounts must be returned as integers in the smallest currency unit (e.g., cents or TZS shilingi without decimals) to avoid floating point issues.  
Currency and formatting is the frontend's responsibility — the backend always sends raw numbers.
