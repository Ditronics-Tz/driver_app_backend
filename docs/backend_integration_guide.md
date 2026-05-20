# 📖 Backend Integration & API Specification Guide
## Ride-Hailing Platform — Back-Office Control Panel & Core API

This document serves as the absolute connection contract, data schema guide, and integration blueprint for developers building or integrating with the ride-hailing platform's backend. 

---

## 🧱 1. CONNECTION & ARCHITECTURE OVERVIEW

### 🌐 Base Entry Points
The backend exposes HTTP/S and WebSocket endpoints grouped by scope:
*   **Core Passenger/Driver APIs:** `https://<api-domain>/api/v1/`
*   **Admin/Superadmin back-office APIs:** `https://<api-domain>/api/admin/v1/`
*   **Real-time WebSocket Gateway:** `wss://<api-domain>/ws/admin/`

All API communications require secure TLS 1.3+ transport. Plaintext HTTP traffic is rejected at the reverse proxy (Nginx/Cloudflare) layer.

---

### 🔐 Authentication System (JWT)
Back-office systems use JSON Web Tokens (JWT) for authentication and access control.

#### Token Structure & Lifetimes
*   **Access Token (TTL: 15 Minutes):** Passed in the request headers: `Authorization: Bearer <access_token>`. Short lifespan to minimize hijack windows.
*   **Refresh Token (TTL: 7 Days):** Passed in requests to get a new access/refresh pair. Features token rotation.

#### JWT Token Claims Structure
A decoded Admin Access Token contains the following payload claims:
```json
{
  "token_type": "access",
  "exp": 1779383600,
  "jti": "8f8b056157f14b6ca5ad56461972b21c",
  "user_uuid": "c30985c4-42f2-4bc7-9a9b-dbff9c3a32bd",
  "user_type": "admin",
  "email": "agent.smith@ditronics.com",
  "name": "Smith Agent",
  "role": "support_agent"
}
```

#### Token Rotation, Revocation, and Session Lifetimes
1.  **Token Rotation (RTR):** When a client submits a refresh token to `/auth/refresh/`, the backend invalidates the submitted token and returns a new access/refresh token pair. If a client attempts to reuse a rotated refresh token, the backend triggers a security alert, revokes all tokens descended from that family, and forces immediate re-authentication.
2.  **Session Termination (Logout):** Calling `/auth/logout/` invalidates the provided refresh token and adds it to the token blocklist.
3.  **Password-Induced Revocation:** When an admin resets or changes their password, all active sessions and refresh tokens associated with that user are immediately blocklisted in Redis and PostgreSQL.
4.  **Account Lockout (Brute-Force Protection):** Five consecutive failed password entries on an admin email trigger a temporary account lock. The login endpoint will return `423 Locked` until a 10-minute cool-down period has elapsed.

---

### 🛡️ Role-Based Access Control (RBAC) Permission Matrix
Role-based authorization is enforced at the view layer using a custom Django REST Framework permission class. If an admin has a valid token but lacks the permission for the view action, the API returns `403 Forbidden`.

| Resource / Module | Module Code | superadmin | support_agent | finance | ops_manager |
|---|---|---|---|---|---|
| **System Settings** | `settings` | Read/Write | None | None | None |
| **Admin User Management** | `admin` | Read/Write | None | None | None |
| **Audit Logs** | `audit` | Read | None | None | None |
| **Dashboard Data** | `dashboard` | Read | Read | Read | Read |
| **Passenger Management** | `users` | Read/Write | Read/Write (No Ban/Delete) | None | Read Only |
| **Driver Profile & KYC** | `users` | Read/Write | Read/Write | None | Read Only |
| **Rides (Core & Live)** | `rides` | Read/Write | Read Only | None | Read/Write (Cancel/Reassign) |
| **Payments & Payouts** | `payments` | Read/Write | None | Read/Write | None |
| **Support Tickets** | `support` | Read/Write | Read/Write | None | None |
| **Claims & Disputes** | `claims` | Read/Write | Read/Write | None | None |
| **Operations Live Map** | `operations` | Read | Read | None | Read/Write |
| **Real-time Alerts & SOS** | `alerts` | Read/Write | Read/Write | None | Read/Write |
| **Analytics & CSV Export** | `analytics` | Read/Write | None | Read/Write | Read Only |

---

## 🚦 2. API CONTRACTS & RESPONSE FORMATS

### 🟢 Successful Payload Structures

#### 1. Single Object Retrieval
Returns the resource object directly at the root, using camelCase formatting for keys. Timestamps are formatted as ISO 8601 UTC strings.
```json
{
  "uuid": "4c227eb5-eb7d-41fa-9f8f-fb4c82b090ef",
  "fullName": "John Kamau",
  "email": "john.kamau@mail.com",
  "phoneNumber": "+255712345678",
  "accountStatus": "active",
  "createdAt": "2026-05-20T19:10:42Z",
  "lastLogin": "2026-05-20T21:40:15Z"
}
```

#### 2. Paginated List Response
All lists are paginated. Page size defaults to 20 records (max 100).
```json
{
  "count": 142,
  "next": "https://api.example.com/api/admin/v1/users/passengers/?page=3&search=John",
  "previous": "https://api.example.com/api/admin/v1/users/passengers/?page=1&search=John",
  "results": [
    {
      "uuid": "4c227eb5-eb7d-41fa-9f8f-fb4c82b090ef",
      "fullName": "John Kamau",
      "email": "john.kamau@mail.com",
      "phoneNumber": "+255712345678",
      "accountStatus": "active"
    }
  ]
}
```

---

### 🔴 Error Payload Structures

#### 1. Input Field Validation Error (HTTP 400 Bad Request)
Returned when request parameters fail schema validation rules.
```json
{
  "success": false,
  "message": "Validation failed",
  "errors": [
    {
      "field": "nidaNumber",
      "message": "NIDA number must contain exactly 20 digits."
    },
    {
      "field": "numberOfSeats",
      "message": "Ensure this value is less than or equal to 7."
    }
  ]
}
```

#### 2. Generic Error Response (HTTP 401, 403, 404, 429, 500)
Returned for authentication issues, routing failures, or server crashes.
```json
{
  "success": false,
  "message": "Authentication credentials were not provided."
}
```

#### 🛠️ Standardized Platform Error Codes
When the platform handles domain-specific business logic errors, the errors should map to these categories:
*   `AUTH_REQUIRED` (401): Missing or expired access token.
*   `PERMISSION_DENIED` (403): User role lacks access to this resource or action.
*   `NOT_FOUND` (404): Resource not found.
*   `VALIDATION_ERROR` (400): Schema validation failure.
*   `RATE_LIMITED` (429): Token or IP exceeded request limits.
*   `CONFLICT` (409): Resource state collision (e.g., trying to verify a driver who has already been verified).
*   `INTERNAL_ERROR` (500): Server error occurred.

---

### 💵 Currency, Formatting, and Measurement Standards
1.  **Monetary Amounts:** Sent as integers representing the smallest unit of currency (e.g., cents, TZS Shilingi) to prevent floating-point rounding errors. For example, 15,000 TZS is represented as `15000`.
2.  **Distance & Speed:** Transmitted in metric units. Distance is in kilometers (decimal format), and speed is in km/h.
3.  **Timestamps:** Timestamps must be sent and received as ISO 8601 strings in UTC timezone (`YYYY-MM-DDTHH:MM:SSZ`).

---

## 📂 3. DETAILED ENDPOINT REFERENCE

### 🔐 1. Authentication Module

#### POST `/auth/login/`
Authenticates the user and returns access/refresh token pairs.
*   **Request Headers:** `Content-Type: application/json`
*   **Request Body:**
    ```json
    {
      "email": "ops.lead@ditronics.com",
      "password": "Password123!"
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "access": "eyJ0eXAiOiJKV1QiLCJhbG...",
      "refresh": "eyJ0eXAiOiJKV1QiLCJhbG..."
    }
    ```
*   **Common Error Responses:**
    *   `400 Bad Request`: Missing password or email.
    *   `401 Unauthorized`: Invalid credentials.
    *   `423 Locked`: Too many failed attempts; account locked for 10 minutes.

#### POST `/auth/refresh/`
Rotates the refresh token and returns a new active access/refresh pair.
*   **Request Body:**
    ```json
    {
      "refresh": "eyJ0eXAiOiJKV1QiLCJhbG..."
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "access": "eyJ0eXAiOiJKV1QiLCJhbG_NEW...",
      "refresh": "eyJ0eXAiOiJKV1QiLCJhbG_NEW..."
    }
    ```

#### POST `/auth/logout/`
Blacklists the provided refresh token and invalidates the session.
*   **Request Headers:** `Authorization: Bearer <access_token>`
*   **Request Body:**
    ```json
    {
      "refresh": "eyJ0eXAiOiJKV1QiLCJhbG..."
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "detail": "Logged out."
    }
    ```

#### POST `/auth/forgot-password/`
Generates a time-limited reset token and sends a link to the admin's email.
*   **Request Body:**
    ```json
    {
      "email": "finance.officer@ditronics.com"
    }
    ```
*   **Response (200 OK):**
    *Note: Returns the same message even if the email does not exist to prevent user enumeration.*
    ```json
    {
      "detail": "If the email exists, a reset link will be sent."
    }
    ```

#### POST `/auth/reset-password/`
Resets the password and invalidates all current active user sessions.
*   **Request Body:**
    ```json
    {
      "token": "reset-token-received-in-email-12345",
      "new_password": "NewStrongPassword456!"
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "detail": "Password updated."
    }
    ```

---

### 📊 2. Dashboard Analytics Module

#### GET `/dashboard/stats/`
Provides real-time system metrics for the dashboard widgets.
*   **Response (200 OK):**
    ```json
    {
      "active_rides": 14,
      "online_drivers": 68,
      "revenue_today": 482000,
      "new_registrations_today": 32,
      "open_ticket_count": 8,
      "unresolved_alert_count": 3
    }
    ```

#### GET `/dashboard/revenue-chart/`
Retrieves daily revenue metrics over a specified historical range.
*   **Query Parameters:**
    *   `range` (string, optional): Duration range. Options: `7d` (default) or `30d`.
*   **Response (200 OK):**
    ```json
    [
      { "date": "2026-05-18", "total_amount": 154000 },
      { "date": "2026-05-19", "total_amount": 182000 },
      { "date": "2026-05-20", "total_amount": 212500 }
    ]
    ```

#### GET `/dashboard/ride-chart/`
Retrieves ride status metrics over a specified historical range.
*   **Query Parameters:**
    *   `range` (string, optional): Options: `7d` (default) or `30d`.
*   **Response (200 OK):**
    ```json
    [
      { "date": "2026-05-18", "completed": 45, "cancelled": 5 },
      { "date": "2026-05-19", "completed": 52, "cancelled": 8 },
      { "date": "2026-05-20", "completed": 60, "cancelled": 3 }
    ]
    ```

---

### 👥 3. Passenger & Driver User Management

#### GET `/users/passengers/`
Returns a paginated list of registered passengers.
*   **Query Parameters:**
    *   `search` (string, optional): Filter by name, email, or phone.
    *   `status` (string, optional): Filter by account state. Options: `active`, `suspended`, `banned`.
    *   `page` (int, optional): Target page number.
*   **Response (200 OK):**
    ```json
    {
      "count": 1,
      "next": null,
      "previous": null,
      "results": [
        {
          "uuid": "b6a0bb65-1d07-4e6f-be6a-e24c65ee1a4d",
          "fullName": "Jane Doe",
          "email": "jane.doe@example.com",
          "phoneNumber": "+255711222333",
          "accountStatus": "active"
        }
      ]
    }
    ```

#### POST `/users/passengers/<uuid:user_id>/suspend/`
Suspends a passenger account, preventing new ride bookings.
*   **Request Body:**
    ```json
    {
      "reason": "Violated terms of service: multiple payment failures."
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "detail": "User suspended."
    }
    ```

#### GET `/users/drivers/`
Returns a paginated list of drivers.
*   **Query Parameters:**
    *   `search` (string, optional): Filter by driver name, email, or plate.
    *   `kyc_status` (string, optional): KYC status. Options: `pending`, `approved`, `rejected`.
*   **Response (200 OK):**
    ```json
    {
      "count": 1,
      "results": [
        {
          "id": 1,
          "fullName": "John Kamau",
          "email": "john.kamau@mail.com",
          "kycStatus": "pending",
          "carName": "Toyota Corolla",
          "plateNumber": "T123ABC",
          "submittedAt": "2026-05-20T19:10:42Z"
        }
      ]
    }
    ```

#### GET `/users/drivers/<int:driver_id>/kyc/`
Retrieves pre-signed download URLs for verification photos.
*   **Response (200 OK):**
    ```json
    {
      "profile_photo": "https://object-storage.ditronics.com/drivers/photos/profile.gif?AWSAccessKeyId=...",
      "id_photo": "https://object-storage.ditronics.com/drivers/ids/id.gif?AWSAccessKeyId=...",
      "car_photo": "https://object-storage.ditronics.com/drivers/cars/car.gif?AWSAccessKeyId=..."
    }
    ```

#### POST `/users/drivers/<int:driver_id>/kyc/reject/`
Rejects a driver's KYC application.
*   **Request Body:**
    ```json
    {
      "reason": "ID photo is blurry and unreadable."
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "detail": "KYC rejected."
    }
    ```

---

### 🚗 4. Rides Module

#### GET `/rides/`
Lists all rides (ongoing and historical).
*   **Query Parameters:**
    *   `status` (string, optional): Options: `pending`, `active`, `completed`, `cancelled`.
    *   `search` (string, optional): Search by ride ID, driver name, or passenger name.
*   **Response (200 OK):**
    ```json
    {
      "count": 1,
      "results": [
        {
          "id": 12,
          "status": "completed",
          "passengerName": "Jane Doe",
          "driverName": "John Kamau",
          "pickupLocation": "Mlimani City, Dar es Salaam",
          "dropoffLocation": "Posta, Dar es Salaam",
          "distanceKm": 8.4,
          "fare": 12000,
          "createdAt": "2026-05-20T18:30:00Z"
        }
      ]
    }
    ```

#### POST `/rides/<int:ride_id>/reassign/`
Reassigns an active ride to another driver.
*   **Request Body:**
    ```json
    {
      "new_driver_id": 4,
      "reason": "Driver vehicle broke down mid-route."
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "detail": "Ride reassigned."
    }
    ```

---

### 💳 5. Payments, Payouts, & Refunds Module

#### GET `/payments/payouts/`
Lists driver withdrawal and payout requests.
*   **Response (200 OK):**
    ```json
    {
      "count": 1,
      "results": [
        {
          "id": 3,
          "driverId": 1,
          "amount": 75000,
          "status": "pending",
          "requestedAt": "2026-05-20T15:00:00Z"
        }
      ]
    }
    ```

#### POST `/payments/payouts/bulk-approve/`
Approves multiple payouts in a single batch.
*   **Request Body:**
    ```json
    {
      "payout_ids": [3, 4, 7]
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "detail": "Bulk payouts approved.",
      "count": 3
    }
    ```

---

### 🎫 6. Support Tickets & Claims Module

#### GET `/support/tickets/<int:ticket_id>/messages/`
Lists all messages in a ticket.
*   **Query Parameters:**
    *   `internal` (boolean, optional): Set to `true` to include internal notes.
*   **Response (200 OK):**
    ```json
    [
      {
        "id": 201,
        "body": "Customer reports fare was calculated incorrectly.",
        "senderType": "admin",
        "senderName": "Agent Smith",
        "isInternal": true,
        "timestamp": "2026-05-20T19:40:00Z"
      },
      {
        "id": 202,
        "body": "Please refund the difference of 3000 TZS.",
        "senderType": "admin",
        "senderName": "Agent Smith",
        "isInternal": false,
        "timestamp": "2026-05-20T19:42:00Z"
      }
    ]
    ```

#### POST `/support/claims/<int:claim_id>/resolve/`
Resolves a passenger/driver claim.
*   **Request Body:**
    ```json
    {
      "resolution_type": "refund",
      "resolution_notes": "Claim approved. Refunding overcharged amount."
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "detail": "Claim resolved."
    }
    ```

---

## ⚡ 4. REAL-TIME EVENT STREAMING (WEBSOCKETS)

The WebSocket gateway connects back-office users to real-time events.

### Handshake & Authentication
Establish the WebSocket connection by appending the JWT access token as a query parameter:
```
wss://api.ditronics-ride.com/ws/admin/?token=<access_token>
```
*   If the token is missing, malformed, or expired, the connection is rejected with an HTTP 401 status code.
*   Connections must be terminated and re-established with a new token after token rotation.

---

### Real-Time Event Payload Formats

#### 🚨 1. Alert Notifications (`admin.alerts`)
Broadcasts system alerts to all connected admin consoles.
```json
{
  "stream": "admin.alerts",
  "payload": {
    "alertId": 104,
    "type": "fraud",
    "severity": "critical",
    "description": "User account 'Alice' initiated 5 ride requests in under 2 minutes",
    "linkedEntityType": "user",
    "linkedEntityId": "a1b2c3d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6",
    "createdAt": "2026-05-20T19:10:00Z"
  }
}
```

#### 📊 2. Dashboard Stat Updates (`admin.dashboard`)
Pushes updated counts to dashboards every 30 seconds.
```json
{
  "stream": "admin.dashboard",
  "payload": {
    "active_rides": 15,
    "online_drivers": 74,
    "revenue_today": 512000,
    "new_registrations_today": 36,
    "open_ticket_count": 7,
    "unresolved_alert_count": 4
  }
}
```

#### 💬 3. Live Support Messages (`ticket.{ticket_id}`)
Pushes new messages to admins viewing a specific ticket's details.
```json
{
  "stream": "ticket.24",
  "payload": {
    "messageId": 402,
    "ticketId": 24,
    "body": "I am standing near the post office, but the driver is not here.",
    "senderType": "passenger",
    "senderName": "Jane Passenger",
    "isInternal": false,
    "timestamp": "2026-05-20T19:15:30Z"
  }
}
```

#### 📍 4. Driver Live Locations (`driver.location`)
Sends high-frequency driver coordinates. These are cached in Redis to keep the live map updated.
```json
{
  "stream": "driver.location",
  "payload": {
    "driverId": 18,
    "latitude": -6.792425,
    "longitude": 39.208611,
    "bearing": 175.4,
    "status": "on_trip"
  }
}
```

#### 🆘 5. Critical SOS Alerts (`sos.alerts`)
High-priority emergency alerts. When an SOS is triggered, this event is broadcast to all admin consoles.
```json
{
  "stream": "sos.alerts",
  "payload": {
    "alertId": 801,
    "rideId": 45,
    "driverName": "David Driver",
    "passengerName": "Alice Passenger",
    "coordinates": [-6.812450, 39.284050],
    "timestamp": "2026-05-20T19:17:05Z"
  }
}
```

---

## 📤 5. OBJECT STORAGE FILE UPLOAD FLOW

To keep the application scalable and secure, files are uploaded directly to the object storage service using pre-signed PUT URLs.

### Upload Workflow
```mermaid
sequenceDiagram
    autonumber
    Client ->> API Gateway: POST /api/v1/data/driver/verification/ (Metadata, File Names)
    API Gateway ->> S3 Bucket: Request Presigned URL (15-min TTL)
    S3 Bucket -->> API Gateway: Returns PUT URL + unique file reference key
    API Gateway -->> Client: HTTP 200 (presignedUploadUrl, fileAccessKey)
    Client ->> S3 Bucket: PUT file binary directly to presignedUploadUrl
    Note over Client, S3 Bucket: File transferred securely; bypassing backend server
    Client ->> API Gateway: POST /driver/verification/submit (Submit fileAccessKey)
```

### Constraints & Validations
*   **Allowed File Formats:** `image/jpeg` (`.jpg`, `.jpeg`), `image/png` (`.png`), `image/webp` (`.webp`), and `application/pdf` (`.pdf`).
*   **Max Upload Size:** 10MB per file.
*   **Access Expiration:** Pre-signed URLs for reading files expire after 15 minutes.

---

## 💡 6. FRONTEND INTEGRATION TEMPLATES

### 🔄 1. Axios HTTP Token Refresh Interceptor (ES6)
```javascript
import axios from 'axios';

const api = axios.create({
  baseURL: 'https://api.ditronics-ride.com/api/admin/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

// Request Interceptor: Attach Access Token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response Interceptor: Handle Expired Access Tokens (401)
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response && error.response.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then((token) => {
            originalRequest.headers['Authorization'] = `Bearer ${token}`;
            return api(originalRequest);
          })
          .catch((err) => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      const refreshToken = localStorage.getItem('refreshToken');
      if (!refreshToken) {
        // No refresh token available, force logout
        handleLogoutRedirect();
        return Promise.reject(error);
      }

      try {
        const response = await axios.post('https://api.ditronics-ride.com/api/admin/v1/auth/refresh/', {
          refresh: refreshToken,
        });

        const { access, refresh } = response.data;
        localStorage.setItem('accessToken', access);
        localStorage.setItem('refreshToken', refresh);

        api.defaults.headers.common['Authorization'] = `Bearer ${access}`;
        originalRequest.headers['Authorization'] = `Bearer ${access}`;
        
        processQueue(null, access);
        isRefreshing = false;
        
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        isRefreshing = false;
        handleLogoutRedirect();
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

function handleLogoutRedirect() {
  localStorage.removeItem('accessToken');
  localStorage.removeItem('refreshToken');
  window.location.href = '/login';
}

export default api;
```

---

### 🔌 2. WebSocket Reconnection Logic with Exponential Backoff
```javascript
class ReconnectingWebSocket {
  constructor(url, token) {
    this.url = url;
    this.token = token;
    this.ws = null;
    this.reconnectAttempts = 0;
    this.maxReconnectDelay = 30000; // Max delay: 30 seconds
    this.minReconnectDelay = 1000;   // Min delay: 1 second
    this.onMessageCallback = null;
    
    this.connect();
  }

  connect() {
    const fullUrl = `${this.url}?token=${this.token}`;
    this.ws = new WebSocket(fullUrl);

    this.ws.onopen = () => {
      console.log('WebSocket connection established.');
      this.reconnectAttempts = 0; // Reset reconnection counter on success
    };

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (this.onMessageCallback) {
          this.onMessageCallback(data.stream, data.payload);
        }
      } catch (err) {
        console.error('Failed to parse incoming WebSocket message:', err);
      }
    };

    this.ws.onclose = (event) => {
      console.log('WebSocket connection closed. Attempting reconnect...');
      this.reconnect();
    };

    this.ws.onerror = (error) => {
      console.error('WebSocket encountered an error:', error);
      this.ws.close();
    };
  }

  onMessage(callback) {
    this.onMessageCallback = callback;
  }

  send(stream, payload) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ stream, payload }));
    } else {
      console.warn('Cannot send message. WebSocket is closed.');
    }
  }

  reconnect() {
    // Exponential backoff reconnect formula: delay = minDelay * (2 ^ attempts)
    const delay = Math.min(
      this.maxReconnectDelay,
      this.minReconnectDelay * Math.pow(2, this.reconnectAttempts)
    );

    console.log(`Reconnecting in ${delay}ms...`);
    setTimeout(() => {
      this.reconnectAttempts++;
      this.connect();
    }, delay);
  }

  close() {
    if (this.ws) {
      this.ws.onclose = null; // Prevent reconnection on manual close
      this.ws.close();
    }
  }
}
```
