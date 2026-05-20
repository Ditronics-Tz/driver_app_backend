from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone
from django.core.validators import MinValueValidator
import uuid

from authentication.models import User
from data.models import Driver
from routing.models import Ride


class AdminRole(models.Model):
    ROLE_CHOICES = [
        ("superadmin", "Superadmin"),
        ("support_agent", "Support Agent"),
        ("finance", "Finance"),
        ("ops_manager", "Ops Manager"),
    ]

    name = models.CharField(max_length=32, choices=ROLE_CHOICES, unique=True)
    permissions = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        "AdminUser",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="updated_roles",
    )

    class Meta:
        db_table = "manager_admin_role"

    def __str__(self):
        return self.name

    def has_permission(self, module: str, action: str) -> bool:
        role_permissions = self.permissions or {}
        if role_permissions.get("*", {}).get("*") is True:
            return True
        module_permissions = role_permissions.get(module, {})
        return module_permissions.get(action) is True


class AdminUserManager(BaseUserManager):
    def create_user(self, email: str, name: str, password: str, **extra_fields):
        if not email:
            raise ValueError("Admin user must have an email")
        if not name:
            raise ValueError("Admin user must have a name")
        email = self.normalize_email(email)
        admin_user = self.model(email=email, name=name, **extra_fields)
        admin_user.set_password(password)
        admin_user.save(using=self._db)
        return admin_user

    def create_superuser(self, email: str, name: str, password: str, **extra_fields):
        extra_fields.setdefault("status", AdminUser.STATUS_ACTIVE)
        extra_fields.setdefault("is_staff", True)
        return self.create_user(email=email, name=name, password=password, **extra_fields)


class AdminUser(AbstractBaseUser):
    STATUS_ACTIVE = "active"
    STATUS_INACTIVE = "inactive"

    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Active"),
        (STATUS_INACTIVE, "Inactive"),
    ]

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, db_index=True)
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    role = models.ForeignKey(AdminRole, on_delete=models.PROTECT, related_name="admin_users")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    created_by = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_admins",
    )
    created_at = models.DateTimeField(default=timezone.now)
    mfa_secret = models.CharField(max_length=255, blank=True)
    is_staff = models.BooleanField(default=False)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name"]

    objects = AdminUserManager()

    class Meta:
        db_table = "manager_admin_user"
        indexes = [
            models.Index(fields=["email"], name="admin_user_email_idx"),
            models.Index(fields=["status"], name="admin_user_status_idx"),
            models.Index(fields=["uuid"], name="admin_user_uuid_idx"),
        ]

    def __str__(self):
        return self.email

    @property
    def is_active(self):
        return self.status == self.STATUS_ACTIVE


class AdminRefreshToken(models.Model):
    admin_user = models.ForeignKey(AdminUser, on_delete=models.CASCADE, related_name="refresh_tokens")
    jti = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(max_length=255, blank=True)

    class Meta:
        db_table = "manager_admin_refresh_token"
        indexes = [
            models.Index(fields=["admin_user", "revoked_at"], name="admin_token_active_idx"),
            models.Index(fields=["expires_at"], name="admin_token_expires_idx"),
        ]

    def revoke(self, reason: str = ""):
        self.revoked_at = timezone.now()
        self.revoked_reason = reason
        self.save(update_fields=["revoked_at", "revoked_reason"])

    @property
    def is_active(self):
        return self.revoked_at is None and self.expires_at > timezone.now()


class AdminPasswordResetToken(models.Model):
    admin_user = models.ForeignKey(AdminUser, on_delete=models.CASCADE, related_name="password_reset_tokens")
    token = models.CharField(max_length=128, unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "manager_admin_password_reset_token"
        indexes = [
            models.Index(fields=["admin_user", "expires_at"], name="admin_reset_token_idx"),
        ]

    @property
    def is_valid(self):
        return self.used_at is None and self.expires_at > timezone.now()


class AuditLog(models.Model):
    admin_user = models.ForeignKey(AdminUser, on_delete=models.SET_NULL, null=True, related_name="audit_logs")
    action = models.CharField(max_length=64)
    target_type = models.CharField(max_length=64)
    target_id = models.CharField(max_length=64)
    old_value = models.JSONField(null=True, blank=True)
    new_value = models.JSONField(null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "manager_audit_log"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["created_at"], name="audit_log_created_idx"),
            models.Index(fields=["admin_user"], name="audit_log_admin_idx"),
            models.Index(fields=["target_type", "target_id"], name="audit_log_target_idx"),
        ]

    def __str__(self):
        return f"{self.action} by {self.admin_user_id}"


class SupportTicket(models.Model):
    PRIORITY_LOW = "low"
    PRIORITY_MEDIUM = "medium"
    PRIORITY_HIGH = "high"
    PRIORITY_CRITICAL = "critical"

    STATUS_OPEN = "open"
    STATUS_IN_PROGRESS = "in_progress"
    STATUS_RESOLVED = "resolved"
    STATUS_CLOSED = "closed"
    STATUS_ESCALATED = "escalated"

    PRIORITY_CHOICES = [
        (PRIORITY_LOW, "Low"),
        (PRIORITY_MEDIUM, "Medium"),
        (PRIORITY_HIGH, "High"),
        (PRIORITY_CRITICAL, "Critical"),
    ]
    STATUS_CHOICES = [
        (STATUS_OPEN, "Open"),
        (STATUS_IN_PROGRESS, "In Progress"),
        (STATUS_RESOLVED, "Resolved"),
        (STATUS_CLOSED, "Closed"),
        (STATUS_ESCALATED, "Escalated"),
    ]

    subject = models.CharField(max_length=255)
    body = models.TextField()
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="support_tickets")
    ride = models.ForeignKey(Ride, on_delete=models.SET_NULL, null=True, blank=True, related_name="support_tickets")
    priority = models.CharField(max_length=16, choices=PRIORITY_CHOICES, default=PRIORITY_LOW)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_OPEN)
    assigned_to = models.ForeignKey(
        AdminUser, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_tickets"
    )
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "manager_support_ticket"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "assigned_to"], name="ticket_status_assigned_idx"),
        ]

    def __str__(self):
        return f"Ticket {self.id}: {self.subject}"


class TicketMessage(models.Model):
    SENDER_USER = "user"
    SENDER_ADMIN = "admin"

    SENDER_CHOICES = [
        (SENDER_USER, "User"),
        (SENDER_ADMIN, "Admin"),
    ]

    ticket = models.ForeignKey(SupportTicket, on_delete=models.CASCADE, related_name="messages")
    sender_type = models.CharField(max_length=8, choices=SENDER_CHOICES)
    sender_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="ticket_messages")
    sender_admin = models.ForeignKey(
        AdminUser, on_delete=models.SET_NULL, null=True, blank=True, related_name="ticket_messages"
    )
    body = models.TextField()
    is_internal = models.BooleanField(default=False)
    attachments = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "manager_ticket_message"
        ordering = ["created_at"]
        indexes = [
            models.Index(fields=["ticket", "created_at"], name="ticket_message_ticket_idx"),
        ]


class Claim(models.Model):
    TYPE_OVERCHARGE = "overcharge"
    TYPE_ACCIDENT = "accident"
    TYPE_LOST_ITEM = "lost_item"
    TYPE_DRIVER_MISCONDUCT = "driver_misconduct"
    TYPE_FRAUD = "fraud"

    STATUS_OPEN = "open"
    STATUS_UNDER_REVIEW = "under_review"
    STATUS_RESOLVED = "resolved"
    STATUS_REJECTED = "rejected"

    CLAIM_TYPES = [
        (TYPE_OVERCHARGE, "Overcharge"),
        (TYPE_ACCIDENT, "Accident"),
        (TYPE_LOST_ITEM, "Lost Item"),
        (TYPE_DRIVER_MISCONDUCT, "Driver Misconduct"),
        (TYPE_FRAUD, "Fraud"),
    ]
    STATUS_CHOICES = [
        (STATUS_OPEN, "Open"),
        (STATUS_UNDER_REVIEW, "Under Review"),
        (STATUS_RESOLVED, "Resolved"),
        (STATUS_REJECTED, "Rejected"),
    ]

    claim_type = models.CharField(max_length=32, choices=CLAIM_TYPES)
    filed_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="claims")
    against_driver = models.ForeignKey(Driver, on_delete=models.SET_NULL, null=True, blank=True, related_name="claims")
    ride = models.ForeignKey(Ride, on_delete=models.SET_NULL, null=True, blank=True, related_name="claims")
    amount_claimed = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    description = models.TextField()
    evidence = models.JSONField(default=list, blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_OPEN)
    resolution_type = models.CharField(max_length=32, blank=True)
    resolution_notes = models.TextField(blank=True)
    resolved_by = models.ForeignKey(
        AdminUser, on_delete=models.SET_NULL, null=True, blank=True, related_name="resolved_claims"
    )
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "manager_claim"
        ordering = ["-created_at"]


class Alert(models.Model):
    TYPE_FRAUD = "fraud"
    TYPE_SOS = "sos"
    TYPE_PAYMENT_FAILURE = "payment_failure"
    TYPE_SYSTEM_ERROR = "system_error"
    TYPE_DRIVER_MISBEHAVIOR = "driver_misbehavior"

    SEVERITY_INFO = "info"
    SEVERITY_WARNING = "warning"
    SEVERITY_CRITICAL = "critical"

    STATUS_ACTIVE = "active"
    STATUS_ACK = "acknowledged"
    STATUS_RESOLVED = "resolved"

    type = models.CharField(max_length=32)
    severity = models.CharField(max_length=16)
    description = models.TextField()
    linked_entity_type = models.CharField(max_length=32, blank=True)
    linked_entity_id = models.CharField(max_length=64, blank=True)
    status = models.CharField(max_length=16, default=STATUS_ACTIVE)
    acknowledged_by = models.ForeignKey(
        AdminUser, on_delete=models.SET_NULL, null=True, blank=True, related_name="acknowledged_alerts"
    )
    resolved_by = models.ForeignKey(
        AdminUser, on_delete=models.SET_NULL, null=True, blank=True, related_name="resolved_alerts"
    )
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "manager_alert"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "severity"], name="alert_status_severity_idx"),
        ]


class Notification(models.Model):
    TARGET_ALL_USERS = "all_users"
    TARGET_ALL_DRIVERS = "all_drivers"
    TARGET_SPECIFIC_USER = "specific_user"
    TARGET_ALL_ADMINS = "all_admins"

    STATUS_PENDING = "pending"
    STATUS_SENT = "sent"
    STATUS_FAILED = "failed"

    title = models.CharField(max_length=255)
    body = models.TextField()
    target_type = models.CharField(max_length=32)
    target_id = models.CharField(max_length=64, blank=True)
    channels = models.JSONField(default=list)
    scheduled_at = models.DateTimeField(null=True, blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=16, default=STATUS_PENDING)
    sent_by = models.ForeignKey(AdminUser, on_delete=models.SET_NULL, null=True, related_name="notifications_sent")
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "manager_notification"
        ordering = ["-created_at"]


class SystemSetting(models.Model):
    key = models.CharField(max_length=64, unique=True)
    value = models.JSONField(default=dict)
    updated_by = models.ForeignKey(AdminUser, on_delete=models.SET_NULL, null=True, related_name="settings_updated")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "manager_system_setting"

    def __str__(self):
        return self.key


class InternalChatThread(models.Model):
    title = models.CharField(max_length=255)
    created_by = models.ForeignKey(AdminUser, on_delete=models.SET_NULL, null=True, related_name="chat_threads_created")
    members = models.ManyToManyField(AdminUser, related_name="chat_threads")
    linked_ticket = models.ForeignKey(
        SupportTicket, on_delete=models.SET_NULL, null=True, blank=True, related_name="chat_threads"
    )
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "manager_internal_chat_thread"


class InternalChatMessage(models.Model):
    thread = models.ForeignKey(InternalChatThread, on_delete=models.CASCADE, related_name="messages")
    sender = models.ForeignKey(AdminUser, on_delete=models.SET_NULL, null=True, related_name="chat_messages")
    body = models.TextField()
    attachments = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "manager_internal_chat_message"
        ordering = ["created_at"]


class PaymentTransaction(models.Model):
    TYPE_RIDE = "ride"
    TYPE_WALLET = "wallet"

    STATUS_PENDING = "pending"
    STATUS_SUCCESS = "success"
    STATUS_FAILED = "failed"

    transaction_type = models.CharField(max_length=16, default=TYPE_RIDE)
    status = models.CharField(max_length=16, default=STATUS_PENDING)
    amount = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name="payment_transactions")
    ride = models.ForeignKey(Ride, on_delete=models.SET_NULL, null=True, blank=True, related_name="payment_transactions")
    provider_reference = models.CharField(max_length=128, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "manager_payment_transaction"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "transaction_type"], name="payment_status_type_idx"),
        ]


class PayoutRequest(models.Model):
    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"

    driver = models.ForeignKey(Driver, on_delete=models.CASCADE, related_name="payout_requests")
    amount = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    status = models.CharField(max_length=16, default=STATUS_PENDING)
    requested_at = models.DateTimeField(default=timezone.now)
    approved_at = models.DateTimeField(null=True, blank=True)
    rejected_at = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(blank=True)

    class Meta:
        db_table = "manager_payout_request"
        ordering = ["-requested_at"]


class Refund(models.Model):
    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name="refunds")
    ride = models.ForeignKey(Ride, on_delete=models.SET_NULL, null=True, blank=True, related_name="refunds")
    amount = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    reason = models.TextField(blank=True)
    status = models.CharField(max_length=16, default=STATUS_PENDING)
    created_at = models.DateTimeField(default=timezone.now)
    approved_at = models.DateTimeField(null=True, blank=True)
    rejected_at = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(blank=True)

    class Meta:
        db_table = "manager_refund"
        ordering = ["-created_at"]


class DailyRevenue(models.Model):
    date = models.DateField(unique=True)
    total_amount = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = "manager_daily_revenue"


class DailyRideStats(models.Model):
    date = models.DateField(unique=True)
    completed = models.PositiveIntegerField(default=0)
    cancelled = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = "manager_daily_ride_stats"


class AnalyticsExportJob(models.Model):
    STATUS_PENDING = "pending"
    STATUS_DONE = "done"
    STATUS_FAILED = "failed"

    job_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    report_type = models.CharField(max_length=32)
    format = models.CharField(max_length=8, default="csv")
    status = models.CharField(max_length=16, default=STATUS_PENDING)
    file_content = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "manager_analytics_export_job"
