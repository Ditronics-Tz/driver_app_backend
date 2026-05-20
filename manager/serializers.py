from rest_framework import serializers

from authentication.models import User
from data.models import Driver
from routing.models import Ride

from .models import (
    AdminUser,
    AdminRole,
    SupportTicket,
    TicketMessage,
    Claim,
    Alert,
    AuditLog,
    Notification,
    SystemSetting,
    InternalChatThread,
    InternalChatMessage,
    PaymentTransaction,
    PayoutRequest,
    Refund,
    DailyRevenue,
    DailyRideStats,
    AnalyticsExportJob,
)


class AdminRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminRole
        fields = ("name", "permissions", "updated_at")
        read_only_fields = ("updated_at",)


class AdminUserSerializer(serializers.ModelSerializer):
    role = serializers.SlugRelatedField(slug_field="name", queryset=AdminRole.objects.all())
    created_by = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = AdminUser
        fields = ("uuid", "name", "email", "role", "status", "created_by", "created_at", "last_login")
        read_only_fields = ("uuid", "created_by", "created_at", "last_login")


class AdminUserCreateSerializer(serializers.ModelSerializer):
    role = serializers.SlugRelatedField(slug_field="name", queryset=AdminRole.objects.all())

    class Meta:
        model = AdminUser
        fields = ("name", "email", "role")


class SupportTicketSerializer(serializers.ModelSerializer):
    class Meta:
        model = SupportTicket
        fields = "__all__"


class TicketMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = TicketMessage
        fields = "__all__"


class ClaimSerializer(serializers.ModelSerializer):
    class Meta:
        model = Claim
        fields = "__all__"


class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = "__all__"


class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = "__all__"


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = "__all__"


class SystemSettingSerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemSetting
        fields = ("key", "value", "updated_by", "updated_at")
        read_only_fields = ("updated_by", "updated_at")


class InternalChatThreadSerializer(serializers.ModelSerializer):
    class Meta:
        model = InternalChatThread
        fields = "__all__"


class InternalChatMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = InternalChatMessage
        fields = "__all__"


class PaymentTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentTransaction
        fields = "__all__"


class PayoutRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = PayoutRequest
        fields = "__all__"


class RefundSerializer(serializers.ModelSerializer):
    class Meta:
        model = Refund
        fields = "__all__"


class PassengerSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("uuid", "email", "phone_number", "full_name", "is_active", "account_status", "date_joined")


class DriverSerializer(serializers.ModelSerializer):
    user = PassengerSerializer(read_only=True)

    class Meta:
        model = Driver
        fields = "__all__"


class RideSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ride
        fields = "__all__"


class DailyRevenueSerializer(serializers.ModelSerializer):
    class Meta:
        model = DailyRevenue
        fields = ("date", "total_amount")


class DailyRideStatsSerializer(serializers.ModelSerializer):
    class Meta:
        model = DailyRideStats
        fields = ("date", "completed", "cancelled")


class AnalyticsExportJobSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnalyticsExportJob
        fields = ("job_id", "report_type", "format", "status", "created_at", "completed_at")
