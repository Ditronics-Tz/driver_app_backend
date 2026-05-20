import csv
import io
import secrets
from datetime import timedelta

from django.contrib.auth.password_validation import validate_password
from django.core.mail import send_mail
from django.db.models import Count, Q, Sum
from django.utils import timezone
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from authentication.models import User
from data.models import Driver
from routing.models import Ride

from .authentication import AdminJWTAuthentication
from .models import (
    AdminUser,
    AdminRole,
    AdminRefreshToken,
    AdminPasswordResetToken,
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
from .permissions import AdminRolePermission
from .serializers import (
    AdminUserSerializer,
    AdminUserCreateSerializer,
    AdminRoleSerializer,
    SupportTicketSerializer,
    TicketMessageSerializer,
    ClaimSerializer,
    AlertSerializer,
    AuditLogSerializer,
    NotificationSerializer,
    SystemSettingSerializer,
    InternalChatThreadSerializer,
    InternalChatMessageSerializer,
    PaymentTransactionSerializer,
    PayoutRequestSerializer,
    RefundSerializer,
    PassengerSerializer,
    DriverSerializer,
    RideSerializer,
    DailyRevenueSerializer,
    DailyRideStatsSerializer,
    AnalyticsExportJobSerializer,
)
from .services import build_admin_tokens, ensure_default_roles, log_audit, revoke_admin_tokens
from .tasks import send_scheduled_notification, export_report
from .utils import error_response


def _client_ip(request):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


class AdminAPIView(GenericAPIView):
    authentication_classes = [AdminJWTAuthentication]
    permission_classes = [AdminRolePermission]


class AdminLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        ensure_default_roles()
        email = request.data.get("email")
        password = request.data.get("password")
        if not email or not password:
            return error_response("VALIDATION_ERROR", "Email and password are required.", status_code=400)

        admin_user = AdminUser.objects.select_related("role").filter(email=email).first()
        ip_address = _client_ip(request)

        if not admin_user:
            AuditLog.objects.create(
                admin_user=None,
                action="ADMIN_LOGIN_FAILED",
                target_type="AdminUser",
                target_id=email,
                old_value=None,
                new_value=None,
                ip_address=ip_address,
            )
            return error_response("AUTH_REQUIRED", "Invalid credentials.", status_code=401)

        if admin_user.status != AdminUser.STATUS_ACTIVE:
            return error_response("PERMISSION_DENIED", "Admin account inactive.", status_code=403)

        if admin_user.locked_until and admin_user.locked_until > timezone.now():
            return error_response("AUTH_REQUIRED", "Account locked. Try again later.", status_code=423)

        if not admin_user.check_password(password):
            admin_user.failed_login_attempts += 1
            if admin_user.failed_login_attempts >= 5:
                admin_user.locked_until = timezone.now() + timedelta(minutes=10)
            admin_user.save(update_fields=["failed_login_attempts", "locked_until"])
            log_audit(admin_user, "ADMIN_LOGIN_FAILED", "AdminUser", admin_user.uuid, None, None, ip_address)
            return error_response("AUTH_REQUIRED", "Invalid credentials.", status_code=401)

        admin_user.failed_login_attempts = 0
        admin_user.locked_until = None
        admin_user.last_login = timezone.now()
        admin_user.save(update_fields=["failed_login_attempts", "locked_until", "last_login"])
        log_audit(admin_user, "ADMIN_LOGIN_SUCCESS", "AdminUser", admin_user.uuid, None, None, ip_address)

        tokens = build_admin_tokens(admin_user)
        return Response(tokens)


class AdminRefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return error_response("VALIDATION_ERROR", "Refresh token is required.", status_code=400)

        try:
            token = RefreshToken(refresh_token)
        except Exception:
            return error_response("AUTH_REQUIRED", "Invalid refresh token.", status_code=401)

        if token.get("user_type") != "admin":
            return error_response("AUTH_REQUIRED", "Invalid refresh token.", status_code=401)

        jti = token.get("jti")
        stored = AdminRefreshToken.objects.filter(jti=jti, revoked_at__isnull=True).first()
        if not stored or not stored.is_active:
            return error_response("AUTH_REQUIRED", "Refresh token revoked.", status_code=401)

        admin_user = AdminUser.objects.select_related("role").filter(uuid=token.get("user_uuid")).first()
        if not admin_user or not admin_user.is_active:
            return error_response("AUTH_REQUIRED", "Admin user inactive.", status_code=401)

        stored.revoke("rotated")
        tokens = build_admin_tokens(admin_user)
        return Response(tokens)


class AdminLogoutView(APIView):
    authentication_classes = [AdminJWTAuthentication]
    permission_classes = [AdminRolePermission]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return error_response("VALIDATION_ERROR", "Refresh token is required.", status_code=400)

        try:
            token = RefreshToken(refresh_token)
        except Exception:
            return error_response("AUTH_REQUIRED", "Invalid refresh token.", status_code=401)

        if token.get("user_type") != "admin":
            return error_response("AUTH_REQUIRED", "Invalid refresh token.", status_code=401)

        stored = AdminRefreshToken.objects.filter(jti=token.get("jti")).first()
        if stored:
            stored.revoke("logout")
        return Response({"detail": "Logged out."})


class AdminForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        if not email:
            return error_response("VALIDATION_ERROR", "Email is required.", status_code=400)

        admin_user = AdminUser.objects.filter(email=email).first()
        if not admin_user:
            return Response({"detail": "If the email exists, a reset link will be sent."})

        token = secrets.token_urlsafe(32)
        expires_at = timezone.now() + timedelta(hours=1)
        AdminPasswordResetToken.objects.create(admin_user=admin_user, token=token, expires_at=expires_at)

        reset_link = f"{request.build_absolute_uri('/')}admin-reset?token={token}"
        send_mail(
            "Admin password reset",
            f"Use this link to reset your password: {reset_link}",
            None,
            [admin_user.email],
            fail_silently=True,
        )
        return Response({"detail": "If the email exists, a reset link will be sent."})


class AdminResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get("token")
        new_password = request.data.get("new_password")
        if not token or not new_password:
            return error_response("VALIDATION_ERROR", "Token and new password are required.", status_code=400)

        reset_token = AdminPasswordResetToken.objects.select_related("admin_user").filter(token=token).first()
        if not reset_token or not reset_token.is_valid:
            return error_response("AUTH_REQUIRED", "Invalid or expired token.", status_code=401)

        validate_password(new_password)
        admin_user = reset_token.admin_user
        admin_user.set_password(new_password)
        admin_user.save(update_fields=["password"])
        reset_token.used_at = timezone.now()
        reset_token.save(update_fields=["used_at"])
        revoke_admin_tokens(admin_user, "password_reset")
        log_audit(admin_user, "RESET_PASSWORD", "AdminUser", admin_user.uuid, None, None, _client_ip(request))
        return Response({"detail": "Password updated."})


class DashboardStatsView(AdminAPIView):
    permission_map = {"GET": ("dashboard", "view")}

    def get(self, request):
        active_rides = Ride.objects.filter(status="active").count()
        online_drivers = Driver.objects.count()
        revenue_today = PaymentTransaction.objects.filter(
            status=PaymentTransaction.STATUS_SUCCESS,
            created_at__date=timezone.now().date(),
        ).aggregate(total=Sum("amount"))["total"] or 0
        new_registrations = User.objects.filter(date_joined__date=timezone.now().date()).count()
        open_tickets = SupportTicket.objects.filter(status__in=[SupportTicket.STATUS_OPEN, SupportTicket.STATUS_IN_PROGRESS]).count()
        unresolved_alerts = Alert.objects.filter(status=Alert.STATUS_ACTIVE).count()

        return Response({
            "active_rides": active_rides,
            "online_drivers": online_drivers,
            "revenue_today": revenue_today,
            "new_registrations_today": new_registrations,
            "open_ticket_count": open_tickets,
            "unresolved_alert_count": unresolved_alerts,
        })


class DashboardRecentAlertsView(AdminAPIView):
    permission_map = {"GET": ("dashboard", "view")}

    def get(self, request):
        alerts = Alert.objects.filter(status=Alert.STATUS_ACTIVE).order_by("-created_at")[:10]
        serializer = AlertSerializer(alerts, many=True)
        return Response(serializer.data)


class DashboardActiveRidesView(AdminAPIView):
    permission_map = {"GET": ("dashboard", "view")}

    def get(self, request):
        rides = Ride.objects.filter(status="active").order_by("-created_at")[:20]
        serializer = RideSerializer(rides, many=True)
        return Response(serializer.data)


class DashboardRevenueChartView(AdminAPIView):
    permission_map = {"GET": ("dashboard", "view")}

    def get(self, request):
        range_param = request.query_params.get("range", "7d")
        days = 7 if range_param == "7d" else 30
        since = timezone.now().date() - timedelta(days=days - 1)
        data = DailyRevenue.objects.filter(date__gte=since).order_by("date")
        serializer = DailyRevenueSerializer(data, many=True)
        return Response(serializer.data)


class DashboardRideChartView(AdminAPIView):
    permission_map = {"GET": ("dashboard", "view")}

    def get(self, request):
        range_param = request.query_params.get("range", "7d")
        days = 7 if range_param == "7d" else 30
        since = timezone.now().date() - timedelta(days=days - 1)
        data = DailyRideStats.objects.filter(date__gte=since).order_by("date")
        serializer = DailyRideStatsSerializer(data, many=True)
        return Response(serializer.data)


class PassengerListView(AdminAPIView):
    permission_map = {"GET": ("users", "view")}

    def get(self, request):
        queryset = User.objects.all().order_by("-date_joined")
        search = request.query_params.get("search")
        if search:
            queryset = queryset.filter(
                Q(full_name__icontains=search) | Q(email__icontains=search) | Q(phone_number__icontains=search)
            )
        status_param = request.query_params.get("status")
        if status_param:
            queryset = queryset.filter(account_status=status_param)
        page = self.paginate_queryset(queryset)
        serializer = PassengerSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class PassengerDetailView(AdminAPIView):
    permission_map = {"GET": ("users", "view")}

    def get(self, request, user_id):
        user = User.objects.filter(uuid=user_id).first()
        if not user:
            return error_response("NOT_FOUND", "User not found.", status_code=404)
        serializer = PassengerSerializer(user)
        return Response(serializer.data)


class PassengerRidesView(AdminAPIView):
    permission_map = {"GET": ("users", "view")}

    def get(self, request, user_id):
        rides = Ride.objects.filter(passenger__uuid=user_id).order_by("-created_at")
        page = self.paginate_queryset(rides)
        serializer = RideSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class PassengerWalletView(AdminAPIView):
    permission_map = {"GET": ("users", "view")}

    def get(self, request, user_id):
        return Response({"transactions": []})


class PassengerNotifyView(AdminAPIView):
    permission_map = {"POST": ("users", "notify")}

    def post(self, request, user_id):
        user = User.objects.filter(uuid=user_id).first()
        if not user:
            return error_response("NOT_FOUND", "User not found.", status_code=404)
        payload = request.data.copy()
        payload["target_type"] = Notification.TARGET_SPECIFIC_USER
        payload["target_id"] = str(user.uuid)
        serializer = NotificationSerializer(data=payload)
        if not serializer.is_valid():
            return error_response("VALIDATION_ERROR", "Invalid payload.", serializer.errors, status_code=400)
        notification = serializer.save(sent_by=request.user)
        log_audit(request.user, "NOTIFY_USER", "Notification", notification.id, None, serializer.data, _client_ip(request))
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class PassengerSuspendView(AdminAPIView):
    permission_map = {"POST": ("users", "suspend")}

    def post(self, request, user_id):
        reason = request.data.get("reason", "")
        user = User.objects.filter(uuid=user_id).first()
        if not user:
            return error_response("NOT_FOUND", "User not found.", status_code=404)
        old_value = {"account_status": user.account_status}
        user.account_status = User.STATUS_SUSPENDED
        user.is_active = False
        user.save(update_fields=["account_status", "is_active"])
        log_audit(request.user, "SUSPEND_USER", "User", user.uuid, old_value, {"reason": reason}, _client_ip(request))
        return Response({"detail": "User suspended."})


class PassengerBanView(AdminAPIView):
    permission_map = {"POST": ("users", "ban")}

    def post(self, request, user_id):
        reason = request.data.get("reason", "")
        user = User.objects.filter(uuid=user_id).first()
        if not user:
            return error_response("NOT_FOUND", "User not found.", status_code=404)
        old_value = {"account_status": user.account_status}
        user.account_status = User.STATUS_BANNED
        user.is_active = False
        user.save(update_fields=["account_status", "is_active"])
        log_audit(request.user, "BAN_USER", "User", user.uuid, old_value, {"reason": reason}, _client_ip(request))
        return Response({"detail": "User banned."})


class PassengerActivateView(AdminAPIView):
    permission_map = {"POST": ("users", "activate")}

    def post(self, request, user_id):
        user = User.objects.filter(uuid=user_id).first()
        if not user:
            return error_response("NOT_FOUND", "User not found.", status_code=404)
        old_value = {"account_status": user.account_status}
        user.account_status = User.STATUS_ACTIVE
        user.is_active = True
        user.save(update_fields=["account_status", "is_active"])
        log_audit(request.user, "ACTIVATE_USER", "User", user.uuid, old_value, {"status": user.account_status}, _client_ip(request))
        return Response({"detail": "User activated."})


class DriverListView(AdminAPIView):
    permission_map = {"GET": ("users", "view")}

    def get(self, request):
        queryset = Driver.objects.select_related("user").all().order_by("-submitted_at")
        search = request.query_params.get("search")
        if search:
            queryset = queryset.filter(
                Q(full_name__icontains=search)
                | Q(user__email__icontains=search)
                | Q(user__phone_number__icontains=search)
            )
        kyc_status = request.query_params.get("kyc_status")
        if kyc_status:
            queryset = queryset.filter(status=kyc_status)
        page = self.paginate_queryset(queryset)
        serializer = DriverSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class DriverDetailView(AdminAPIView):
    permission_map = {"GET": ("users", "view")}

    def get(self, request, driver_id):
        driver = Driver.objects.select_related("user").filter(id=driver_id).first()
        if not driver:
            return error_response("NOT_FOUND", "Driver not found.", status_code=404)
        serializer = DriverSerializer(driver)
        return Response(serializer.data)


class DriverKycView(AdminAPIView):
    permission_map = {"GET": ("users", "view")}

    def get(self, request, driver_id):
        driver = Driver.objects.filter(id=driver_id).first()
        if not driver:
            return error_response("NOT_FOUND", "Driver not found.", status_code=404)
        return Response({
            "profile_photo": driver.profile_photo.url if driver.profile_photo else None,
            "id_photo": driver.id_photo.url if driver.id_photo else None,
            "car_photo": driver.car_photo.url if driver.car_photo else None,
        })


class DriverRidesView(AdminAPIView):
    permission_map = {"GET": ("users", "view")}

    def get(self, request, driver_id):
        rides = Ride.objects.filter(driver_id=driver_id).order_by("-created_at")
        page = self.paginate_queryset(rides)
        serializer = RideSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class DriverEarningsView(AdminAPIView):
    permission_map = {"GET": ("users", "view")}

    def get(self, request, driver_id):
        total = PaymentTransaction.objects.filter(ride__driver_id=driver_id, status=PaymentTransaction.STATUS_SUCCESS).aggregate(
            total=Sum("amount")
        )["total"] or 0
        payouts = PayoutRequest.objects.filter(driver_id=driver_id, status=PayoutRequest.STATUS_APPROVED).aggregate(
            total=Sum("amount")
        )["total"] or 0
        return Response({"gross": total, "payouts_made": payouts, "pending_balance": max(total - payouts, 0)})


class DriverSuspendView(AdminAPIView):
    permission_map = {"POST": ("users", "suspend")}

    def post(self, request, driver_id):
        driver = Driver.objects.select_related("user").filter(id=driver_id).first()
        if not driver:
            return error_response("NOT_FOUND", "Driver not found.", status_code=404)
        old_value = {"account_status": driver.user.account_status}
        driver.user.account_status = User.STATUS_SUSPENDED
        driver.user.is_active = False
        driver.user.save(update_fields=["account_status", "is_active"])
        log_audit(request.user, "SUSPEND_DRIVER", "Driver", driver.id, old_value, {"status": driver.user.account_status}, _client_ip(request))
        return Response({"detail": "Driver suspended."})


class DriverActivateView(AdminAPIView):
    permission_map = {"POST": ("users", "activate")}

    def post(self, request, driver_id):
        driver = Driver.objects.select_related("user").filter(id=driver_id).first()
        if not driver:
            return error_response("NOT_FOUND", "Driver not found.", status_code=404)
        old_value = {"account_status": driver.user.account_status}
        driver.user.account_status = User.STATUS_ACTIVE
        driver.user.is_active = True
        driver.user.save(update_fields=["account_status", "is_active"])
        log_audit(request.user, "ACTIVATE_DRIVER", "Driver", driver.id, old_value, {"status": driver.user.account_status}, _client_ip(request))
        return Response({"detail": "Driver activated."})


class DriverKycApproveView(AdminAPIView):
    permission_map = {"POST": ("users", "update")}

    def post(self, request, driver_id):
        driver = Driver.objects.filter(id=driver_id).first()
        if not driver:
            return error_response("NOT_FOUND", "Driver not found.", status_code=404)
        old_value = {"status": driver.status}
        driver.status = "approved"
        driver.reviewed_at = timezone.now()
        driver.save(update_fields=["status", "reviewed_at"])
        log_audit(request.user, "APPROVE_KYC", "Driver", driver.id, old_value, {"status": driver.status}, _client_ip(request))
        return Response({"detail": "KYC approved."})


class DriverKycRejectView(AdminAPIView):
    permission_map = {"POST": ("users", "update")}

    def post(self, request, driver_id):
        reason = request.data.get("reason", "")
        driver = Driver.objects.filter(id=driver_id).first()
        if not driver:
            return error_response("NOT_FOUND", "Driver not found.", status_code=404)
        old_value = {"status": driver.status}
        driver.status = "rejected"
        driver.reviewed_at = timezone.now()
        driver.reviewer_notes = reason
        driver.save(update_fields=["status", "reviewed_at", "reviewer_notes"])
        log_audit(request.user, "REJECT_KYC", "Driver", driver.id, old_value, {"status": driver.status}, _client_ip(request))
        return Response({"detail": "KYC rejected."})


class RideListView(AdminAPIView):
    permission_map = {"GET": ("rides", "view")}

    def get(self, request):
        queryset = Ride.objects.all().order_by("-created_at")
        status_filter = request.query_params.get("status")
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        page = self.paginate_queryset(queryset)
        serializer = RideSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class RideDetailView(AdminAPIView):
    permission_map = {"GET": ("rides", "view")}

    def get(self, request, ride_id):
        ride = Ride.objects.filter(id=ride_id).first()
        if not ride:
            return error_response("NOT_FOUND", "Ride not found.", status_code=404)
        serializer = RideSerializer(ride)
        return Response(serializer.data)


class RideCancelView(AdminAPIView):
    permission_map = {"POST": ("rides", "cancel")}

    def post(self, request, ride_id):
        reason = request.data.get("reason", "")
        ride = Ride.objects.filter(id=ride_id).first()
        if not ride:
            return error_response("NOT_FOUND", "Ride not found.", status_code=404)
        old_value = {"status": ride.status}
        ride.status = "cancelled"
        ride.cancel_reason = reason
        ride.cancelled_at = timezone.now()
        ride.save(update_fields=["status", "cancel_reason", "cancelled_at"])
        log_audit(request.user, "CANCEL_RIDE", "Ride", ride.id, old_value, {"reason": reason}, _client_ip(request))
        return Response({"detail": "Ride cancelled."})


class RideReassignView(AdminAPIView):
    permission_map = {"POST": ("rides", "reassign")}

    def post(self, request, ride_id):
        new_driver_id = request.data.get("new_driver_id")
        reason = request.data.get("reason", "")
        ride = Ride.objects.filter(id=ride_id).first()
        driver = Driver.objects.filter(id=new_driver_id).first()
        if not ride or not driver:
            return error_response("NOT_FOUND", "Ride or driver not found.", status_code=404)
        old_value = {"driver_id": ride.driver_id}
        ride.driver = driver
        ride.save(update_fields=["driver"])
        log_audit(request.user, "REASSIGN_RIDE", "Ride", ride.id, old_value, {"driver_id": driver.id, "reason": reason}, _client_ip(request))
        return Response({"detail": "Ride reassigned."})


class RideRefundView(AdminAPIView):
    permission_map = {"POST": ("rides", "refund")}

    def post(self, request, ride_id):
        amount = request.data.get("amount")
        reason = request.data.get("reason", "")
        ride = Ride.objects.filter(id=ride_id).first()
        try:
            amount_val = int(amount)
        except (TypeError, ValueError):
            amount_val = None
        if not ride or amount_val is None:
            return error_response("VALIDATION_ERROR", "Ride and amount are required.", status_code=400)
        refund = Refund.objects.create(
            user=ride.passenger if ride.passenger else None,
            ride=ride,
            amount=amount_val,
            reason=reason,
            status=Refund.STATUS_APPROVED,
            approved_at=timezone.now(),
        )
        log_audit(request.user, "REFUND_RIDE", "Ride", ride.id, None, {"refund_id": refund.id}, _client_ip(request))
        return Response({"detail": "Refund issued."})


class RideFlagView(AdminAPIView):
    permission_map = {"POST": ("rides", "flag")}

    def post(self, request, ride_id):
        reason = request.data.get("reason", "")
        ride = Ride.objects.filter(id=ride_id).first()
        if not ride:
            return error_response("NOT_FOUND", "Ride not found.", status_code=404)
        alert = Alert.objects.create(
            type=Alert.TYPE_FRAUD,
            severity=Alert.SEVERITY_WARNING,
            description=reason or "Ride flagged for review",
            linked_entity_type="ride",
            linked_entity_id=str(ride.id),
        )
        log_audit(request.user, "FLAG_RIDE", "Ride", ride.id, None, {"alert_id": alert.id}, _client_ip(request))
        return Response({"detail": "Ride flagged."})


class RideExportView(AdminAPIView):
    permission_map = {"GET": ("rides", "view")}

    def get(self, request):
        rows = Ride.objects.all().order_by("-created_at").values(
            "id", "status", "created_at", "distance_km", "duration_min"
        )
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["id", "status", "created_at", "distance_km", "duration_min"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        response = Response(output.getvalue(), content_type="text/csv")
        response["Content-Disposition"] = "attachment; filename=rides.csv"
        return response


class TransactionListView(AdminAPIView):
    permission_map = {"GET": ("payments", "view")}

    def get(self, request):
        queryset = PaymentTransaction.objects.all().order_by("-created_at")
        page = self.paginate_queryset(queryset)
        serializer = PaymentTransactionSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class TransactionExportView(AdminAPIView):
    permission_map = {"GET": ("payments", "export")}

    def get(self, request):
        rows = PaymentTransaction.objects.all().order_by("-created_at").values(
            "id", "transaction_type", "status", "amount", "created_at"
        )
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["id", "transaction_type", "status", "amount", "created_at"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        response = Response(output.getvalue(), content_type="text/csv")
        response["Content-Disposition"] = "attachment; filename=transactions.csv"
        return response


class PayoutListView(AdminAPIView):
    permission_map = {"GET": ("payments", "view")}

    def get(self, request):
        queryset = PayoutRequest.objects.all().order_by("-requested_at")
        page = self.paginate_queryset(queryset)
        serializer = PayoutRequestSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class PayoutApproveView(AdminAPIView):
    permission_map = {"POST": ("payments", "approve")}

    def post(self, request, payout_id):
        payout = PayoutRequest.objects.filter(id=payout_id).first()
        if not payout:
            return error_response("NOT_FOUND", "Payout not found.", status_code=404)
        old_value = {"status": payout.status}
        payout.status = PayoutRequest.STATUS_APPROVED
        payout.approved_at = timezone.now()
        payout.save(update_fields=["status", "approved_at"])
        log_audit(request.user, "APPROVE_PAYOUT", "PayoutRequest", payout.id, old_value, {"status": payout.status}, _client_ip(request))
        return Response({"detail": "Payout approved."})


class PayoutRejectView(AdminAPIView):
    permission_map = {"POST": ("payments", "reject")}

    def post(self, request, payout_id):
        reason = request.data.get("reason", "")
        payout = PayoutRequest.objects.filter(id=payout_id).first()
        if not payout:
            return error_response("NOT_FOUND", "Payout not found.", status_code=404)
        old_value = {"status": payout.status}
        payout.status = PayoutRequest.STATUS_REJECTED
        payout.rejected_at = timezone.now()
        payout.rejection_reason = reason
        payout.save(update_fields=["status", "rejected_at", "rejection_reason"])
        log_audit(request.user, "REJECT_PAYOUT", "PayoutRequest", payout.id, old_value, {"reason": reason}, _client_ip(request))
        return Response({"detail": "Payout rejected."})


class PayoutBulkApproveView(AdminAPIView):
    permission_map = {"POST": ("payments", "approve")}

    def post(self, request):
        payout_ids = request.data.get("payout_ids", [])
        payouts = PayoutRequest.objects.filter(id__in=payout_ids)
        for payout in payouts:
            payout.status = PayoutRequest.STATUS_APPROVED
            payout.approved_at = timezone.now()
            payout.save(update_fields=["status", "approved_at"])
        log_audit(request.user, "BULK_APPROVE_PAYOUT", "PayoutRequest", "bulk", None, {"count": payouts.count()}, _client_ip(request))
        return Response({"detail": "Bulk payouts approved.", "count": payouts.count()})


class RefundListView(AdminAPIView):
    permission_map = {"GET": ("payments", "view")}

    def get(self, request):
        queryset = Refund.objects.all().order_by("-created_at")
        page = self.paginate_queryset(queryset)
        serializer = RefundSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class RefundApproveView(AdminAPIView):
    permission_map = {"POST": ("payments", "approve")}

    def post(self, request, refund_id):
        refund = Refund.objects.filter(id=refund_id).first()
        if not refund:
            return error_response("NOT_FOUND", "Refund not found.", status_code=404)
        refund.status = Refund.STATUS_APPROVED
        refund.approved_at = timezone.now()
        refund.save(update_fields=["status", "approved_at"])
        log_audit(request.user, "APPROVE_REFUND", "Refund", refund.id, None, {"status": refund.status}, _client_ip(request))
        return Response({"detail": "Refund approved."})


class RefundRejectView(AdminAPIView):
    permission_map = {"POST": ("payments", "reject")}

    def post(self, request, refund_id):
        reason = request.data.get("reason", "")
        refund = Refund.objects.filter(id=refund_id).first()
        if not refund:
            return error_response("NOT_FOUND", "Refund not found.", status_code=404)
        refund.status = Refund.STATUS_REJECTED
        refund.rejected_at = timezone.now()
        refund.rejection_reason = reason
        refund.save(update_fields=["status", "rejected_at", "rejection_reason"])
        log_audit(request.user, "REJECT_REFUND", "Refund", refund.id, None, {"reason": reason}, _client_ip(request))
        return Response({"detail": "Refund rejected."})


class RefundManualView(AdminAPIView):
    permission_map = {"POST": ("payments", "refund")}

    def post(self, request):
        user_id = request.data.get("user_id")
        ride_id = request.data.get("ride_id")
        amount = request.data.get("amount")
        reason = request.data.get("reason", "")
        user = User.objects.filter(uuid=user_id).first()
        ride = Ride.objects.filter(id=ride_id).first() if ride_id else None
        try:
            amount_val = int(amount)
        except (TypeError, ValueError):
            amount_val = None
        if not user or amount_val is None:
            return error_response("VALIDATION_ERROR", "User and amount are required.", status_code=400)
        refund = Refund.objects.create(
            user=user,
            ride=ride,
            amount=amount_val,
            reason=reason,
            status=Refund.STATUS_APPROVED,
            approved_at=timezone.now(),
        )
        log_audit(request.user, "MANUAL_REFUND", "Refund", refund.id, None, {"amount": amount_val}, _client_ip(request))
        return Response({"detail": "Manual refund processed."})


class SupportTicketListCreateView(AdminAPIView):
    permission_map = {"GET": ("support", "view"), "POST": ("support", "create")}

    def get(self, request):
        queryset = SupportTicket.objects.all().order_by("-created_at")
        page = self.paginate_queryset(queryset)
        serializer = SupportTicketSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)

    def post(self, request):
        serializer = SupportTicketSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("VALIDATION_ERROR", "Invalid payload.", serializer.errors, status_code=400)
        ticket = serializer.save()
        log_audit(request.user, "CREATE_TICKET", "SupportTicket", ticket.id, None, serializer.data, _client_ip(request))
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class SupportTicketDetailView(AdminAPIView):
    permission_map = {"GET": ("support", "view"), "PATCH": ("support", "update")}

    def get(self, request, ticket_id):
        ticket = SupportTicket.objects.filter(id=ticket_id).first()
        if not ticket:
            return error_response("NOT_FOUND", "Ticket not found.", status_code=404)
        serializer = SupportTicketSerializer(ticket)
        return Response(serializer.data)

    def patch(self, request, ticket_id):
        ticket = SupportTicket.objects.filter(id=ticket_id).first()
        if not ticket:
            return error_response("NOT_FOUND", "Ticket not found.", status_code=404)
        old_value = {"status": ticket.status, "priority": ticket.priority, "assigned_to": ticket.assigned_to_id}
        serializer = SupportTicketSerializer(ticket, data=request.data, partial=True)
        if not serializer.is_valid():
            return error_response("VALIDATION_ERROR", "Invalid payload.", serializer.errors, status_code=400)
        serializer.save()
        log_audit(request.user, "UPDATE_TICKET", "SupportTicket", ticket.id, old_value, serializer.data, _client_ip(request))
        return Response(serializer.data)


class SupportTicketMessagesView(AdminAPIView):
    permission_map = {"GET": ("support", "view"), "POST": ("support", "update")}

    def get(self, request, ticket_id):
        ticket = SupportTicket.objects.filter(id=ticket_id).first()
        if not ticket:
            return error_response("NOT_FOUND", "Ticket not found.", status_code=404)
        include_internal = request.query_params.get("internal") == "true"
        queryset = ticket.messages.all()
        if not include_internal:
            queryset = queryset.filter(is_internal=False)
        serializer = TicketMessageSerializer(queryset, many=True)
        return Response(serializer.data)

    def post(self, request, ticket_id):
        ticket = SupportTicket.objects.filter(id=ticket_id).first()
        if not ticket:
            return error_response("NOT_FOUND", "Ticket not found.", status_code=404)
        payload = request.data.copy()
        payload["ticket"] = ticket.id
        payload["sender_type"] = "admin"
        payload["sender_admin"] = request.user.id
        serializer = TicketMessageSerializer(data=payload)
        if not serializer.is_valid():
            return error_response("VALIDATION_ERROR", "Invalid payload.", serializer.errors, status_code=400)
        message = serializer.save()
        log_audit(request.user, "CREATE_TICKET_MESSAGE", "SupportTicket", ticket.id, None, {"message_id": message.id}, _client_ip(request))
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class SupportTicketAssignView(AdminAPIView):
    permission_map = {"POST": ("support", "assign")}

    def post(self, request, ticket_id):
        admin_user_id = request.data.get("admin_user_id")
        ticket = SupportTicket.objects.filter(id=ticket_id).first()
        admin_user = AdminUser.objects.filter(id=admin_user_id).first()
        if not ticket or not admin_user:
            return error_response("NOT_FOUND", "Ticket or admin not found.", status_code=404)
        old_value = {"assigned_to": ticket.assigned_to_id}
        ticket.assigned_to = admin_user
        ticket.save(update_fields=["assigned_to"])
        log_audit(request.user, "ASSIGN_TICKET", "SupportTicket", ticket.id, old_value, {"assigned_to": admin_user.id}, _client_ip(request))
        return Response({"detail": "Ticket assigned."})


class SupportTicketEscalateView(AdminAPIView):
    permission_map = {"POST": ("support", "escalate")}

    def post(self, request, ticket_id):
        reason = request.data.get("reason", "")
        ticket = SupportTicket.objects.filter(id=ticket_id).first()
        if not ticket:
            return error_response("NOT_FOUND", "Ticket not found.", status_code=404)
        old_value = {"status": ticket.status, "priority": ticket.priority}
        ticket.status = SupportTicket.STATUS_ESCALATED
        ticket.priority = SupportTicket.PRIORITY_CRITICAL
        ticket.save(update_fields=["status", "priority"])
        log_audit(request.user, "ESCALATE_TICKET", "SupportTicket", ticket.id, old_value, {"reason": reason}, _client_ip(request))
        return Response({"detail": "Ticket escalated."})


class SupportTicketCloseView(AdminAPIView):
    permission_map = {"POST": ("support", "close")}

    def post(self, request, ticket_id):
        ticket = SupportTicket.objects.filter(id=ticket_id).first()
        if not ticket:
            return error_response("NOT_FOUND", "Ticket not found.", status_code=404)
        old_value = {"status": ticket.status}
        ticket.status = SupportTicket.STATUS_CLOSED
        ticket.save(update_fields=["status"])
        log_audit(request.user, "CLOSE_TICKET", "SupportTicket", ticket.id, old_value, {"status": ticket.status}, _client_ip(request))
        return Response({"detail": "Ticket closed."})


class ClaimListCreateView(AdminAPIView):
    permission_map = {"GET": ("claims", "view"), "POST": ("claims", "create")}

    def get(self, request):
        queryset = Claim.objects.all().order_by("-created_at")
        page = self.paginate_queryset(queryset)
        serializer = ClaimSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)

    def post(self, request):
        serializer = ClaimSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("VALIDATION_ERROR", "Invalid payload.", serializer.errors, status_code=400)
        claim = serializer.save()
        log_audit(request.user, "CREATE_CLAIM", "Claim", claim.id, None, serializer.data, _client_ip(request))
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class ClaimDetailView(AdminAPIView):
    permission_map = {"GET": ("claims", "view")}

    def get(self, request, claim_id):
        claim = Claim.objects.filter(id=claim_id).first()
        if not claim:
            return error_response("NOT_FOUND", "Claim not found.", status_code=404)
        serializer = ClaimSerializer(claim)
        return Response(serializer.data)


class ClaimResolveView(AdminAPIView):
    permission_map = {"POST": ("claims", "resolve")}

    def post(self, request, claim_id):
        resolution_type = request.data.get("resolution_type")
        resolution_notes = request.data.get("resolution_notes", "")
        claim = Claim.objects.filter(id=claim_id).first()
        if not claim:
            return error_response("NOT_FOUND", "Claim not found.", status_code=404)
        claim.status = Claim.STATUS_RESOLVED
        claim.resolution_type = resolution_type or ""
        claim.resolution_notes = resolution_notes
        claim.resolved_by = request.user
        claim.save(update_fields=["status", "resolution_type", "resolution_notes", "resolved_by"])
        if resolution_type == "refund":
            Refund.objects.create(
                user=claim.filed_by,
                ride=claim.ride,
                amount=claim.amount_claimed,
                reason="Claim resolution refund",
                status=Refund.STATUS_APPROVED,
                approved_at=timezone.now(),
            )
        if resolution_type == "driver_suspension" and claim.against_driver:
            driver_user = claim.against_driver.user
            driver_user.account_status = User.STATUS_SUSPENDED
            driver_user.is_active = False
            driver_user.save(update_fields=["account_status", "is_active"])
        log_audit(request.user, "RESOLVE_CLAIM", "Claim", claim.id, None, {"resolution_type": resolution_type}, _client_ip(request))
        return Response({"detail": "Claim resolved."})


class ClaimRejectView(AdminAPIView):
    permission_map = {"POST": ("claims", "reject")}

    def post(self, request, claim_id):
        reason = request.data.get("reason", "")
        claim = Claim.objects.filter(id=claim_id).first()
        if not claim:
            return error_response("NOT_FOUND", "Claim not found.", status_code=404)
        claim.status = Claim.STATUS_REJECTED
        claim.resolution_notes = reason
        claim.resolved_by = request.user
        claim.save(update_fields=["status", "resolution_notes", "resolved_by"])
        log_audit(request.user, "REJECT_CLAIM", "Claim", claim.id, None, {"reason": reason}, _client_ip(request))
        return Response({"detail": "Claim rejected."})


class ClaimEscalateView(AdminAPIView):
    permission_map = {"POST": ("claims", "escalate")}

    def post(self, request, claim_id):
        reason = request.data.get("reason", "")
        claim = Claim.objects.filter(id=claim_id).first()
        if not claim:
            return error_response("NOT_FOUND", "Claim not found.", status_code=404)
        claim.status = Claim.STATUS_UNDER_REVIEW
        claim.save(update_fields=["status"])
        log_audit(request.user, "ESCALATE_CLAIM", "Claim", claim.id, None, {"reason": reason}, _client_ip(request))
        return Response({"detail": "Claim escalated."})


class OperationsDriversLiveView(AdminAPIView):
    permission_map = {"GET": ("operations", "view")}

    def get(self, request):
        drivers = Driver.objects.select_related("user").filter(status="approved")
        serializer = DriverSerializer(drivers, many=True)
        return Response(serializer.data)


class OperationsZonesStatsView(AdminAPIView):
    permission_map = {"GET": ("operations", "view")}

    def get(self, request):
        return Response({"zones": []})


class OperationsHeatmapView(AdminAPIView):
    permission_map = {"GET": ("operations", "view")}

    def get(self, request):
        return Response({"heatmap": []})


class AlertListView(AdminAPIView):
    permission_map = {"GET": ("alerts", "view")}

    def get(self, request):
        queryset = Alert.objects.all().order_by("-created_at")
        page = self.paginate_queryset(queryset)
        serializer = AlertSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class AlertAcknowledgeView(AdminAPIView):
    permission_map = {"POST": ("alerts", "ack")}

    def post(self, request, alert_id):
        alert = Alert.objects.filter(id=alert_id).first()
        if not alert:
            return error_response("NOT_FOUND", "Alert not found.", status_code=404)
        alert.status = Alert.STATUS_ACK
        alert.acknowledged_by = request.user
        alert.save(update_fields=["status", "acknowledged_by"])
        log_audit(request.user, "ACK_ALERT", "Alert", alert.id, None, {"status": alert.status}, _client_ip(request))
        return Response({"detail": "Alert acknowledged."})


class AlertResolveView(AdminAPIView):
    permission_map = {"POST": ("alerts", "resolve")}

    def post(self, request, alert_id):
        alert = Alert.objects.filter(id=alert_id).first()
        if not alert:
            return error_response("NOT_FOUND", "Alert not found.", status_code=404)
        alert.status = Alert.STATUS_RESOLVED
        alert.resolved_by = request.user
        alert.save(update_fields=["status", "resolved_by"])
        log_audit(request.user, "RESOLVE_ALERT", "Alert", alert.id, None, {"status": alert.status}, _client_ip(request))
        return Response({"detail": "Alert resolved."})


class AlertSOSView(AdminAPIView):
    permission_map = {"GET": ("alerts", "view")}

    def get(self, request):
        alerts = Alert.objects.filter(type=Alert.TYPE_SOS, status=Alert.STATUS_ACTIVE)
        serializer = AlertSerializer(alerts, many=True)
        return Response(serializer.data)


class AlertMarkSafeView(AdminAPIView):
    permission_map = {"POST": ("alerts", "resolve")}

    def post(self, request, alert_id):
        alert = Alert.objects.filter(id=alert_id, type=Alert.TYPE_SOS).first()
        if not alert:
            return error_response("NOT_FOUND", "SOS alert not found.", status_code=404)
        alert.status = Alert.STATUS_RESOLVED
        alert.resolved_by = request.user
        alert.save(update_fields=["status", "resolved_by"])
        log_audit(request.user, "MARK_SOS_SAFE", "Alert", alert.id, None, {"status": alert.status}, _client_ip(request))
        return Response({"detail": "SOS alert marked safe."})


class AnalyticsRevenueView(AdminAPIView):
    permission_map = {"GET": ("analytics", "view")}

    def get(self, request):
        stats = DailyRevenue.objects.order_by("date")
        serializer = DailyRevenueSerializer(stats, many=True)
        return Response(serializer.data)


class AnalyticsRideTrendsView(AdminAPIView):
    permission_map = {"GET": ("analytics", "view")}

    def get(self, request):
        stats = DailyRideStats.objects.order_by("date")
        serializer = DailyRideStatsSerializer(stats, many=True)
        return Response(serializer.data)


class AnalyticsSupportView(AdminAPIView):
    permission_map = {"GET": ("analytics", "view")}

    def get(self, request):
        stats = SupportTicket.objects.values("status").annotate(count=Count("id"))
        return Response({"stats": list(stats)})


class AnalyticsUserGrowthView(AdminAPIView):
    permission_map = {"GET": ("analytics", "view")}

    def get(self, request):
        stats = User.objects.extra(select={"date": "date(date_joined)"}).values("date").annotate(count=Count("id")).order_by("date")
        return Response({"stats": list(stats)})


class AnalyticsDriverPerformanceView(AdminAPIView):
    permission_map = {"GET": ("analytics", "view")}

    def get(self, request):
        stats = Driver.objects.annotate(trips=Count("rides")).order_by("-trips")[:10]
        serializer = DriverSerializer(stats, many=True)
        return Response(serializer.data)


class AnalyticsCancellationAnalysisView(AdminAPIView):
    permission_map = {"GET": ("analytics", "view")}

    def get(self, request):
        stats = Ride.objects.filter(status="cancelled").values("cancel_reason").annotate(count=Count("id"))
        return Response({"stats": list(stats)})


class AnalyticsPaymentView(AdminAPIView):
    permission_map = {"GET": ("analytics", "view")}

    def get(self, request):
        stats = PaymentTransaction.objects.values("status").annotate(count=Count("id"))
        return Response({"stats": list(stats)})


class AnalyticsExportView(AdminAPIView):
    permission_map = {"GET": ("analytics", "export")}

    def get(self, request):
        report_type = request.query_params.get("report_type", "revenue")
        async_export = request.query_params.get("async") == "true"
        if async_export:
            job = AnalyticsExportJob.objects.create(report_type=report_type)
            export_report.delay(str(job.job_id))
            return Response({"job_id": job.job_id, "status": job.status})
        output = io.StringIO()
        writer = csv.writer(output)
        if report_type == "revenue":
            writer.writerow(["date", "total_amount"])
            for row in DailyRevenue.objects.order_by("date"):
                writer.writerow([row.date, row.total_amount])
        elif report_type == "rides":
            writer.writerow(["date", "completed", "cancelled"])
            for row in DailyRideStats.objects.order_by("date"):
                writer.writerow([row.date, row.completed, row.cancelled])
        else:
            return error_response("VALIDATION_ERROR", "Unknown report type.", status_code=400)
        response = Response(output.getvalue(), content_type="text/csv")
        response["Content-Disposition"] = f"attachment; filename={report_type}.csv"
        return response


class AnalyticsExportStatusView(AdminAPIView):
    permission_map = {"GET": ("analytics", "export")}

    def get(self, request, job_id):
        job = AnalyticsExportJob.objects.filter(job_id=job_id).first()
        if not job:
            return error_response("NOT_FOUND", "Job not found.", status_code=404)
        return Response(AnalyticsExportJobSerializer(job).data)


class AnalyticsExportDownloadView(AdminAPIView):
    permission_map = {"GET": ("analytics", "export")}

    def get(self, request, job_id):
        job = AnalyticsExportJob.objects.filter(job_id=job_id).first()
        if not job or job.status != AnalyticsExportJob.STATUS_DONE:
            return error_response("NOT_FOUND", "Export not ready.", status_code=404)
        response = Response(job.file_content, content_type="text/csv")
        response["Content-Disposition"] = f"attachment; filename={job.report_type}.csv"
        return response


class AdminUserListCreateView(AdminAPIView):
    permission_map = {"GET": ("admin", "view"), "POST": ("admin", "create")}

    def get(self, request):
        queryset = AdminUser.objects.select_related("role").all().order_by("-created_at")
        page = self.paginate_queryset(queryset)
        serializer = AdminUserSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)

    def post(self, request):
        serializer = AdminUserCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("VALIDATION_ERROR", "Invalid payload.", serializer.errors, status_code=400)
        temp_password = secrets.token_urlsafe(8)
        admin_user = AdminUser.objects.create_user(
            email=serializer.validated_data["email"],
            name=serializer.validated_data["name"],
            role=serializer.validated_data["role"],
            password=temp_password,
            created_by=request.user,
        )
        send_mail(
            "Admin account created",
            f"Your temporary password is: {temp_password}",
            None,
            [admin_user.email],
            fail_silently=True,
        )
        log_audit(request.user, "CREATE_ADMIN", "AdminUser", admin_user.uuid, None, {"email": admin_user.email}, _client_ip(request))
        return Response(AdminUserSerializer(admin_user).data, status=status.HTTP_201_CREATED)


class AdminUserDetailUpdateDeleteView(AdminAPIView):
    permission_map = {"PATCH": ("admin", "update"), "DELETE": ("admin", "delete")}

    def patch(self, request, admin_id):
        admin_user = AdminUser.objects.filter(uuid=admin_id).first()
        if not admin_user:
            return error_response("NOT_FOUND", "Admin not found.", status_code=404)
        if admin_user.uuid == request.user.uuid and "role" in request.data:
            return error_response("PERMISSION_DENIED", "Cannot modify your own role.", status_code=403)
        old_value = {"role": admin_user.role.name, "status": admin_user.status}
        serializer = AdminUserSerializer(admin_user, data=request.data, partial=True)
        if not serializer.is_valid():
            return error_response("VALIDATION_ERROR", "Invalid payload.", serializer.errors, status_code=400)
        serializer.save()
        log_audit(request.user, "UPDATE_ADMIN", "AdminUser", admin_user.uuid, old_value, serializer.data, _client_ip(request))
        return Response(serializer.data)

    def delete(self, request, admin_id):
        admin_user = AdminUser.objects.filter(uuid=admin_id).first()
        if not admin_user:
            return error_response("NOT_FOUND", "Admin not found.", status_code=404)
        old_value = {"status": admin_user.status}
        admin_user.status = AdminUser.STATUS_INACTIVE
        admin_user.save(update_fields=["status"])
        revoke_admin_tokens(admin_user, "deactivated")
        log_audit(request.user, "DEACTIVATE_ADMIN", "AdminUser", admin_user.uuid, old_value, {"status": admin_user.status}, _client_ip(request))
        return Response({"detail": "Admin deactivated."})


class AdminRoleListView(AdminAPIView):
    permission_map = {"GET": ("admin", "view")}

    def get(self, request):
        ensure_default_roles()
        roles = AdminRole.objects.all().order_by("name")
        serializer = AdminRoleSerializer(roles, many=True)
        return Response(serializer.data)


class AdminRolePermissionsUpdateView(AdminAPIView):
    permission_map = {"PATCH": ("admin", "update")}

    def patch(self, request, role_name):
        role = AdminRole.objects.filter(name=role_name).first()
        if not role:
            return error_response("NOT_FOUND", "Role not found.", status_code=404)
        permissions = request.data.get("permissions")
        if permissions is None:
            return error_response("VALIDATION_ERROR", "Permissions payload required.", status_code=400)
        old_value = {"permissions": role.permissions}
        role.permissions = permissions
        role.updated_by = request.user
        role.save(update_fields=["permissions", "updated_by"])
        log_audit(request.user, "UPDATE_ROLE", "AdminRole", role.name, old_value, {"permissions": permissions}, _client_ip(request))
        return Response(AdminRoleSerializer(role).data)


class AuditLogListView(AdminAPIView):
    permission_map = {"GET": ("admin", "view")}

    def get(self, request):
        queryset = AuditLog.objects.all().order_by("-created_at")
        page = self.paginate_queryset(queryset)
        serializer = AuditLogSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class AuditLogExportView(AdminAPIView):
    permission_map = {"GET": ("admin", "view")}

    def get(self, request):
        rows = AuditLog.objects.order_by("-created_at").values(
            "id", "admin_user_id", "action", "target_type", "target_id", "created_at"
        )
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["id", "admin_user_id", "action", "target_type", "target_id", "created_at"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        response = Response(output.getvalue(), content_type="text/csv")
        response["Content-Disposition"] = "attachment; filename=audit_logs.csv"
        return response


class SettingsView(AdminAPIView):
    permission_map = {"GET": ("admin", "view"), "PATCH": ("admin", "update")}

    def get(self, request):
        settings_qs = SystemSetting.objects.all()
        serializer = SystemSettingSerializer(settings_qs, many=True)
        return Response({item["key"]: item["value"] for item in serializer.data})

    def patch(self, request):
        if request.user.role.name != "superadmin":
            return error_response("PERMISSION_DENIED", "Superadmin only.", status_code=403)
        updates = request.data or {}
        for key, value in updates.items():
            setting, _ = SystemSetting.objects.get_or_create(key=key)
            old_value = {"value": setting.value}
            setting.value = value
            setting.updated_by = request.user
            setting.save(update_fields=["value", "updated_by", "updated_at"])
            log_audit(request.user, "UPDATE_SETTING", "SystemSetting", key, old_value, {"value": value}, _client_ip(request))
        return Response({"detail": "Settings updated."})


class NotificationListView(AdminAPIView):
    permission_map = {"GET": ("notifications", "view")}

    def get(self, request):
        queryset = Notification.objects.all().order_by("-created_at")
        page = self.paginate_queryset(queryset)
        serializer = NotificationSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class NotificationSendView(AdminAPIView):
    permission_map = {"POST": ("notifications", "send")}

    def post(self, request):
        serializer = NotificationSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("VALIDATION_ERROR", "Invalid payload.", serializer.errors, status_code=400)
        notification = serializer.save(sent_by=request.user)
        if notification.scheduled_at is None:
            notification.status = Notification.STATUS_SENT
            notification.sent_at = timezone.now()
            notification.save(update_fields=["status", "sent_at"])
        else:
            send_scheduled_notification.apply_async((notification.id,), eta=notification.scheduled_at)
        log_audit(request.user, "SEND_NOTIFICATION", "Notification", notification.id, None, serializer.data, _client_ip(request))
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class NotificationDetailView(AdminAPIView):
    permission_map = {"GET": ("notifications", "view")}

    def get(self, request, notification_id):
        notification = Notification.objects.filter(id=notification_id).first()
        if not notification:
            return error_response("NOT_FOUND", "Notification not found.", status_code=404)
        serializer = NotificationSerializer(notification)
        return Response(serializer.data)


class ChatThreadListCreateView(AdminAPIView):
    permission_map = {"GET": ("admin", "view"), "POST": ("admin", "create")}

    def get(self, request):
        threads = InternalChatThread.objects.filter(members=request.user)
        serializer = InternalChatThreadSerializer(threads, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = InternalChatThreadSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("VALIDATION_ERROR", "Invalid payload.", serializer.errors, status_code=400)
        thread = serializer.save(created_by=request.user)
        thread.members.add(request.user)
        return Response(InternalChatThreadSerializer(thread).data, status=status.HTTP_201_CREATED)


class ChatThreadMessagesView(AdminAPIView):
    permission_map = {"GET": ("admin", "view"), "POST": ("admin", "create")}

    def get(self, request, thread_id):
        thread = InternalChatThread.objects.filter(id=thread_id, members=request.user).first()
        if not thread:
            return error_response("NOT_FOUND", "Thread not found.", status_code=404)
        serializer = InternalChatMessageSerializer(thread.messages.all(), many=True)
        return Response(serializer.data)

    def post(self, request, thread_id):
        thread = InternalChatThread.objects.filter(id=thread_id, members=request.user).first()
        if not thread:
            return error_response("NOT_FOUND", "Thread not found.", status_code=404)
        payload = request.data.copy()
        payload["thread"] = thread.id
        payload["sender"] = request.user.id
        serializer = InternalChatMessageSerializer(data=payload)
        if not serializer.is_valid():
            return error_response("VALIDATION_ERROR", "Invalid payload.", serializer.errors, status_code=400)
        message = serializer.save()
        return Response(InternalChatMessageSerializer(message).data, status=status.HTTP_201_CREATED)
