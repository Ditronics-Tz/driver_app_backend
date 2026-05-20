from datetime import timedelta

from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from .models import AdminRole, AuditLog, AdminRefreshToken
from .permissions import ROLE_PERMISSIONS


def ensure_default_roles():
    for role_name, permissions in ROLE_PERMISSIONS.items():
        role, created = AdminRole.objects.get_or_create(
            name=role_name,
            defaults={"permissions": permissions},
        )
        if not created and not role.permissions:
            role.permissions = permissions
            role.save(update_fields=["permissions"])


def build_admin_tokens(admin_user):
    refresh = RefreshToken()
    refresh["user_uuid"] = str(admin_user.uuid)
    refresh["user_type"] = "admin"
    refresh["role"] = admin_user.role.name
    refresh.set_exp(lifetime=timedelta(days=7))
    access = refresh.access_token
    access["user_uuid"] = str(admin_user.uuid)
    access["user_type"] = "admin"
    access["role"] = admin_user.role.name
    access.set_exp(lifetime=timedelta(minutes=15))

    AdminRefreshToken.objects.create(
        admin_user=admin_user,
        jti=str(refresh["jti"]),
        created_at=timezone.now(),
        expires_at=timezone.now() + timedelta(days=7),
    )

    return {
        "access": str(access),
        "refresh": str(refresh),
        "expires_in": 15 * 60,
    }


def revoke_admin_tokens(admin_user, reason: str):
    tokens = AdminRefreshToken.objects.filter(admin_user=admin_user, revoked_at__isnull=True)
    for token in tokens:
        token.revoke(reason=reason)


def log_audit(admin_user, action, target_type, target_id, old_value, new_value, ip_address):
    AuditLog.objects.create(
        admin_user=admin_user,
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        old_value=old_value,
        new_value=new_value,
        ip_address=ip_address,
    )
