from rest_framework.permissions import BasePermission


ROLE_PERMISSIONS = {
    "superadmin": {"*": {"*": True}},
    "support_agent": {
        "users": {"view": True, "suspend": True, "ban": True, "activate": True, "notify": True},
        "rides": {"view": True},
        "support": {"view": True, "create": True, "update": True, "assign": True, "escalate": True, "close": True},
        "claims": {"view": True, "create": True, "resolve": True, "reject": True, "escalate": True},
        "notifications": {"view": True, "send": True},
        "dashboard": {"view": True},
        "alerts": {"view": True},
    },
    "finance": {
        "payments": {"view": True, "export": True, "approve": True, "reject": True, "refund": True},
        "analytics": {"view": True, "export": True},
        "dashboard": {"view": True},
    },
    "ops_manager": {
        "operations": {"view": True},
        "rides": {"view": True, "cancel": True, "reassign": True, "flag": True},
        "alerts": {"view": True, "ack": True, "resolve": True},
        "analytics": {"view": True},
        "users": {"view": True},
        "dashboard": {"view": True},
    },
}


class AdminRolePermission(BasePermission):
    def has_permission(self, request, view):
        admin_user = getattr(request, "user", None)
        if admin_user is None or not hasattr(admin_user, "role"):
            return False
        if admin_user.status != admin_user.STATUS_ACTIVE:
            return False
        if admin_user.role.name == "superadmin":
            return True
        permission_map = getattr(view, "permission_map", None)
        if not permission_map:
            return True
        action = permission_map.get(request.method)
        if not action:
            return False
        module, action_name = action
        return admin_user.role.has_permission(module, action_name)
