from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed
from django.utils.translation import gettext_lazy as _

from .models import AdminUser


class AdminJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        user_uuid = validated_token.get("user_uuid")
        user_type = validated_token.get("user_type")
        if not user_uuid or user_type != "admin":
            raise InvalidToken(_("Token does not identify an admin user."))

        try:
            admin_user = AdminUser.objects.select_related("role").get(uuid=user_uuid)
        except AdminUser.DoesNotExist as exc:
            raise AuthenticationFailed(_("Admin user not found.")) from exc

        return admin_user
