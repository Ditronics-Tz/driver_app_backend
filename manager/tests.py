from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from datetime import timedelta

from .models import AdminRole, AdminUser, AdminRefreshToken, AdminPasswordResetToken
from .services import ensure_default_roles, build_admin_tokens, revoke_admin_tokens
import secrets


class AdminPermissionTests(TestCase):
    def setUp(self):
        ensure_default_roles()
        self.superadmin_role = AdminRole.objects.get(name="superadmin")
        self.support_role = AdminRole.objects.get(name="support_agent")

        self.superadmin = AdminUser.objects.create_user(
            email="superadmin@example.com",
            name="Super Admin",
            role=self.superadmin_role,
            password="password123",
        )
        self.support_admin = AdminUser.objects.create_user(
            email="support@example.com",
            name="Support Agent",
            role=self.support_role,
            password="password123",
        )

        self.client = APIClient()

    def test_superadmin_can_list_admin_users(self):
        tokens = build_admin_tokens(self.superadmin)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        response = self.client.get("/api/admin/v1/admin/users/")
        self.assertEqual(response.status_code, 200)

    def test_support_cannot_list_admin_users(self):
        tokens = build_admin_tokens(self.support_admin)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        response = self.client.get("/api/admin/v1/admin/users/")
        self.assertEqual(response.status_code, 403)


class AdminAuthLoginTests(TestCase):
    def setUp(self):
        ensure_default_roles()
        self.superadmin_role = AdminRole.objects.get(name="superadmin")
        self.admin_user = AdminUser.objects.create_user(
            email="login@example.com",
            name="Login Test",
            role=self.superadmin_role,
            password="TestPassword123!",
        )
        self.client = APIClient()

    def test_login_with_role_claims(self):
        """Verify login endpoint returns JWT with role claims"""
        response = self.client.post(
            "/api/admin/v1/auth/login/",
            {"email": "login@example.com", "password": "TestPassword123!"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("access", data)
        self.assertIn("refresh", data)

        # Verify role claims in tokens
        refresh_token = RefreshToken(data["refresh"])
        access_token = refresh_token.access_token
        self.assertEqual(refresh_token.get("role"), "superadmin")
        self.assertEqual(access_token.get("role"), "superadmin")
        self.assertEqual(refresh_token.get("user_type"), "admin")
        self.assertEqual(str(refresh_token.get("user_uuid")), str(self.admin_user.uuid))

    def test_login_with_invalid_credentials(self):
        """Verify login rejects invalid credentials"""
        response = self.client.post(
            "/api/admin/v1/auth/login/",
            {"email": "login@example.com", "password": "WrongPassword"},
        )
        self.assertEqual(response.status_code, 401)

    def test_account_lockout_after_failed_attempts(self):
        """Verify account locks after 5 failed login attempts"""
        for i in range(5):
            response = self.client.post(
                "/api/admin/v1/auth/login/",
                {"email": "login@example.com", "password": "WrongPassword"},
            )
            self.assertEqual(response.status_code, 401)

        # Verify account is locked
        self.admin_user.refresh_from_db()
        self.assertIsNotNone(self.admin_user.locked_until)
        self.assertEqual(self.admin_user.failed_login_attempts, 5)

        # Attempt login while locked should return 423
        response = self.client.post(
            "/api/admin/v1/auth/login/",
            {"email": "login@example.com", "password": "TestPassword123!"},
        )
        self.assertEqual(response.status_code, 423)


class AdminTokenRefreshTests(TestCase):
    def setUp(self):
        ensure_default_roles()
        self.finance_role = AdminRole.objects.get(name="finance")
        self.admin_user = AdminUser.objects.create_user(
            email="refresh@example.com",
            name="Refresh Test",
            role=self.finance_role,
            password="TestPassword123!",
        )
        self.client = APIClient()

    def test_refresh_token_rotation(self):
        """Verify token refresh invalidates old token and issues new one"""
        # Get initial tokens
        tokens1 = build_admin_tokens(self.admin_user)
        jti1 = RefreshToken(tokens1["refresh"]).get("jti")

        # Refresh tokens
        response = self.client.post(
            "/api/admin/v1/auth/refresh/", {"refresh": tokens1["refresh"]}
        )
        self.assertEqual(response.status_code, 200)
        tokens2 = response.json()

        # Verify old token is revoked with reason "rotated"
        old_token = AdminRefreshToken.objects.get(jti=jti1)
        self.assertIsNotNone(old_token.revoked_at)
        self.assertEqual(old_token.revoked_reason, "rotated")

        # Verify new token is active
        jti2 = RefreshToken(tokens2["refresh"]).get("jti")
        new_token = AdminRefreshToken.objects.get(jti=jti2)
        self.assertIsNone(new_token.revoked_at)
        self.assertTrue(new_token.is_active)

        # Verify role claim preserved in new token
        new_refresh_token = RefreshToken(tokens2["refresh"])
        self.assertEqual(new_refresh_token.get("role"), "finance")

    def test_refresh_revoked_token_rejected(self):
        """Verify refresh endpoint rejects revoked tokens"""
        tokens = build_admin_tokens(self.admin_user)
        jti = RefreshToken(tokens["refresh"]).get("jti")

        # Revoke the token manually
        token_obj = AdminRefreshToken.objects.get(jti=jti)
        token_obj.revoke("test")

        # Attempt to refresh should be rejected
        response = self.client.post(
            "/api/admin/v1/auth/refresh/", {"refresh": tokens["refresh"]}
        )
        self.assertEqual(response.status_code, 401)


class AdminLogoutTests(TestCase):
    def setUp(self):
        ensure_default_roles()
        self.ops_role = AdminRole.objects.get(name="ops_manager")
        self.admin_user = AdminUser.objects.create_user(
            email="logout@example.com",
            name="Logout Test",
            role=self.ops_role,
            password="TestPassword123!",
        )
        self.client = APIClient()

    def test_logout_revokes_token(self):
        """Verify logout endpoint revokes refresh token"""
        tokens = build_admin_tokens(self.admin_user)
        jti = RefreshToken(tokens["refresh"]).get("jti")

        # Logout requires authentication
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        response = self.client.post(
            "/api/admin/v1/auth/logout/", {"refresh": tokens["refresh"]}
        )
        self.assertEqual(response.status_code, 200)

        # Verify token is revoked with reason "logout"
        token_obj = AdminRefreshToken.objects.get(jti=jti)
        self.assertIsNotNone(token_obj.revoked_at)
        self.assertEqual(token_obj.revoked_reason, "logout")

    def test_refresh_after_logout_rejected(self):
        """Verify refresh is rejected after logout"""
        tokens = build_admin_tokens(self.admin_user)

        # Logout requires authentication
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        self.client.post("/api/admin/v1/auth/logout/", {"refresh": tokens["refresh"]})

        # Attempt refresh should be rejected
        response = self.client.post(
            "/api/admin/v1/auth/refresh/", {"refresh": tokens["refresh"]}
        )
        self.assertEqual(response.status_code, 401)


class AdminPasswordResetTests(TestCase):
    def setUp(self):
        ensure_default_roles()
        self.support_role = AdminRole.objects.get(name="support_agent")
        self.admin_user = AdminUser.objects.create_user(
            email="reset@example.com",
            name="Reset Test",
            role=self.support_role,
            password="OldPassword123!",
        )
        self.client = APIClient()

    def test_forgot_password_creates_reset_token(self):
        """Verify forgot password endpoint creates valid reset token"""
        response = self.client.post(
            "/api/admin/v1/auth/forgot-password/", {"email": "reset@example.com"}
        )
        self.assertEqual(response.status_code, 200)

        # Verify reset token created
        reset_token = AdminPasswordResetToken.objects.filter(
            admin_user=self.admin_user
        ).first()
        self.assertIsNotNone(reset_token)
        self.assertIsNone(reset_token.used_at)
        self.assertGreater(reset_token.expires_at, timezone.now())

    def test_reset_password_invalidates_all_tokens(self):
        """Verify password reset invalidates all active tokens"""
        # Create multiple active tokens
        tokens1 = build_admin_tokens(self.admin_user)
        tokens2 = build_admin_tokens(self.admin_user)

        jti1 = RefreshToken(tokens1["refresh"]).get("jti")
        jti2 = RefreshToken(tokens2["refresh"]).get("jti")

        token1 = AdminRefreshToken.objects.get(jti=jti1)
        token2 = AdminRefreshToken.objects.get(jti=jti2)
        self.assertTrue(token1.is_active)
        self.assertTrue(token2.is_active)

        # Create and use reset token
        reset_token_str = secrets.token_urlsafe(32)
        reset_token = AdminPasswordResetToken.objects.create(
            admin_user=self.admin_user,
            token=reset_token_str,
            expires_at=timezone.now() + timedelta(hours=1),
        )

        response = self.client.post(
            "/api/admin/v1/auth/reset-password/",
            {"token": reset_token_str, "new_password": "NewPassword123!"},
        )
        self.assertEqual(response.status_code, 200)

        # Verify all tokens revoked
        token1.refresh_from_db()
        token2.refresh_from_db()
        self.assertFalse(token1.is_active)
        self.assertFalse(token2.is_active)
        self.assertEqual(token1.revoked_reason, "password_reset")
        self.assertEqual(token2.revoked_reason, "password_reset")

        # Verify reset token marked as used
        reset_token.refresh_from_db()
        self.assertIsNotNone(reset_token.used_at)

    def test_reset_password_allows_new_login(self):
        """Verify new password works after password reset"""
        # Create reset token
        reset_token_str = secrets.token_urlsafe(32)
        AdminPasswordResetToken.objects.create(
            admin_user=self.admin_user,
            token=reset_token_str,
            expires_at=timezone.now() + timedelta(hours=1),
        )

        # Reset password
        response = self.client.post(
            "/api/admin/v1/auth/reset-password/",
            {"token": reset_token_str, "new_password": "NewPassword123!"},
        )
        self.assertEqual(response.status_code, 200)

        # Verify login with new password works
        response = self.client.post(
            "/api/admin/v1/auth/login/",
            {"email": "reset@example.com", "password": "NewPassword123!"},
        )
        self.assertEqual(response.status_code, 200)


class TokenInvalidationTests(TestCase):
    def setUp(self):
        ensure_default_roles()
        self.superadmin_role = AdminRole.objects.get(name="superadmin")
        self.admin_user = AdminUser.objects.create_user(
            email="invalidation@example.com",
            name="Invalidation Test",
            role=self.superadmin_role,
            password="TestPassword123!",
        )

    def test_revoke_all_tokens_for_user(self):
        """Verify revoke_admin_tokens invalidates all active tokens"""
        # Create multiple active tokens
        tokens1 = build_admin_tokens(self.admin_user)
        tokens2 = build_admin_tokens(self.admin_user)
        tokens3 = build_admin_tokens(self.admin_user)

        jti1 = RefreshToken(tokens1["refresh"]).get("jti")
        jti2 = RefreshToken(tokens2["refresh"]).get("jti")
        jti3 = RefreshToken(tokens3["refresh"]).get("jti")

        token1 = AdminRefreshToken.objects.get(jti=jti1)
        token2 = AdminRefreshToken.objects.get(jti=jti2)
        token3 = AdminRefreshToken.objects.get(jti=jti3)

        self.assertTrue(token1.is_active)
        self.assertTrue(token2.is_active)
        self.assertTrue(token3.is_active)

        # Revoke all tokens
        revoke_admin_tokens(self.admin_user, "test_reason")

        # Verify all tokens revoked
        token1.refresh_from_db()
        token2.refresh_from_db()
        token3.refresh_from_db()
        self.assertFalse(token1.is_active)
        self.assertFalse(token2.is_active)
        self.assertFalse(token3.is_active)
        self.assertEqual(token1.revoked_reason, "test_reason")
        self.assertEqual(token2.revoked_reason, "test_reason")
        self.assertEqual(token3.revoked_reason, "test_reason")
