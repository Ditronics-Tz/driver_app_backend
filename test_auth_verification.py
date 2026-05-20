#!/usr/bin/env python
"""
Verification tests for admin auth endpoints and JWT role claims
"""
import os
import sys
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'driver_app_backend.settings')
sys.path.insert(0, os.path.dirname(__file__))
django.setup()

from django.conf import settings
if 'testserver' not in settings.ALLOWED_HOSTS:
    settings.ALLOWED_HOSTS.append('testserver')

from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken
from manager.models import AdminRole, AdminUser, AdminRefreshToken
from manager.services import ensure_default_roles, build_admin_tokens
from django.utils import timezone
from datetime import timedelta


def test_login_with_role_claims():
    """Test 1: Login endpoint with role claims"""
    print('\nTEST 1: Admin Login with Role Claims')
    ensure_default_roles()
    client = APIClient()
    
    superadmin_role = AdminRole.objects.get(name='superadmin')
    admin_user = AdminUser.objects.create_user(
        email='test@example.com',
        name='Test Admin',
        role=superadmin_role,
        password='TestPassword123!'
    )
    
    response = client.post('/api/admin/v1/auth/login/', {
        'email': 'test@example.com',
        'password': 'TestPassword123!'
    })
    
    print(f'  Status: {response.status_code}')
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.json()}"
    
    data = response.json()
    print(f'  ✓ Tokens returned')
    
    # Verify role claim in token
    refresh_token = RefreshToken(data['refresh'])
    access_token = refresh_token.access_token
    
    assert refresh_token.get('role') == 'superadmin', "Role not in refresh token"
    assert access_token.get('role') == 'superadmin', "Role not in access token"
    assert refresh_token.get('user_type') == 'admin', "user_type not correct"
    assert str(refresh_token.get('user_uuid')) == str(admin_user.uuid), "UUID mismatch"
    
    print(f'  ✓ Refresh token role claim: {refresh_token.get("role")}')
    print(f'  ✓ Access token role claim: {access_token.get("role")}')
    print(f'  ✓ User type: {refresh_token.get("user_type")}')
    print(f'  ✓ User UUID matches')
    
    return data


def test_token_refresh_with_rotation(data):
    """Test 2: Refresh endpoint with token rotation"""
    print('\nTEST 2: Token Refresh with Rotation')
    client = APIClient()
    
    response = client.post('/api/admin/v1/auth/refresh/', {'refresh': data['refresh']})
    print(f'  Status: {response.status_code}')
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.json()}"
    
    new_data = response.json()
    print(f'  ✓ New tokens issued')
    
    # Verify old token is revoked
    old_jti = RefreshToken(data['refresh']).get('jti')
    old_token = AdminRefreshToken.objects.get(jti=old_jti)
    assert old_token.revoked_at is not None, "Old token should be revoked"
    assert old_token.revoked_reason == 'rotated', f"Revoke reason should be 'rotated', got {old_token.revoked_reason}"
    print(f'  ✓ Old token revoked: reason={old_token.revoked_reason}')
    
    # Verify new token is active
    new_refresh_token = RefreshToken(new_data['refresh'])
    new_jti = new_refresh_token.get('jti')
    new_token = AdminRefreshToken.objects.get(jti=new_jti)
    assert new_token.is_active, "New token should be active"
    assert new_token.revoked_at is None, "New token should not be revoked"
    print(f'  ✓ New token is active and not revoked')
    
    # Verify role claims still present
    assert new_refresh_token.get('role') == 'superadmin', "Role lost in refresh"
    print(f'  ✓ Role claim preserved in new token: {new_refresh_token.get("role")}')
    
    return new_data, old_token


def test_logout(new_data):
    """Test 3: Logout endpoint"""
    print('\nTEST 3: Admin Logout')
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {new_data['access']}")
    
    new_refresh_token = RefreshToken(new_data['refresh'])
    logout_response = client.post('/api/admin/v1/auth/logout/', {'refresh': new_data['refresh']})
    
    print(f'  Status: {logout_response.status_code}')
    assert logout_response.status_code == 200, f"Expected 200, got {logout_response.status_code}: {logout_response.json()}"
    print(f'  ✓ Logout successful')
    
    # Verify token is revoked
    logout_token = AdminRefreshToken.objects.get(jti=new_refresh_token.get('jti'))
    assert logout_token.revoked_at is not None, "Token should be revoked after logout"
    assert logout_token.revoked_reason == 'logout', f"Revoke reason should be 'logout', got {logout_token.revoked_reason}"
    print(f'  ✓ Token revoked: reason={logout_token.revoked_reason}')


def test_refresh_invalidation_after_logout(new_data):
    """Test 4: Refresh invalidation after logout"""
    print('\nTEST 4: Refresh Invalidation After Logout')
    client = APIClient()
    
    refresh_attempt = client.post('/api/admin/v1/auth/refresh/', {'refresh': new_data['refresh']})
    print(f'  Status: {refresh_attempt.status_code}')
    assert refresh_attempt.status_code == 401, f"Expected 401, got {refresh_attempt.status_code}"
    print(f'  ✓ Refresh correctly rejected (revoked token)')


def test_password_reset_invalidation():
    """Test 5: Password reset invalidates all tokens"""
    print('\nTEST 5: Password Reset Token Invalidation')
    ensure_default_roles()
    client = APIClient()
    
    # Create admin user and get tokens
    finance_role = AdminRole.objects.get(name='finance')
    admin_user = AdminUser.objects.create_user(
        email='finance@example.com',
        name='Finance Admin',
        role=finance_role,
        password='OldPassword123!'
    )
    
    # Issue multiple tokens
    tokens1 = build_admin_tokens(admin_user)
    tokens2 = build_admin_tokens(admin_user)
    tokens3 = build_admin_tokens(admin_user)
    
    # Verify all tokens are active
    jti1 = RefreshToken(tokens1['refresh']).get('jti')
    jti2 = RefreshToken(tokens2['refresh']).get('jti')
    jti3 = RefreshToken(tokens3['refresh']).get('jti')
    
    token1 = AdminRefreshToken.objects.get(jti=jti1)
    token2 = AdminRefreshToken.objects.get(jti=jti2)
    token3 = AdminRefreshToken.objects.get(jti=jti3)
    
    assert token1.is_active and token2.is_active and token3.is_active, "All tokens should be active initially"
    print(f'  ✓ Created 3 active tokens')
    
    # Perform password reset
    from manager.services import revoke_admin_tokens
    revoke_admin_tokens(admin_user, 'password_reset')
    
    # Verify all tokens are revoked
    token1.refresh_from_db()
    token2.refresh_from_db()
    token3.refresh_from_db()
    
    assert not token1.is_active and not token2.is_active and not token3.is_active, "All tokens should be revoked"
    assert token1.revoked_reason == 'password_reset', "Revoke reason should be password_reset"
    print(f'  ✓ All active tokens revoked after password reset')
    print(f'  ✓ Revoke reason: {token1.revoked_reason}')


def test_forgot_password_endpoint():
    """Test 6: Forgot password endpoint"""
    print('\nTEST 6: Forgot Password Endpoint')
    ensure_default_roles()
    client = APIClient()
    
    support_role = AdminRole.objects.get(name='support_agent')
    admin_user = AdminUser.objects.create_user(
        email='support@example.com',
        name='Support Admin',
        role=support_role,
        password='Password123!'
    )
    
    response = client.post('/api/admin/v1/auth/forgot-password/', {
        'email': 'support@example.com'
    })
    
    print(f'  Status: {response.status_code}')
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    print(f'  ✓ Forgot password endpoint working')
    
    # Verify reset token was created
    from manager.models import AdminPasswordResetToken
    reset_token = AdminPasswordResetToken.objects.filter(admin_user=admin_user).first()
    assert reset_token is not None, "Reset token should be created"
    assert reset_token.used_at is None, "Reset token should not be marked as used yet"
    assert reset_token.expires_at > timezone.now(), "Reset token should not be expired"
    print(f'  ✓ Reset token created and valid')


def test_reset_password_endpoint():
    """Test 7: Reset password endpoint"""
    print('\nTEST 7: Reset Password Endpoint')
    ensure_default_roles()
    client = APIClient()
    
    ops_role = AdminRole.objects.get(name='ops_manager')
    admin_user = AdminUser.objects.create_user(
        email='ops@example.com',
        name='Ops Admin',
        role=ops_role,
        password='OldPassword123!'
    )
    
    # Create a reset token
    from manager.models import AdminPasswordResetToken
    from django.contrib.auth.hashers import make_password
    import secrets
    
    reset_token_str = secrets.token_urlsafe(32)
    reset_token = AdminPasswordResetToken.objects.create(
        admin_user=admin_user,
        token=reset_token_str,
        expires_at=timezone.now() + timedelta(hours=1)
    )
    
    # Create active tokens before reset
    tokens_before = build_admin_tokens(admin_user)
    jti_before = RefreshToken(tokens_before['refresh']).get('jti')
    token_before = AdminRefreshToken.objects.get(jti=jti_before)
    assert token_before.is_active, "Token should be active before reset"
    print(f'  ✓ Token active before password reset')
    
    # Reset password
    response = client.post('/api/admin/v1/auth/reset-password/', {
        'token': reset_token_str,
        'new_password': 'NewPassword123!'
    })
    
    print(f'  Status: {response.status_code}')
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.json()}"
    print(f'  ✓ Password reset successful')
    
    # Verify reset token marked as used
    reset_token.refresh_from_db()
    assert reset_token.used_at is not None, "Reset token should be marked as used"
    print(f'  ✓ Reset token marked as used')
    
    # Verify all previous tokens invalidated
    token_before.refresh_from_db()
    assert not token_before.is_active, "Token should be revoked after password reset"
    assert token_before.revoked_reason == 'password_reset', "Revoke reason should be password_reset"
    print(f'  ✓ Previous tokens revoked: reason={token_before.revoked_reason}')
    
    # Verify new password works
    response = client.post('/api/admin/v1/auth/login/', {
        'email': 'ops@example.com',
        'password': 'NewPassword123!'
    })
    assert response.status_code == 200, f"Login with new password should work: {response.json()}"
    print(f'  ✓ New password works for login')


def test_account_lockout():
    """Test 8: Account lockout after failed attempts"""
    print('\nTEST 8: Account Lockout After Failed Login Attempts')
    ensure_default_roles()
    client = APIClient()
    
    superadmin_role = AdminRole.objects.get(name='superadmin')
    admin_user = AdminUser.objects.create_user(
        email='locktest@example.com',
        name='Lock Test Admin',
        role=superadmin_role,
        password='CorrectPassword123!'
    )
    
    # Attempt wrong password 5 times
    for i in range(5):
        response = client.post('/api/admin/v1/auth/login/', {
            'email': 'locktest@example.com',
            'password': 'WrongPassword'
        })
        print(f'  Attempt {i+1}: Status {response.status_code}')
        assert response.status_code == 401, f"Failed attempt {i+1} should return 401"
    
    # Verify account is locked
    admin_user.refresh_from_db()
    assert admin_user.locked_until is not None, "Account should be locked"
    assert admin_user.failed_login_attempts == 5, f"Should have 5 failed attempts, got {admin_user.failed_login_attempts}"
    print(f'  ✓ Account locked after 5 failed attempts')
    
    # Attempt login while locked
    response = client.post('/api/admin/v1/auth/login/', {
        'email': 'locktest@example.com',
        'password': 'CorrectPassword123!'
    })
    assert response.status_code == 423, f"Locked account should return 423, got {response.status_code}"
    print(f'  ✓ Login rejected for locked account (423 Locked)')


def run_all_tests():
    """Run all verification tests"""
    print('='*70)
    print('ADMIN AUTH ENDPOINTS & JWT ROLE CLAIMS VERIFICATION')
    print('='*70)
    
    # Clean up existing test users if they exist
    emails = ['test@example.com', 'finance@example.com', 'support@example.com', 'ops@example.com', 'locktest@example.com']
    AdminUser.objects.filter(email__in=emails).delete()
    
    try:
        # Test 1-4: Login flow
        data = test_login_with_role_claims()
        new_data, old_token = test_token_refresh_with_rotation(data)
        test_logout(new_data)
        test_refresh_invalidation_after_logout(new_data)
        
        # Test 5-8: Additional flows
        test_password_reset_invalidation()
        test_forgot_password_endpoint()
        test_reset_password_endpoint()
        test_account_lockout()
        
        print('\n' + '='*70)
        print('✓ ALL TESTS PASSED SUCCESSFULLY!')
        print('='*70)
        print('\nSUMMARY:')
        print('  ✓ Login endpoint working with role claims')
        print('  ✓ JWT tokens include role, user_type, user_uuid')
        print('  ✓ Token refresh with rotation (old token revoked)')
        print('  ✓ Logout invalidates refresh token')
        print('  ✓ Refresh invalidation prevents reuse')
        print('  ✓ Password reset revokes all active tokens')
        print('  ✓ Forgot password creates valid reset token')
        print('  ✓ Account lockout after 5 failed attempts')
        print('='*70)
        
        return True
        
    except AssertionError as e:
        print(f'\n✗ TEST FAILED: {e}')
        print('='*70)
        return False
    except Exception as e:
        print(f'\n✗ UNEXPECTED ERROR: {e}')
        import traceback
        traceback.print_exc()
        print('='*70)
        return False
    finally:
        # Clean up database after test execution
        AdminUser.objects.filter(email__in=emails).delete()


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
