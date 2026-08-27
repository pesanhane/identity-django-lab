# users/tests/test_security.py

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from rest_framework import status
from rest_framework.test import APIClient, APIRequestFactory

from rest_framework_simplejwt.tokens import (
    AccessToken,
    RefreshToken,
)

from users.models import (
    User,
    Role,
    Permission,
    Organization,
    AuditLog,
)

from users.utils import create_audit_log


# =============================================================
# BASE
# =============================================================

class SecurityTestBase(TestCase):
    """
    Base para os testes de segurança do IAM.

    Arquitetura:

        Organization
            |
            +--- User
            |      |
            |      +--- roles (ManyToMany)
            |
            +--- Role
                   |
                   +--- permissions (ManyToMany)
    """

    def setUp(self):

        self.client = APIClient()

        # =====================================================
        # ORGANIZATION
        # =====================================================

        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Organization for security tests",
        )

        # =====================================================
        # PERMISSIONS
        # =====================================================

        self.view_permission = Permission.objects.create(
            code="user.view",
            description="View users",
        )

        self.create_permission = Permission.objects.create(
            code="user.create",
            description="Create users",
        )

        self.update_permission = Permission.objects.create(
            code="user.update",
            description="Update users",
        )

        self.delete_permission = Permission.objects.create(
            code="user.delete",
            description="Delete users",
        )

        self.audit_view_permission = Permission.objects.create(
            code="audit.view",
            description="View audit logs",
        )

        self.activate_permission = Permission.objects.create(
            code="user.activate",
            description="Activate users",
        )

        self.deactivate_permission = Permission.objects.create(
            code="user.deactivate",
            description="Deactivate users",
        )

        self.role_manage_permission = Permission.objects.create(
            code="role.manage",
            description="Manage roles and permissions",
        )

        self.password_change_permission = Permission.objects.create(
            code="password.change",
            description="Change password",
        )

        # =====================================================
        # ADMIN ROLE
        # =====================================================

        self.admin_role = Role.objects.create(
            organization=self.organization,
            name="Admin",
            description="Administrator",
        )

        self.admin_role.permissions.set([
            self.view_permission,
            self.create_permission,
            self.update_permission,
            self.delete_permission,
            self.audit_view_permission,
            self.activate_permission,
            self.deactivate_permission,
            self.role_manage_permission,
            self.password_change_permission,
        ])

        # =====================================================
        # NORMAL USER ROLE
        # =====================================================

        self.user_role = Role.objects.create(
            organization=self.organization,
            name="User",
            description="Normal user",
        )

        # =====================================================
        # ADMIN USER
        # =====================================================

        self.admin = User.objects.create_user(
            username="admin",
            email="admin@example.com",
            password="AdminPassword123!",
            organization=self.organization,
        )

        self.admin.roles.add(self.admin_role)

        # =====================================================
        # NORMAL USER
        # =====================================================

        self.user = User.objects.create_user(
            username="user",
            email="user@example.com",
            password="UserPassword123!",
            organization=self.organization,
        )

        self.user.roles.add(self.user_role)

        # =====================================================
        # KNOWN STATE
        # =====================================================

        self.admin.is_active = True
        self.admin.is_verified = True

        self.admin.save(
            update_fields=[
                "is_active",
                "is_verified",
            ]
        )

        self.user.is_active = True
        self.user.is_verified = False

        self.user.save(
            update_fields=[
                "is_active",
                "is_verified",
            ]
        )

    # =========================================================
    # ROLE HELPERS
    # =========================================================

    def user_has_role(self, user, role):
        return user.roles.filter(
            id=role.id
        ).exists()

    # =========================================================
    # JWT AUTHENTICATION
    # =========================================================

    def authenticate(self, user):

        refresh = RefreshToken.for_user(user)

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {str(refresh.access_token)}"
        )

        return refresh

    def clear_authentication(self):

        self.client.credentials()

    # =========================================================
    # CREATE TARGET USER
    # =========================================================

    def create_target_user(self):

        target = User.objects.create_user(
            username="target",
            email="target@example.com",
            password="TargetPassword123!",
            organization=self.organization,
        )

        target.roles.add(self.user_role)

        return target

    # =========================================================
    # CREATE SECOND ORGANIZATION
    # =========================================================

    def create_other_organization(self):

        return Organization.objects.create(
            name="Other Organization",
            description="Second organization for isolation tests",
        )


# =============================================================
# UNAUTHENTICATED ACCESS
# =============================================================

class UnauthenticatedSecurityTest(SecurityTestBase):

    def test_users_endpoint_requires_authentication(self):

        self.clear_authentication()

        response = self.client.get(
            "/api/users/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_me_endpoint_requires_authentication(self):

        self.clear_authentication()

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_change_password_requires_authentication(self):

        self.clear_authentication()

        response = self.client.post(
            "/api/users/change-password/",
            {
                "old_password": "UserPassword123!",
                "new_password": "NewPassword123!",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )


# =============================================================
# INVALID TOKEN
# =============================================================

class InvalidTokenSecurityTest(SecurityTestBase):

    def test_invalid_token_is_rejected(self):

        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer invalid-token"
        )

        response = self.client.get(
            "/api/users/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_random_jwt_is_rejected(self):

        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer invalid.jwt.token"
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_missing_bearer_prefix_is_rejected(self):

        refresh = RefreshToken.for_user(self.user)

        self.client.credentials(
            HTTP_AUTHORIZATION=str(refresh.access_token)
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )


# =============================================================
# AUTHENTICATION
# =============================================================

class AuthenticationSecurityTest(SecurityTestBase):

    def test_valid_credentials_are_accepted(self):

        response = self.client.post(
            "/api/token/",
            {
                "username": "user",
                "password": "UserPassword123!",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertIn(
            "access",
            response.data,
        )

        self.assertIn(
            "refresh",
            response.data,
        )

    def test_invalid_password_is_rejected(self):

        response = self.client.post(
            "/api/token/",
            {
                "username": "user",
                "password": "WrongPassword123!",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_invalid_username_is_rejected(self):

        response = self.client.post(
            "/api/token/",
            {
                "username": "nonexistent",
                "password": "UserPassword123!",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_inactive_user_cannot_login(self):

        self.user.is_active = False

        self.user.save(
            update_fields=["is_active"]
        )

        response = self.client.post(
            "/api/token/",
            {
                "username": "user",
                "password": "UserPassword123!",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_missing_username_is_rejected(self):

        response = self.client.post(
            "/api/token/",
            {
                "password": "UserPassword123!",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_missing_password_is_rejected(self):

        response = self.client.post(
            "/api/token/",
            {
                "username": "user",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_login_does_not_return_password(self):

        response = self.client.post(
            "/api/token/",
            {
                "username": "user",
                "password": "UserPassword123!",
            },
            format="json",
        )

        self.assertNotIn(
            "password",
            response.data,
        )


# =============================================================
# JWT SECURITY
# =============================================================

class JWTSecurityTest(SecurityTestBase):

    def test_access_token_is_accepted(self):

        self.authenticate(self.user)

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

    def test_expired_access_token_is_rejected(self):

        token = AccessToken.for_user(
            self.user
        )

        token.set_exp(
            from_time=timezone.now(),
            lifetime=timedelta(seconds=-1),
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {str(token)}"
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_refresh_token_cannot_access_protected_endpoint(self):

        refresh = RefreshToken.for_user(
            self.user
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {str(refresh)}"
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_access_token_cannot_be_used_as_refresh_token(self):

        access = AccessToken.for_user(
            self.user
        )

        response = self.client.post(
            "/api/token/refresh/",
            {
                "refresh": str(access),
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_invalid_refresh_token_is_rejected(self):

        response = self.client.post(
            "/api/token/refresh/",
            {
                "refresh": "invalid-refresh-token",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_refresh_token_contains_expected_user(self):

        refresh = RefreshToken.for_user(
            self.user
        )

        self.assertEqual(
            int(refresh["user_id"]),
            self.user.id,
        )


# =============================================================
# JWT BLACKLIST
# =============================================================

class JWTBlacklistSecurityTest(SecurityTestBase):

    def test_refresh_token_is_blacklisted_after_logout(self):

        refresh = self.authenticate(
            self.user
        )

        refresh_token = str(refresh)

        response = self.client.post(
            "/api/users/logout/",
            {
                "refresh": refresh_token,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        response = self.client.post(
            "/api/token/refresh/",
            {
                "refresh": refresh_token,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_blacklisted_refresh_token_cannot_be_reused(self):

        refresh = RefreshToken.for_user(
            self.user
        )

        refresh_token = str(refresh)

        self.authenticate(
            self.user
        )

        response = self.client.post(
            "/api/users/logout/",
            {
                "refresh": refresh_token,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        response = self.client.post(
            "/api/token/refresh/",
            {
                "refresh": refresh_token,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )


# =============================================================
# INACTIVE USER
# =============================================================

class InactiveUserSecurityTest(SecurityTestBase):

    def test_active_user_can_access_me(self):

        self.authenticate(
            self.user
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

    def test_inactive_user_cannot_access_me(self):

        self.authenticate(
            self.user
        )

        self.user.is_active = False

        self.user.save(
            update_fields=["is_active"]
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_inactive_user_cannot_access_users(self):

        self.authenticate(
            self.user
        )

        self.user.is_active = False

        self.user.save(
            update_fields=["is_active"]
        )

        response = self.client.get(
            "/api/users/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )


# =============================================================
# RBAC
# =============================================================

class RBACSecurityTest(SecurityTestBase):

    def test_normal_user_cannot_list_users(self):

        self.authenticate(
            self.user
        )

        response = self.client.get(
            "/api/users/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

    def test_normal_user_cannot_create_user(self):

        self.authenticate(
            self.user
        )

        response = self.client.post(
            "/api/users/",
            {
                "username": "attacker",
                "email": "attacker@example.com",
                "password": "Password123!",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

    def test_admin_can_access_users(self):

        self.authenticate(
            self.admin
        )

        response = self.client.get(
            "/api/users/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )


# =============================================================
# PRIVILEGE ESCALATION
# =============================================================

class PrivilegeEscalationSecurityTest(SecurityTestBase):

    def test_user_cannot_create_role(self):

        self.authenticate(
            self.user
        )

        response = self.client.post(
            "/api/users/roles/",
            {
                "name": "SuperAdmin",
                "description": "Malicious role",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

    def test_user_cannot_update_role(self):

        role = Role.objects.create(
            organization=self.organization,
            name="Manager",
            description="Manager",
        )

        self.authenticate(
            self.user
        )

        response = self.client.patch(
            f"/api/users/roles/{role.id}/",
            {
                "name": "SuperAdmin",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

    def test_user_cannot_delete_role(self):

        role = Role.objects.create(
            organization=self.organization,
            name="Manager",
            description="Manager",
        )

        self.authenticate(
            self.user
        )

        response = self.client.delete(
            f"/api/users/roles/{role.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

    def test_user_cannot_create_permission(self):

        self.authenticate(
            self.user
        )

        response = self.client.post(
            "/api/users/permissions/",
            {
                "code": "system.admin",
                "description": "Malicious permission",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

    def test_user_cannot_update_permission(self):

        permission = Permission.objects.create(
            code="system.test",
            description="Test",
        )

        self.authenticate(
            self.user
        )

        response = self.client.patch(
            f"/api/users/permissions/{permission.id}/",
            {
                "code": "system.admin",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

    def test_user_cannot_delete_permission(self):

        permission = Permission.objects.create(
            code="system.test",
            description="Test",
        )

        self.authenticate(
            self.user
        )

        response = self.client.delete(
            f"/api/users/permissions/{permission.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )


# =============================================================
# IDOR / HORIZONTAL ACCESS CONTROL
# =============================================================

class IDORSecurityTest(SecurityTestBase):

    def test_user_cannot_modify_another_user(self):

        target = self.create_target_user()

        self.authenticate(
            self.user
        )

        response = self.client.patch(
            f"/api/users/{target.id}/",
            {
                "email": "attacker@example.com",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

        target.refresh_from_db()

        self.assertEqual(
            target.email,
            "target@example.com",
        )

    def test_user_cannot_change_another_users_role(self):

        target = self.create_target_user()

        self.authenticate(
            self.user
        )

        response = self.client.patch(
            f"/api/users/{target.id}/",
            {
                "roles": [self.admin_role.id],
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

        target.refresh_from_db()

        self.assertTrue(
            self.user_has_role(
                target,
                self.user_role,
            )
        )

        self.assertFalse(
            self.user_has_role(
                target,
                self.admin_role,
            )
        )

    def test_user_cannot_delete_another_user(self):

        target = self.create_target_user()

        self.authenticate(
            self.user
        )

        response = self.client.delete(
            f"/api/users/{target.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

        self.assertTrue(
            User.objects.filter(
                id=target.id
            ).exists()
        )


# =============================================================
# MASS ASSIGNMENT
# =============================================================

class MassAssignmentSecurityTest(SecurityTestBase):

    def test_user_cannot_change_own_roles(self):

        self.authenticate(
            self.user
        )

        response = self.client.patch(
            f"/api/users/{self.user.id}/",
            {
                "roles": [self.admin_role.id],
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user_has_role(
                self.user,
                self.user_role,
            )
        )

        self.assertFalse(
            self.user_has_role(
                self.user,
                self.admin_role,
            )
        )

    def test_user_cannot_change_is_verified(self):

        self.authenticate(
            self.user
        )

        response = self.client.patch(
            f"/api/users/{self.user.id}/",
            {
                "is_verified": True,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

        self.user.refresh_from_db()

        self.assertFalse(
            self.user.is_verified
        )

    def test_user_cannot_change_is_active(self):

        self.authenticate(
            self.user
        )

        response = self.client.patch(
            f"/api/users/{self.user.id}/",
            {
                "is_active": False,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.is_active
        )

    def test_mass_assignment_is_rejected(self):

        self.authenticate(
            self.user
        )

        response = self.client.patch(
            f"/api/users/{self.user.id}/",
            {
                "roles": [self.admin_role.id],
                "is_verified": True,
                "is_active": False,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user_has_role(
                self.user,
                self.user_role,
            )
        )

        self.assertFalse(
            self.user_has_role(
                self.user,
                self.admin_role,
            )
        )

        self.assertFalse(
            self.user.is_verified
        )

        self.assertTrue(
            self.user.is_active
        )

    def test_admin_can_change_roles(self):

        self.authenticate(
            self.admin
        )

        response = self.client.patch(
            f"/api/users/{self.user.id}/",
            {
                "roles": [self.admin_role.id],
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user_has_role(
                self.user,
                self.admin_role,
            )
        )

    def test_admin_can_change_verification_status(self):

        self.authenticate(
            self.admin
        )

        response = self.client.patch(
            f"/api/users/{self.user.id}/",
            {
                "is_verified": True,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.is_verified
        )


# =============================================================
# CROSS ORGANIZATION / TENANT ISOLATION
# =============================================================

class CrossOrganizationSecurityTest(SecurityTestBase):

    def setUp(self):

        super().setUp()

        self.organization2 = self.create_other_organization()

        self.other_role = Role.objects.create(
            organization=self.organization2,
            name="OtherAdmin",
            description="Administrator of another organization",
        )

        self.other_user = User.objects.create_user(
            username="otheruser",
            email="other@example.com",
            password="OtherPassword123!",
            organization=self.organization2,
        )

        self.other_user.roles.add(
            self.other_role
        )

    def test_user_cannot_access_foreign_role(self):

        self.authenticate(
            self.admin
        )

        response = self.client.patch(
            f"/api/users/roles/{self.other_role.id}/",
            {
                "name": "HackedRole",
            },
            format="json",
        )

        self.assertIn(
            response.status_code,
            [
                status.HTTP_403_FORBIDDEN,
                status.HTTP_404_NOT_FOUND,
            ],
        )

        self.other_role.refresh_from_db()

        self.assertEqual(
            self.other_role.name,
            "OtherAdmin",
        )

    def test_user_cannot_assign_foreign_role(self):

        self.authenticate(
            self.admin
        )

        response = self.client.patch(
            f"/api/users/{self.user.id}/",
            {
                "roles": [self.other_role.id],
            },
            format="json",
        )

        self.assertIn(
            response.status_code,
            [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_403_FORBIDDEN,
            ],
        )

        self.user.refresh_from_db()

        self.assertFalse(
            self.user_has_role(
                self.user,
                self.other_role,
            )
        )

    def test_foreign_user_is_not_modifiable(self):

        self.authenticate(
            self.admin
        )

        response = self.client.patch(
            f"/api/users/{self.other_user.id}/",
            {
                "email": "hacked@example.com",
            },
            format="json",
        )

        self.assertIn(
            response.status_code,
            [
                status.HTTP_403_FORBIDDEN,
                status.HTTP_404_NOT_FOUND,
            ],
        )

        self.other_user.refresh_from_db()

        self.assertEqual(
            self.other_user.email,
            "other@example.com",
        )


# =============================================================
# PASSWORD SECURITY
# =============================================================

class PasswordSecurityTest(SecurityTestBase):

    def test_password_is_hashed(self):

        self.assertNotEqual(
            self.user.password,
            "UserPassword123!",
        )

        self.assertTrue(
            self.user.check_password(
                "UserPassword123!"
            )
        )

    def test_password_is_not_exposed_in_me(self):

        self.authenticate(
            self.admin
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertNotIn(
            "password",
            response.data,
        )

    def test_old_password_stops_working_after_change(self):

        self.authenticate(
            self.user
        )

        response = self.client.post(
            "/api/users/change-password/",
            {
                "old_password": "UserPassword123!",
                "new_password": "NewStrongPassword!2026",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.user.refresh_from_db()

        self.assertFalse(
            self.user.check_password(
                "UserPassword123!"
            )
        )

    def test_new_password_works_after_change(self):

        self.authenticate(
            self.user
        )

        response = self.client.post(
            "/api/users/change-password/",
            {
                "old_password": "UserPassword123!",
                "new_password": "NewStrongPassword!2026",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.check_password(
                "NewStrongPassword!2026"
            )
        )

    def test_wrong_old_password_is_rejected(self):

        self.authenticate(
            self.user
        )

        response = self.client.post(
            "/api/users/change-password/",
            {
                "old_password": "WrongPassword123!",
                "new_password": "NewStrongPassword!2026",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )


# =============================================================
# PASSWORD POLICY
# =============================================================

class PasswordPolicySecurityTest(SecurityTestBase):

    def test_weak_password_is_rejected(self):

        self.authenticate(
            self.user
        )

        response = self.client.post(
            "/api/users/change-password/",
            {
                "old_password": "UserPassword123!",
                "new_password": "123",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_numeric_password_is_rejected(self):

        self.authenticate(
            self.user
        )

        response = self.client.post(
            "/api/users/change-password/",
            {
                "old_password": "UserPassword123!",
                "new_password": "12345678",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_common_password_is_rejected(self):

        self.authenticate(
            self.user
        )

        response = self.client.post(
            "/api/users/change-password/",
            {
                "old_password": "UserPassword123!",
                "new_password": "password",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_same_password_is_rejected(self):

        self.authenticate(
            self.user
        )

        response = self.client.post(
            "/api/users/change-password/",
            {
                "old_password": "UserPassword123!",
                "new_password": "UserPassword123!",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_strong_password_is_accepted(self):

        self.authenticate(
            self.user
        )

        response = self.client.post(
            "/api/users/change-password/",
            {
                "old_password": "UserPassword123!",
                "new_password": "NewStrongPassword!2026",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )


# =============================================================
# AUDIT LOG UNIT SECURITY
# =============================================================

class SecurityAuditTest(TestCase):

    def setUp(self):

        self.organization = Organization.objects.create(
            name="Security Audit Organization"
        )

        self.user = User.objects.create_user(
            username="securityadmin",
            email="security@example.com",
            password="StrongPassword123!",
            organization=self.organization,
        )

        self.factory = APIRequestFactory()

    def test_login_failure_is_audited(self):

        request = self.factory.post(
            "/api/token/",
            {
                "username": "securityadmin",
                "password": "wrong-password",
            },
            format="json",
            REMOTE_ADDR="192.168.1.50",
            HTTP_USER_AGENT="TestClient/1.0",
        )

        request.user = self.user

        create_audit_log(
            request=request,
            action="LOGIN_FAILURE",
            description="Invalid username or password",
            result="FAILURE",
            status_code=401,
        )

        log = AuditLog.objects.latest("id")

        self.assertEqual(
            log.action,
            "LOGIN_FAILURE",
        )

        self.assertEqual(
            log.result,
            "FAILURE",
        )

        self.assertEqual(
            log.status_code,
            401,
        )

        self.assertEqual(
            log.ip_address,
            "192.168.1.50",
        )

        self.assertEqual(
            log.endpoint,
            "/api/token/",
        )

        self.assertEqual(
            log.http_method,
            "POST",
        )

        self.assertEqual(
            log.user_agent,
            "TestClient/1.0",
        )

    def test_access_denied_is_audited(self):

        request = self.factory.get(
            "/api/admin/users/",
            REMOTE_ADDR="192.168.1.51",
            HTTP_USER_AGENT="TestClient/1.0",
        )

        request.user = self.user

        create_audit_log(
            request=request,
            action="ACCESS_DENIED",
            description="User does not have permission",
            result="FAILURE",
            status_code=403,
        )

        log = AuditLog.objects.latest("id")

        self.assertEqual(
            log.action,
            "ACCESS_DENIED",
        )

        self.assertEqual(
            log.result,
            "FAILURE",
        )

        self.assertEqual(
            log.status_code,
            403,
        )

        self.assertEqual(
            log.endpoint,
            "/api/admin/users/",
        )

        self.assertEqual(
            log.http_method,
            "GET",
        )

    def test_privilege_escalation_is_audited(self):

        request = self.factory.patch(
            "/api/users/10/",
            {
                "roles": ["admin"],
            },
            format="json",
            REMOTE_ADDR="192.168.1.52",
            HTTP_USER_AGENT="TestClient/1.0",
        )

        request.user = self.user

        create_audit_log(
            request=request,
            action="PRIVILEGE_ESCALATION_ATTEMPT",
            description="User attempted to modify privileged role",
            object_type="User",
            object_id=10,
            result="FAILURE",
            status_code=403,
        )

        log = AuditLog.objects.latest("id")

        self.assertEqual(
            log.action,
            "PRIVILEGE_ESCALATION_ATTEMPT",
        )

        self.assertEqual(
            log.result,
            "FAILURE",
        )

        self.assertEqual(
            log.status_code,
            403,
        )

        self.assertEqual(
            log.object_type,
            "User",
        )

        self.assertEqual(
            log.object_id,
            "10",
        )

        self.assertEqual(
            log.ip_address,
            "192.168.1.52",
        )

    def test_invalid_token_is_audited(self):

        request = self.factory.get(
            "/api/users/",
            HTTP_AUTHORIZATION="Bearer invalid-token",
            REMOTE_ADDR="192.168.1.53",
            HTTP_USER_AGENT="TestClient/1.0",
        )

        request.user = self.user

        create_audit_log(
            request=request,
            action="TOKEN_INVALID",
            description="Invalid JWT token",
            result="FAILURE",
            status_code=401,
        )

        log = AuditLog.objects.latest("id")

        self.assertEqual(
            log.action,
            "TOKEN_INVALID",
        )

        self.assertEqual(
            log.result,
            "FAILURE",
        )

        self.assertEqual(
            log.status_code,
            401,
        )

        self.assertEqual(
            log.endpoint,
            "/api/users/",
        )


# =============================================================
# AUDIT EVENT INTEGRITY
# =============================================================

class AuditEventIntegrityTest(SecurityTestBase):

    def test_create_role_generates_audit_event(self):

        self.authenticate(
            self.admin
        )

        response = self.client.post(
            "/api/users/roles/",
            {
                "name": "Manager",
                "description": "Manager role",
                "permissions": [
                    self.view_permission.id,
                ],
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        log = AuditLog.objects.filter(
            action="CREATE_ROLE"
        ).order_by("-created_at").first()

        self.assertIsNotNone(log)

        self.assertEqual(
            log.user,
            self.admin,
        )

        self.assertIn(
            "Manager",
            log.description,
        )

    def test_update_role_generates_audit_event(self):

        role = Role.objects.create(
            organization=self.organization,
            name="Manager",
            description="Manager role",
        )

        self.authenticate(
            self.admin
        )

        response = self.client.patch(
            f"/api/users/roles/{role.id}/",
            {
                "description": "Updated manager role",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        log = AuditLog.objects.filter(
            action="UPDATE_ROLE"
        ).order_by("-created_at").first()

        self.assertIsNotNone(log)

        self.assertEqual(
            log.user,
            self.admin,
        )

        self.assertIn(
            "Manager",
            log.description,
        )

    def test_delete_role_generates_audit_event(self):

        role = Role.objects.create(
            organization=self.organization,
            name="Manager",
            description="Manager role",
        )

        self.authenticate(
            self.admin
        )

        response = self.client.delete(
            f"/api/users/roles/{role.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_204_NO_CONTENT,
        )

        log = AuditLog.objects.filter(
            action="DELETE_ROLE"
        ).order_by("-created_at").first()

        self.assertIsNotNone(log)

        self.assertEqual(
            log.user,
            self.admin,
        )

        self.assertIn(
            "Manager",
            log.description,
        )

    def test_create_permission_generates_audit_event(self):

        self.authenticate(
            self.admin
        )

        response = self.client.post(
            "/api/users/permissions/",
            {
                "code": "system.test",
                "description": "System test permission",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        log = AuditLog.objects.filter(
            action="CREATE_PERMISSION"
        ).order_by("-created_at").first()

        self.assertIsNotNone(log)

        self.assertEqual(
            log.user,
            self.admin,
        )

        self.assertIn(
            "system.test",
            log.description,
        )

    def test_update_permission_generates_audit_event(self):

        permission = Permission.objects.create(
            code="system.test",
            description="System test permission",
        )

        self.authenticate(
            self.admin
        )

        response = self.client.patch(
            f"/api/users/permissions/{permission.id}/",
            {
                "description": "Updated permission",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        log = AuditLog.objects.filter(
            action="UPDATE_PERMISSION"
        ).order_by("-created_at").first()

        self.assertIsNotNone(log)

        self.assertEqual(
            log.user,
            self.admin,
        )

        self.assertIn(
            "system.test",
            log.description,
        )

    def test_delete_permission_generates_audit_event(self):

        permission = Permission.objects.create(
            code="system.test",
            description="System test permission",
        )

        self.authenticate(
            self.admin
        )

        response = self.client.delete(
            f"/api/users/permissions/{permission.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_204_NO_CONTENT,
        )

        log = AuditLog.objects.filter(
            action="DELETE_PERMISSION"
        ).order_by("-created_at").first()

        self.assertIsNotNone(log)

        self.assertEqual(
            log.user,
            self.admin,
        )

        self.assertIn(
            "system.test",
            log.description,
        )

    def test_activate_user_generates_audit_event(self):

        self.user.is_active = False

        self.user.save(
            update_fields=["is_active"]
        )

        self.authenticate(
            self.admin
        )

        response = self.client.post(
            f"/api/users/{self.user.id}/activate/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        log = AuditLog.objects.filter(
            action="ACTIVATE_USER"
        ).order_by("-created_at").first()

        self.assertIsNotNone(log)

        self.assertEqual(
            log.user,
            self.admin,
        )

        self.assertIn(
            self.user.username,
            log.description,
        )

    def test_deactivate_user_generates_audit_event(self):

        self.authenticate(
            self.admin
        )

        response = self.client.post(
            f"/api/users/{self.user.id}/deactivate/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        log = AuditLog.objects.filter(
            action="DEACTIVATE_USER"
        ).order_by("-created_at").first()

        self.assertIsNotNone(log)

        self.assertEqual(
            log.user,
            self.admin,
        )

        self.assertIn(
            self.user.username,
            log.description,
        )


# =============================================================
# INPUT VALIDATION
# =============================================================

class InputValidationSecurityTest(SecurityTestBase):

    def test_invalid_role_id_is_rejected(self):

        self.authenticate(
            self.admin
        )

        response = self.client.patch(
            f"/api/users/{self.user.id}/",
            {
                "roles": [999999999],
            },
            format="json",
        )

        self.assertIn(
            response.status_code,
            [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_404_NOT_FOUND,
            ],
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user_has_role(
                self.user,
                self.user_role,
            )
        )

    def test_nonexistent_user_update_is_not_applied(self):

        self.authenticate(
            self.admin
        )

        response = self.client.patch(
            "/api/users/999999999/",
            {
                "roles": [self.admin_role.id],
            },
            format="json",
        )

        self.assertIn(
            response.status_code,
            [
                status.HTTP_403_FORBIDDEN,
                status.HTTP_404_NOT_FOUND,
            ],
        )

    def test_nonexistent_permission_cannot_be_updated(self):

        self.authenticate(
            self.admin
        )

        response = self.client.patch(
            "/api/users/permissions/999999999/",
            {
                "description": "Malicious update",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND,
        )

    def test_nonexistent_role_cannot_be_deleted(self):

        self.authenticate(
            self.admin
        )

        response = self.client.delete(
            "/api/users/roles/999999999/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND,
        )


# =============================================================
# ADMIN AUTHORIZATION
# =============================================================

class AdminAuthorizationSecurityTest(SecurityTestBase):

    def test_admin_can_create_role(self):

        self.authenticate(
            self.admin
        )

        response = self.client.post(
            "/api/users/roles/",
            {
                "name": "Manager",
                "description": "Manager role",
                "permissions": [
                    self.view_permission.id,
                ],
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

    def test_admin_can_create_permission(self):

        self.authenticate(
            self.admin
        )

        response = self.client.post(
            "/api/users/permissions/",
            {
                "code": "system.test",
                "description": "System permission",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

    def test_admin_can_update_permission(self):

        permission = Permission.objects.create(
            code="system.test",
            description="Original",
        )

        self.authenticate(
            self.admin
        )

        response = self.client.patch(
            f"/api/users/permissions/{permission.id}/",
            {
                "description": "Updated",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )


# =============================================================
# SECURITY REGRESSION TESTS
# =============================================================

class SecurityRegressionTest(SecurityTestBase):

    def test_user_role_remains_user_after_failed_escalation(self):

        self.authenticate(
            self.user
        )

        response = self.client.patch(
            f"/api/users/{self.user.id}/",
            {
                "roles": [self.admin_role.id],
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user_has_role(
                self.user,
                self.user_role,
            )
        )

        self.assertFalse(
            self.user_has_role(
                self.user,
                self.admin_role,
            )
        )

    def test_user_cannot_enable_own_account_after_deactivation(self):

        self.user.is_active = False

        self.user.save(
            update_fields=["is_active"]
        )

        self.authenticate(
            self.user
        )

        response = self.client.patch(
            f"/api/users/{self.user.id}/",
            {
                "is_active": True,
            },
            format="json",
        )

        self.assertIn(
            response.status_code,
            [
                status.HTTP_401_UNAUTHORIZED,
                status.HTTP_403_FORBIDDEN,
            ],
        )

        self.user.refresh_from_db()

        self.assertFalse(
            self.user.is_active
        )

    def test_user_cannot_assign_privileged_permission_to_role(self):

        self.authenticate(
            self.user
        )

        response = self.client.post(
            "/api/users/roles/",
            {
                "name": "MaliciousRole",
                "description": "Privilege escalation",
                "permissions": [
                    self.role_manage_permission.id,
                ],
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

    def test_user_cannot_create_admin_like_role(self):

        self.authenticate(
            self.user
        )

        response = self.client.post(
            "/api/users/roles/",
            {
                "name": "SuperAdmin",
                "description": "Administrative role",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )