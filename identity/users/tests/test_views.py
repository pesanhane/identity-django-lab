from django.test import TestCase

from rest_framework.test import APIClient
from rest_framework import status

from rest_framework_simplejwt.tokens import (
    RefreshToken,
)

from users.models import (
    User,
    Role,
    Permission,
    AuditLog,
    Organization,
    Group,
)


# ============================================================
# BASE PARA OS TESTES DA API
# ============================================================

class APITestBase(TestCase):

    def setUp(self):

        self.client = APIClient()

        # =====================================================
        # ORGANIZAÇÃO PRINCIPAL
        # =====================================================

        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Organização para testes"
        )

        # =====================================================
        # SEGUNDA ORGANIZAÇÃO
        # Utilizada para testar isolamento multi-tenant
        # =====================================================

        self.other_organization = Organization.objects.create(
            name="Other Organization",
            description="Outra organização"
        )

        # =====================================================
        # PERMISSIONS
        # =====================================================

        permission_codes = [
            "user.view",
            "user.create",
            "user.update",
            "user.delete",
            "user.activate",
            "user.deactivate",
            "password.change",
            "audit.view",
            "role.manage",
            "group.manage",
        ]

        self.permissions = {}

        for code in permission_codes:

            permission = Permission.objects.create(
                code=code,
                description=f"Permission {code}"
            )

            self.permissions[code] = permission

        # =====================================================
        # ADMIN ROLE
        # =====================================================

        self.admin_role = Role.objects.create(
            name="Admin",
            description="Administrador do sistema",
            organization=self.organization
        )

        self.admin_role.permissions.set(
            self.permissions.values()
        )

        # =====================================================
        # USER ROLE
        # =====================================================

        self.user_role = Role.objects.create(
            name="User",
            description="Utilizador normal",
            organization=self.organization
        )

        # =====================================================
        # ADMIN USER
        # =====================================================

        self.admin = User.objects.create_user(
            username="admin",
            email="admin@example.com",
            password="AdminPassword123!",
            organization=self.organization
        )

        self.admin.roles.add(
            self.admin_role
        )

        # =====================================================
        # NORMAL USER
        # =====================================================

        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPassword123!",
            organization=self.organization
        )

        self.user.roles.add(
            self.user_role
        )

        # =====================================================
        # USER DA OUTRA ORGANIZAÇÃO
        # =====================================================

        self.other_role = Role.objects.create(
            name="OtherAdmin",
            description="Administrador da outra organização",
            organization=self.other_organization
        )

        self.other_role.permissions.set(
            self.permissions.values()
        )

        self.other_user = User.objects.create_user(
            username="otheruser",
            email="other@example.com",
            password="OtherPassword123!",
            organization=self.other_organization
        )

        self.other_user.roles.add(
            self.other_role
        )

        # =====================================================
        # AUTHENTICATE AS ADMIN
        # =====================================================

        self.authenticate(self.admin)

    # =========================================================
    # JWT AUTHENTICATION
    # =========================================================

    def authenticate(self, user):

        refresh = RefreshToken.for_user(user)

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}"
        )

        return refresh

    # =========================================================
    # LOGOUT / AUTH RESET
    # =========================================================

    def unauthenticate(self):

        self.client.credentials()


# ============================================================
# USER MODEL / API
# ============================================================

class UserViewTest(APITestBase):

    # =========================================================
    # LIST USERS
    # =========================================================

    def test_admin_can_list_users(self):

        response = self.client.get(
            "/api/users/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.assertIsInstance(
            response.data,
            list
        )

        usernames = [
            user["username"]
            for user in response.data
        ]

        self.assertIn(
            "admin",
            usernames
        )

        self.assertIn(
            "testuser",
            usernames
        )

        # O utilizador da outra organização não deve aparecer
        self.assertNotIn(
            "otheruser",
            usernames
        )

    # =========================================================
    # CREATE USER
    # =========================================================

    def test_admin_can_create_user(self):

        data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "NewPassword123!",
            "first_name": "New",
            "last_name": "User",
            "phone_number": "841234567",
            "roles": [
                self.user_role.id
            ],
        }

        response = self.client.post(
            "/api/users/",
            data,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED
        )

        user = User.objects.get(
            username="newuser"
        )

        self.assertEqual(
            user.organization,
            self.organization
        )

        self.assertEqual(
            user.email,
            "newuser@example.com"
        )

        self.assertTrue(
            user.check_password(
                "NewPassword123!"
            )
        )

        self.assertTrue(
            user.roles.filter(
                id=self.user_role.id
            ).exists()
        )

        self.assertTrue(
            AuditLog.objects.filter(
                action="CREATE_USER",
                organization=self.organization
            ).exists()
        )

    # =========================================================
    # CREATE USER WITHOUT ROLE
    # =========================================================

    def test_admin_can_create_user_without_role(self):

        data = {
            "username": "noroleuser",
            "email": "norole@example.com",
            "password": "NewPassword123!",
        }

        response = self.client.post(
            "/api/users/",
            data,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED
        )

        user = User.objects.get(
            username="noroleuser"
        )

        self.assertEqual(
            user.organization,
            self.organization
        )

        self.assertEqual(
            user.roles.count(),
            0
        )

    # =========================================================
    # GET USER
    # =========================================================

    def test_admin_can_get_user(self):

        response = self.client.get(
            f"/api/users/{self.user.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.assertEqual(
            response.data["username"],
            "testuser"
        )

        self.assertEqual(
            response.data["organization"],
            self.organization.id
        )

    # =========================================================
    # UPDATE USER
    # =========================================================

    def test_admin_can_update_user(self):

        data = {
            "first_name": "Updated",
            "last_name": "User"
        }

        response = self.client.patch(
            f"/api/users/{self.user.id}/",
            data,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.user.refresh_from_db()

        self.assertEqual(
            self.user.first_name,
            "Updated"
        )

        self.assertEqual(
            self.user.last_name,
            "User"
        )

        self.assertTrue(
            AuditLog.objects.filter(
                action="UPDATE_USER",
                organization=self.organization
            ).exists()
        )

    # =========================================================
    # ADMIN CAN UPDATE USER ROLES
    # =========================================================

    def test_admin_can_update_user_roles(self):

        data = {
            "roles": [
                self.admin_role.id
            ]
        }

        response = self.client.patch(
            f"/api/users/{self.user.id}/",
            data,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.roles.filter(
                id=self.admin_role.id
            ).exists()
        )

        self.assertFalse(
            self.user.roles.filter(
                id=self.user_role.id
            ).exists()
        )

    # =========================================================
    # ADMIN CANNOT ASSIGN ROLE FROM ANOTHER ORGANIZATION
    # =========================================================

    def test_admin_cannot_assign_role_from_another_organization(
        self
    ):

        data = {
            "roles": [
                self.other_role.id
            ]
        }

        response = self.client.patch(
            f"/api/users/{self.user.id}/",
            data,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST
        )

        self.user.refresh_from_db()

        self.assertFalse(
            self.user.roles.filter(
                id=self.other_role.id
            ).exists()
        )

    # =========================================================
    # DELETE USER
    # =========================================================

    def test_admin_can_delete_user(self):

        user_id = self.user.id

        response = self.client.delete(
            f"/api/users/{user_id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_204_NO_CONTENT
        )

        self.assertFalse(
            User.objects.filter(
                id=user_id
            ).exists()
        )

        self.assertTrue(
            AuditLog.objects.filter(
                action="DELETE_USER",
                organization=self.organization
            ).exists()
        )

    # =========================================================
    # CANNOT ACCESS USER FROM ANOTHER ORGANIZATION
    # =========================================================

    def test_admin_cannot_get_user_from_another_organization(
        self
    ):

        response = self.client.get(
            f"/api/users/{self.other_user.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND
        )

    # =========================================================
    # CANNOT UPDATE USER FROM ANOTHER ORGANIZATION
    # =========================================================

    def test_admin_cannot_update_user_from_another_organization(
        self
    ):

        response = self.client.patch(
            f"/api/users/{self.other_user.id}/",
            {
                "first_name": "Hacked"
            },
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND
        )

        self.other_user.refresh_from_db()

        self.assertNotEqual(
            self.other_user.first_name,
            "Hacked"
        )

    # =========================================================
    # CANNOT DELETE USER FROM ANOTHER ORGANIZATION
    # =========================================================

    def test_admin_cannot_delete_user_from_another_organization(
        self
    ):

        user_id = self.other_user.id

        response = self.client.delete(
            f"/api/users/{user_id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND
        )

        self.assertTrue(
            User.objects.filter(
                id=user_id
            ).exists()
        )


# ============================================================
# USER ACTIVATION
# ============================================================

class UserActivationViewTest(APITestBase):

    # =========================================================
    # ACTIVATE
    # =========================================================

    def test_admin_can_activate_user(self):

        self.user.is_active = False
        self.user.save()

        response = self.client.post(
            f"/api/users/{self.user.id}/activate/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.is_active
        )

        self.assertTrue(
            AuditLog.objects.filter(
                action="ACTIVATE_USER",
                organization=self.organization
            ).exists()
        )

    # =========================================================
    # DEACTIVATE
    # =========================================================

    def test_admin_can_deactivate_user(self):

        response = self.client.post(
            f"/api/users/{self.user.id}/deactivate/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.user.refresh_from_db()

        self.assertFalse(
            self.user.is_active
        )

        self.assertTrue(
            AuditLog.objects.filter(
                action="DEACTIVATE_USER",
                organization=self.organization
            ).exists()
        )

    # =========================================================
    # CANNOT DEACTIVATE OWN ACCOUNT
    # =========================================================

    def test_admin_cannot_deactivate_own_account(self):

        response = self.client.post(
            f"/api/users/{self.admin.id}/deactivate/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST
        )

        self.admin.refresh_from_db()

        self.assertTrue(
            self.admin.is_active
        )

        self.assertFalse(
            AuditLog.objects.filter(
                action="DEACTIVATE_USER"
            ).exists()
        )

    # =========================================================
    # CANNOT ACTIVATE USER FROM ANOTHER ORGANIZATION
    # =========================================================

    def test_admin_cannot_activate_user_from_other_organization(
        self
    ):

        self.other_user.is_active = False
        self.other_user.save()

        response = self.client.post(
            f"/api/users/{self.other_user.id}/activate/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND
        )

        self.other_user.refresh_from_db()

        self.assertFalse(
            self.other_user.is_active
        )


# ============================================================
# RBAC
# ============================================================

class RBACViewTest(APITestBase):

    # =========================================================
    # LIST
    # =========================================================

    def test_user_without_permission_cannot_list_users(self):

        self.authenticate(self.user)

        response = self.client.get(
            "/api/users/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN
        )

    # =========================================================
    # CREATE
    # =========================================================

    def test_user_without_permission_cannot_create_user(self):

        self.authenticate(self.user)

        data = {
            "username": "blockeduser",
            "email": "blocked@example.com",
            "password": "BlockedPassword123!",
        }

        response = self.client.post(
            "/api/users/",
            data,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN
        )

        self.assertFalse(
            User.objects.filter(
                username="blockeduser"
            ).exists()
        )

    # =========================================================
    # GET USER
    # =========================================================

    def test_user_without_permission_cannot_get_user(self):

        self.authenticate(self.user)

        response = self.client.get(
            f"/api/users/{self.admin.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN
        )

    # =========================================================
    # UPDATE
    # =========================================================

    def test_user_without_permission_cannot_update_user(self):

        self.authenticate(self.user)

        response = self.client.patch(
            f"/api/users/{self.admin.id}/",
            {
                "first_name": "Hacked"
            },
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN
        )

    # =========================================================
    # DELETE
    # =========================================================

    def test_user_without_permission_cannot_delete_user(self):

        self.authenticate(self.user)

        response = self.client.delete(
            f"/api/users/{self.admin.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN
        )

        self.assertTrue(
            User.objects.filter(
                id=self.admin.id
            ).exists()
        )

    # =========================================================
    # ACTIVATE
    # =========================================================

    def test_user_without_permission_cannot_activate_user(self):

        self.authenticate(self.user)

        self.admin.is_active = False
        self.admin.save()

        response = self.client.post(
            f"/api/users/{self.admin.id}/activate/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN
        )

        self.admin.refresh_from_db()

        self.assertFalse(
            self.admin.is_active
        )

    # =========================================================
    # DEACTIVATE
    # =========================================================

    def test_user_without_permission_cannot_deactivate_user(self):

        self.authenticate(self.user)

        response = self.client.post(
            f"/api/users/{self.admin.id}/deactivate/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN
        )

    # =========================================================
    # UNAUTHENTICATED
    # =========================================================

    def test_unauthenticated_user_cannot_access_users(self):

        self.unauthenticate()

        response = self.client.get(
            "/api/users/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED
        )


# ============================================================
# CURRENT USER
# ============================================================

class CurrentUserViewTest(APITestBase):

    def test_authenticated_user_can_access_me(self):

        self.authenticate(self.user)

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.assertEqual(
            response.data["username"],
            "testuser"
        )

        self.assertEqual(
            response.data["organization"],
            self.organization.id
        )


# ============================================================
# PASSWORD
# ============================================================

class ChangePasswordViewTest(APITestBase):

    # =========================================================
    # CHANGE PASSWORD
    # =========================================================

    def test_user_can_change_password(self):

        self.authenticate(self.user)

        data = {
            "old_password": "TestPassword123!",
            "new_password": "NewPassword123!"
        }

        response = self.client.post(
            "/api/users/change-password/",
            data,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.check_password(
                "NewPassword123!"
            )
        )

        self.assertTrue(
            AuditLog.objects.filter(
                action="CHANGE_PASSWORD",
                organization=self.organization
            ).exists()
        )

    # =========================================================
    # WRONG OLD PASSWORD
    # =========================================================

    def test_wrong_old_password_is_rejected(self):

        self.authenticate(self.user)

        data = {
            "old_password": "WrongPassword123!",
            "new_password": "NewPassword123!"
        }

        response = self.client.post(
            "/api/users/change-password/",
            data,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.check_password(
                "TestPassword123!"
            )
        )

    # =========================================================
    # SAME PASSWORD
    # =========================================================

    def test_new_password_cannot_be_same_as_old_password(self):

        self.authenticate(self.user)

        data = {
            "old_password": "TestPassword123!",
            "new_password": "TestPassword123!"
        }

        response = self.client.post(
            "/api/users/change-password/",
            data,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST
        )

    # =========================================================
    # UNAUTHENTICATED
    # =========================================================

    def test_unauthenticated_user_cannot_change_password(self):

        self.unauthenticate()

        response = self.client.post(
            "/api/users/change-password/",
            {
                "old_password": "TestPassword123!",
                "new_password": "NewPassword123!"
            },
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED
        )


# ============================================================
# LOGOUT
# ============================================================

class LogoutViewTest(APITestBase):

    def test_logout_blacklists_refresh_token(self):

        refresh = self.authenticate(
            self.user
        )

        refresh_token = str(refresh)

        response = self.client.post(
            "/api/users/logout/",
            {
                "refresh": refresh_token
            },
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.assertTrue(
            AuditLog.objects.filter(
                action="LOGOUT",
                organization=self.organization
            ).exists()
        )

        # O refresh token não deve mais ser utilizável
        self.assertRaises(
            Exception,
            RefreshToken,
            refresh_token
        )


# ============================================================
# AUDIT LOG
# ============================================================

class AuditViewTest(APITestBase):

    # =========================================================
    # ADMIN CAN VIEW
    # =========================================================

    def test_admin_can_view_audit_logs(self):

        AuditLog.objects.create(
            organization=self.organization,
            user=self.admin,
            action="LOGIN",
            description="Login de teste",
            ip_address="127.0.0.1"
        )

        response = self.client.get(
            "/api/users/audit/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.assertIsInstance(
            response.data,
            list
        )

        self.assertGreaterEqual(
            len(response.data),
            1
        )

    # =========================================================
    # USER WITHOUT PERMISSION
    # =========================================================

    def test_user_without_audit_permission_is_denied(self):

        self.authenticate(self.user)

        response = self.client.get(
            "/api/users/audit/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN
        )

    # =========================================================
    # ORGANIZATION ISOLATION
    # =========================================================

    def test_audit_logs_are_isolated_by_organization(self):

        AuditLog.objects.create(
            organization=self.organization,
            user=self.admin,
            action="LOGIN",
            description="Log da organização A",
            ip_address="127.0.0.1"
        )

        AuditLog.objects.create(
            organization=self.other_organization,
            user=self.other_user,
            action="LOGIN",
            description="Log da organização B",
            ip_address="127.0.0.2"
        )

        response = self.client.get(
            "/api/users/audit/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        descriptions = [
            item["description"]
            for item in response.data
        ]

        self.assertIn(
            "Log da organização A",
            descriptions
        )

        self.assertNotIn(
            "Log da organização B",
            descriptions
        )


# ============================================================
# ROLE API
# ============================================================

class RoleViewTest(APITestBase):

    # =========================================================
    # LIST
    # =========================================================

    def test_admin_can_list_roles(self):

        response = self.client.get(
            "/api/users/roles/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        role_names = [
            role["name"]
            for role in response.data
        ]

        self.assertIn(
            "Admin",
            role_names
        )

        self.assertIn(
            "User",
            role_names
        )

        self.assertNotIn(
            "OtherAdmin",
            role_names
        )

    # =========================================================
    # CREATE
    # =========================================================

    def test_admin_can_create_role(self):

        data = {
            "name": "Manager",
            "description": "Gestor do sistema",
            "permissions": [
                self.permissions["user.view"].id
            ]
        }

        response = self.client.post(
            "/api/users/roles/",
            data,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED
        )

        role = Role.objects.get(
            name="Manager"
        )

        self.assertEqual(
            role.organization,
            self.organization
        )

        self.assertTrue(
            role.permissions.filter(
                id=self.permissions["user.view"].id
            ).exists()
        )

        self.assertTrue(
            AuditLog.objects.filter(
                action="CREATE_ROLE",
                organization=self.organization
            ).exists()
        )

    # =========================================================
    # GET
    # =========================================================

    def test_admin_can_get_role(self):

        response = self.client.get(
            f"/api/users/roles/{self.admin_role.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.assertEqual(
            response.data["name"],
            "Admin"
        )

        self.assertEqual(
            response.data["organization"],
            self.organization.id
        )

    # =========================================================
    # UPDATE
    # =========================================================

    def test_admin_can_update_role(self):

        data = {
            "name": "Administrator",
            "description": "Administrator atualizado",
            "permissions": [
                self.permissions["user.view"].id
            ]
        }

        response = self.client.patch(
            f"/api/users/roles/{self.admin_role.id}/",
            data,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.admin_role.refresh_from_db()

        self.assertEqual(
            self.admin_role.name,
            "Administrator"
        )

        self.assertTrue(
            AuditLog.objects.filter(
                action="UPDATE_ROLE",
                organization=self.organization
            ).exists()
        )

    # =========================================================
    # DUPLICATE ROLE
    # =========================================================

    def test_admin_cannot_create_duplicate_role(self):

        data = {
            "name": "Admin",
            "description": "Role duplicada",
            "permissions": []
        }

        response = self.client.post(
            "/api/users/roles/",
            data,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST
        )

    # =========================================================
    # DELETE
    # =========================================================

    def test_admin_can_delete_role(self):

        role = Role.objects.create(
            name="Temporary",
            description="Role temporária",
            organization=self.organization
        )

        role_id = role.id

        response = self.client.delete(
            f"/api/users/roles/{role_id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_204_NO_CONTENT
        )

        self.assertFalse(
            Role.objects.filter(
                id=role_id
            ).exists()
        )

        self.assertTrue(
            AuditLog.objects.filter(
                action="DELETE_ROLE",
                organization=self.organization
            ).exists()
        )

    # =========================================================
    # CROSS ORGANIZATION
    # =========================================================

    def test_admin_cannot_get_role_from_another_organization(
        self
    ):

        response = self.client.get(
            f"/api/users/roles/{self.other_role.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND
        )

    # =========================================================
    # USER WITHOUT PERMISSION
    # =========================================================

    def test_user_without_role_permission_cannot_manage_roles(
        self
    ):

        self.authenticate(self.user)

        response = self.client.get(
            "/api/users/roles/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN
        )


# ============================================================
# PERMISSION API
# ============================================================

class PermissionViewTest(APITestBase):

    # =========================================================
    # LIST
    # =========================================================

    def test_admin_can_list_permissions(self):

        response = self.client.get(
            "/api/users/permissions/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.assertIsInstance(
            response.data,
            list
        )

    # =========================================================
    # CREATE
    # =========================================================

    def test_admin_can_create_permission(self):

        data = {
            "code": "profile.update",
            "description": "Atualizar perfil"
        }

        response = self.client.post(
            "/api/users/permissions/",
            data,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED
        )

        self.assertTrue(
            Permission.objects.filter(
                code="profile.update"
            ).exists()
        )

        self.assertTrue(
            AuditLog.objects.filter(
                action="CREATE_PERMISSION",
                organization=self.organization
            ).exists()
        )

    # =========================================================
    # GET
    # =========================================================

    def test_admin_can_get_permission(self):

        permission = self.permissions[
            "user.view"
        ]

        response = self.client.get(
            f"/api/users/permissions/{permission.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.assertEqual(
            response.data["code"],
            "user.view"
        )

    # =========================================================
    # UPDATE
    # =========================================================

    def test_admin_can_update_permission(self):

        permission = self.permissions[
            "user.view"
        ]

        data = {
            "code": "user.read",
            "description": "Consultar utilizadores"
        }

        response = self.client.patch(
            f"/api/users/permissions/{permission.id}/",
            data,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        permission.refresh_from_db()

        self.assertEqual(
            permission.code,
            "user.read"
        )

        self.assertTrue(
            AuditLog.objects.filter(
                action="UPDATE_PERMISSION",
                organization=self.organization
            ).exists()
        )

    # =========================================================
    # DELETE
    # =========================================================

    def test_admin_can_delete_permission(self):

        permission = Permission.objects.create(
            code="temporary.permission",
            description="Temporary"
        )

        permission_id = permission.id

        response = self.client.delete(
            f"/api/users/permissions/{permission_id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_204_NO_CONTENT
        )

        self.assertFalse(
            Permission.objects.filter(
                id=permission_id
            ).exists()
        )

        self.assertTrue(
            AuditLog.objects.filter(
                action="DELETE_PERMISSION",
                organization=self.organization
            ).exists()
        )

    # =========================================================
    # USER WITHOUT PERMISSION
    # =========================================================

    def test_user_without_role_permission_cannot_manage_permissions(
        self
    ):

        self.authenticate(self.user)

        response = self.client.get(
            "/api/users/permissions/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN
        )


# ============================================================
# GROUP API
# ============================================================

class GroupViewTest(APITestBase):

    # =========================================================
    # LIST
    # =========================================================

    def test_admin_can_list_groups(self):

        group = Group.objects.create(
            name="Developers",
            description="Grupo de desenvolvimento",
            organization=self.organization
        )

        response = self.client.get(
            "/api/users/groups/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        group_ids = [
            item["id"]
            for item in response.data
        ]

        self.assertIn(
            group.id,
            group_ids
        )

    # =========================================================
    # CREATE
    # =========================================================

    def test_admin_can_create_group(self):

        data = {
            "name": "Developers",
            "description": "Grupo de desenvolvimento",
            "is_active": True,
        }

        response = self.client.post(
            "/api/users/groups/",
            data,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED
        )

        group = Group.objects.get(
            name="Developers"
        )

        self.assertEqual(
            group.organization,
            self.organization
        )

        self.assertTrue(
            AuditLog.objects.filter(
                action="CREATE_GROUP",
                organization=self.organization
            ).exists()
        )

    # =========================================================
    # GET
    # =========================================================

    def test_admin_can_get_group(self):

        group = Group.objects.create(
            name="Developers",
            description="Grupo",
            organization=self.organization
        )

        response = self.client.get(
            f"/api/users/groups/{group.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.assertEqual(
            response.data["name"],
            "Developers"
        )

        self.assertEqual(
            response.data["organization"],
            self.organization.id
        )

    # =========================================================
    # UPDATE
    # =========================================================

    def test_admin_can_update_group(self):

        group = Group.objects.create(
            name="Developers",
            description="Grupo",
            organization=self.organization
        )

        data = {
            "name": "Development Team",
            "description": "Grupo atualizado",
            "is_active": True,
        }

        response = self.client.patch(
            f"/api/users/groups/{group.id}/",
            data,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        group.refresh_from_db()

        self.assertEqual(
            group.name,
            "Development Team"
        )

        self.assertTrue(
            AuditLog.objects.filter(
                action="UPDATE_GROUP",
                organization=self.organization
            ).exists()
        )

    # =========================================================
    # DUPLICATE GROUP
    # =========================================================

    def test_admin_cannot_create_duplicate_group(self):

        Group.objects.create(
            name="Developers",
            description="Primeiro grupo",
            organization=self.organization
        )

        response = self.client.post(
            "/api/users/groups/",
            {
                "name": "Developers",
                "description": "Grupo duplicado",
                "is_active": True,
            },
            format="json"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST
        )

    # =========================================================
    # DELETE
    # =========================================================

    def test_admin_can_delete_group(self):

        group = Group.objects.create(
            name="Temporary",
            description="Grupo temporário",
            organization=self.organization
        )

        group_id = group.id

        response = self.client.delete(
            f"/api/users/groups/{group_id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_204_NO_CONTENT
        )

        self.assertFalse(
            Group.objects.filter(
                id=group_id
            ).exists()
        )

        self.assertTrue(
            AuditLog.objects.filter(
                action="DELETE_GROUP",
                organization=self.organization
            ).exists()
        )

    # =========================================================
    # CROSS ORGANIZATION
    # =========================================================

    def test_admin_cannot_get_group_from_another_organization(
        self
    ):

        group = Group.objects.create(
            name="Other Group",
            description="Grupo da outra organização",
            organization=self.other_organization
        )

        response = self.client.get(
            f"/api/users/groups/{group.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND
        )

    # =========================================================
    # USER WITHOUT PERMISSION
    # =========================================================

    def test_user_without_group_permission_is_denied(self):

        self.authenticate(self.user)

        response = self.client.get(
            "/api/users/groups/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN
        )