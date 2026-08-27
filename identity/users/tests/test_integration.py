from django.test import TestCase

from rest_framework.test import APIClient

from users.models import (
    User,
    Organization,
    Role,
    Permission,
    AuditLog,
)


class IdentityIntegrationTest(TestCase):

    def setUp(self):
        self.client = APIClient()

        self.password = "TestPassword123!"

        self.organization = Organization.objects.create(
            name="Integration Organization",
            description="Organization for integration tests",
        )

        self.user = User.objects.create_user(
            username="integration_user",
            email="integration@example.com",
            password=self.password,
            organization=self.organization,
        )

        self.target_user = User.objects.create_user(
            username="target_user",
            email="target@example.com",
            password=self.password,
            organization=self.organization,
        )

        self.other_organization = Organization.objects.create(
            name="Other Organization",
            description="Other organization",
        )

        self.other_user = User.objects.create_user(
            username="other_user",
            email="other@example.com",
            password=self.password,
            organization=self.other_organization,
        )

        # ------------------------------------------------------
        # PERMISSÕES
        # ------------------------------------------------------

        self.permission_user_view = Permission.objects.create(
            code="user.view",
            description="Visualizar utilizadores",
        )

        self.permission_user_create = Permission.objects.create(
            code="user.create",
            description="Criar utilizadores",
        )

        self.permission_user_update = Permission.objects.create(
            code="user.update",
            description="Atualizar utilizadores",
        )

        self.permission_user_delete = Permission.objects.create(
            code="user.delete",
            description="Eliminar utilizadores",
        )

        self.permission_audit_view = Permission.objects.create(
            code="audit.view",
            description="Visualizar auditoria",
        )

        # ------------------------------------------------------
        # ROLE ADMIN
        # ------------------------------------------------------

        self.admin_role = Role.objects.create(
            organization=self.organization,
            name="Integration Administrator",
            description="Administrador para testes de integração",
        )

        self.admin_role.permissions.add(
            self.permission_user_view,
            self.permission_user_create,
            self.permission_user_update,
            self.permission_user_delete,
            self.permission_audit_view,
        )

        self.user.roles.add(self.admin_role)

    # ==========================================================
    # AUTHENTICATION + CURRENT USER
    # ==========================================================

    def test_authenticated_user_can_access_me(self):

        response = self.client.post(
            "/api/token/",
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        access = response.data["access"]

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {access}"
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response.data["username"],
            self.user.username,
        )

    # ==========================================================
    # LIST USERS
    # ==========================================================

    def test_admin_can_list_users(self):

        self.client.force_authenticate(
            user=self.user
        )

        response = self.client.get(
            "/api/users/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        usernames = [
            user["username"]
            for user in response.data
        ]

        self.assertIn(
            self.user.username,
            usernames,
        )

        self.assertIn(
            self.target_user.username,
            usernames,
        )

        self.assertNotIn(
            self.other_user.username,
            usernames,
        )

    # ==========================================================
    # CREATE USER
    # ==========================================================

    def test_admin_can_create_user(self):

        self.client.force_authenticate(
            user=self.user
        )

        response = self.client.post(
            "/api/users/",
            {
                "username": "created_user",
                "email": "created@example.com",
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            201,
        )

        self.assertTrue(
            User.objects.filter(
                username="created_user",
                organization=self.organization,
            ).exists()
        )

    # ==========================================================
    # UPDATE USER
    # ==========================================================

    def test_admin_can_update_user(self):

        self.client.force_authenticate(
            user=self.user
        )

        response = self.client.patch(
            f"/api/users/{self.target_user.id}/",
            {
                "email": "updated@example.com",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.target_user.refresh_from_db()

        self.assertEqual(
            self.target_user.email,
            "updated@example.com",
        )

    # ==========================================================
    # DELETE USER
    # ==========================================================

    def test_admin_can_delete_user(self):

        self.client.force_authenticate(
            user=self.user
        )

        target_id = self.target_user.id

        response = self.client.delete(
            f"/api/users/{target_id}/"
        )

        self.assertEqual(
            response.status_code,
            204,
        )

        self.assertFalse(
            User.objects.filter(
                id=target_id
            ).exists()
        )

    # ==========================================================
    # AUDIT LOG
    # ==========================================================

    def test_admin_can_access_audit_logs(self):

        self.client.force_authenticate(
            user=self.user
        )

        AuditLog.objects.create(
            user=self.user,
            organization=self.organization,
            action="CREATE_USER",
            description="Teste de auditoria",
        )

        response = self.client.get(
            "/api/users/audit/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        actions = [
            log["action"]
            for log in response.data
        ]

        self.assertIn(
            "CREATE_USER",
            actions,
        )

    # ==========================================================
    # UNAUTHENTICATED ACCESS
    # ==========================================================

    def test_unauthenticated_user_cannot_access_me(self):

        self.client.credentials()

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            401,
        )

    # ==========================================================
    # UNAUTHENTICATED USER LIST
    # ==========================================================

    def test_unauthenticated_user_cannot_list_users(self):

        self.client.credentials()

        response = self.client.get(
            "/api/users/"
        )

        self.assertEqual(
            response.status_code,
            401,
        )

    # ==========================================================
    # CROSS ORGANIZATION ISOLATION
    # ==========================================================

    def test_user_cannot_access_other_organization_user(self):

        self.client.force_authenticate(
            user=self.user
        )

        response = self.client.get(
            f"/api/users/{self.other_user.id}/"
        )

        self.assertEqual(
            response.status_code,
            404,
        )

    # ==========================================================
    # CROSS ORGANIZATION UPDATE
    # ==========================================================

    def test_user_cannot_update_other_organization_user(self):

        self.client.force_authenticate(
            user=self.user
        )

        response = self.client.patch(
            f"/api/users/{self.other_user.id}/",
            {
                "email": "hacked@example.com",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            404,
        )

        self.other_user.refresh_from_db()

        self.assertEqual(
            self.other_user.email,
            "other@example.com",
        )

    # ==========================================================
    # CROSS ORGANIZATION DELETE
    # ==========================================================

    def test_user_cannot_delete_other_organization_user(self):

        self.client.force_authenticate(
            user=self.user
        )

        target_id = self.other_user.id

        response = self.client.delete(
            f"/api/users/{target_id}/"
        )

        self.assertEqual(
            response.status_code,
            404,
        )

        self.assertTrue(
            User.objects.filter(
                id=target_id
            ).exists()
        )

    # ==========================================================
    # LOGOUT + REFRESH TOKEN
    # ==========================================================

    def test_logout_invalidates_refresh_token(self):

        login_response = self.client.post(
            "/api/token/",
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            login_response.status_code,
            200,
        )

        access = login_response.data["access"]
        refresh = login_response.data["refresh"]

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {access}"
        )

        logout_response = self.client.post(
            "/api/users/logout/",
            {
                "refresh": refresh,
            },
            format="json",
        )

        self.assertEqual(
            logout_response.status_code,
            200,
        )

        refresh_response = self.client.post(
            "/api/token/refresh/",
            {
                "refresh": refresh,
            },
            format="json",
        )

        self.assertNotEqual(
            refresh_response.status_code,
            200,
        )
