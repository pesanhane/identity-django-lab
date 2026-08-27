from django.test import TestCase
from rest_framework.test import APIClient

from users.models import (
    User,
    Organization,
    Role,
    Permission,
)


class RolePermissionManagementTest(TestCase):

    def setUp(self):
        self.client = APIClient()

        self.password = "TestPassword123!"

        # ======================================================
        # ORGANIZATION
        # ======================================================

        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Organization for automated tests",
        )

        self.other_organization = Organization.objects.create(
            name="Other Organization",
            description="Second organization",
        )

        # ======================================================
        # PERMISSIONS
        # ======================================================

        self.permission_role_manage = Permission.objects.create(
            code="role.manage",
            description="Gerir roles",
        )

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

        self.permission_audit = Permission.objects.create(
            code="audit.view",
            description="Visualizar auditoria",
        )

        # ======================================================
        # ROLES
        # ======================================================

        self.admin_role = Role.objects.create(
            organization=self.organization,
            name="Administrator",
            description="Administrador",
        )

        self.viewer_role = Role.objects.create(
            organization=self.organization,
            name="Viewer",
            description="Visualização",
        )

        self.other_role = Role.objects.create(
            organization=self.other_organization,
            name="Other Administrator",
            description="Role de outra organização",
        )

        # ======================================================
        # ROLE PERMISSIONS
        # ======================================================

        self.admin_role.permissions.add(
            self.permission_role_manage,
            self.permission_user_view,
            self.permission_user_create,
            self.permission_user_update,
            self.permission_user_delete,
            self.permission_audit,
        )

        self.viewer_role.permissions.add(
            self.permission_user_view,
        )

        self.other_role.permissions.add(
            self.permission_role_manage,
        )

        # ======================================================
        # USERS
        # ======================================================

        self.admin_user = User.objects.create_user(
            username="admin_roles",
            email="admin_roles@example.com",
            password=self.password,
            organization=self.organization,
        )

        self.viewer_user = User.objects.create_user(
            username="viewer_roles",
            email="viewer_roles@example.com",
            password=self.password,
            organization=self.organization,
        )

        self.other_user = User.objects.create_user(
            username="other_roles",
            email="other_roles@example.com",
            password=self.password,
            organization=self.other_organization,
        )

        self.admin_user.roles.add(self.admin_role)
        self.viewer_user.roles.add(self.viewer_role)
        self.other_user.roles.add(self.other_role)

    # ==========================================================
    # AUTHENTICATION
    # ==========================================================

    def authenticate(self, user):
        self.client.force_authenticate(user=user)

    # ==========================================================
    # ROLES - LIST
    # ==========================================================

    def test_admin_can_list_roles(self):
        self.authenticate(self.admin_user)

        response = self.client.get(
            "/api/users/roles/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        names = {
            role["name"]
            for role in response.data
        }

        self.assertIn(
            "Administrator",
            names,
        )

        self.assertIn(
            "Viewer",
            names,
        )

        self.assertNotIn(
            "Other Administrator",
            names,
        )

    # ==========================================================
    # ROLES - CREATE
    # ==========================================================

    def test_admin_can_create_role(self):
        self.authenticate(self.admin_user)

        response = self.client.post(
            "/api/users/roles/",
            {
                "name": "Manager",
                "description": "Gestor",
                "permissions": [
                    self.permission_user_view.id,
                    self.permission_user_update.id,
                ],
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            201,
        )

        role = Role.objects.get(
            name="Manager",
            organization=self.organization,
        )

        self.assertEqual(
            role.organization,
            self.organization,
        )

        self.assertEqual(
            set(
                role.permissions.values_list(
                    "code",
                    flat=True,
                )
            ),
            {
                "user.view",
                "user.update",
            },
        )

    # ==========================================================
    # ROLES - GET DETAIL
    # ==========================================================

    def test_admin_can_get_role_detail(self):
        self.authenticate(self.admin_user)

        response = self.client.get(
            f"/api/users/roles/{self.admin_role.id}/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response.data["name"],
            "Administrator",
        )

    # ==========================================================
    # ROLES - UPDATE
    # ==========================================================

    def test_admin_can_update_role(self):
        self.authenticate(self.admin_user)

        response = self.client.patch(
            f"/api/users/roles/{self.admin_role.id}/",
            {
                "name": "Super Administrator",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.admin_role.refresh_from_db()

        self.assertEqual(
            self.admin_role.name,
            "Super Administrator",
        )

    # ==========================================================
    # ROLES - DELETE
    # ==========================================================

    def test_admin_can_delete_role(self):
        self.authenticate(self.admin_user)

        role_id = self.admin_role.id

        response = self.client.delete(
            f"/api/users/roles/{role_id}/"
        )

        self.assertEqual(
            response.status_code,
            204,
        )

        self.assertFalse(
            Role.objects.filter(
                id=role_id
            ).exists()
        )

    # ==========================================================
    # ROLE ISOLATION
    # ==========================================================

    def test_admin_cannot_access_role_from_other_organization(self):
        self.authenticate(self.admin_user)

        response = self.client.get(
            f"/api/users/roles/{self.other_role.id}/"
        )

        self.assertEqual(
            response.status_code,
            404,
        )

    # ==========================================================
    # VIEWER DENIED
    # ==========================================================

    def test_viewer_cannot_manage_roles(self):
        self.authenticate(self.viewer_user)

        response = self.client.get(
            "/api/users/roles/"
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    # ==========================================================
    # PERMISSIONS - LIST
    # ==========================================================

    def test_admin_can_list_permissions(self):
        self.authenticate(self.admin_user)

        response = self.client.get(
            "/api/users/permissions/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        codes = {
            permission["code"]
            for permission in response.data
        }

        self.assertIn(
            "user.view",
            codes,
        )

        self.assertIn(
            "role.manage",
            codes,
        )

    # ==========================================================
    # PERMISSIONS - CREATE
    # ==========================================================

    def test_admin_can_create_permission(self):
        self.authenticate(self.admin_user)

        response = self.client.post(
            "/api/users/permissions/",
            {
                "code": "user.activate",
                "description": "Ativar utilizadores",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            201,
        )

        self.assertTrue(
            Permission.objects.filter(
                code="user.activate"
            ).exists()
        )

    # ==========================================================
    # PERMISSIONS - GET DETAIL
    # ==========================================================

    def test_admin_can_get_permission_detail(self):
        self.authenticate(self.admin_user)

        response = self.client.get(
            f"/api/users/permissions/{self.permission_user_view.id}/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response.data["code"],
            "user.view",
        )

    # ==========================================================
    # PERMISSIONS - UPDATE
    # ==========================================================

    def test_admin_can_update_permission(self):
        self.authenticate(self.admin_user)

        response = self.client.patch(
            f"/api/users/permissions/{self.permission_user_view.id}/",
            {
                "description": "Visualizar todos os utilizadores",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.permission_user_view.refresh_from_db()

        self.assertEqual(
            self.permission_user_view.description,
            "Visualizar todos os utilizadores",
        )

    # ==========================================================
    # PERMISSIONS - DELETE
    # ==========================================================

    def test_admin_can_delete_permission(self):
        self.authenticate(self.admin_user)

        permission_id = self.permission_audit.id

        response = self.client.delete(
            f"/api/users/permissions/{permission_id}/"
        )

        self.assertEqual(
            response.status_code,
            204,
        )

        self.assertFalse(
            Permission.objects.filter(
                id=permission_id
            ).exists()
        )

    # ==========================================================
    # PERMISSIONS - VIEWER DENIED
    # ==========================================================

    def test_viewer_cannot_manage_permissions(self):
        self.authenticate(self.viewer_user)

        response = self.client.get(
            "/api/users/permissions/"
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    # ==========================================================
    # ROLE PERMISSIONS
    # ==========================================================

    def test_role_contains_expected_permissions(self):
        permissions = set(
            self.admin_role.permissions.values_list(
                "code",
                flat=True,
            )
        )

        self.assertIn(
            "user.view",
            permissions,
        )

        self.assertIn(
            "user.create",
            permissions,
        )

        self.assertIn(
            "role.manage",
            permissions,
        )

    # ==========================================================
    # ROLE ORGANIZATION ISOLATION
    # ==========================================================

    def test_role_permissions_are_not_cross_organization(self):
        self.assertEqual(
            self.admin_role.organization,
            self.organization,
        )

        self.assertEqual(
            self.other_role.organization,
            self.other_organization,
        )

        self.assertNotEqual(
            self.admin_role.organization,
            self.other_role.organization,
        )
