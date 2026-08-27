from django.test import TestCase
from rest_framework.test import APIClient

from users.models import (
    User,
    Organization,
    Group,
    Role,
    Permission,
)


class GroupManagementTest(TestCase):

    def setUp(self):

        self.client = APIClient()

        self.password = "StrongPass123!"

        self.organization_a = Organization.objects.create(
            name="Organization A",
            description="Organization A",
        )

        self.organization_b = Organization.objects.create(
            name="Organization B",
            description="Organization B",
        )

        self.permission_group_manage = Permission.objects.create(
            code="group.manage",
            description="Gerenciar grupos",
        )

        self.admin_role = Role.objects.create(
            name="Organization Admin",
            description="Administrador da organização",
            organization=self.organization_a,
        )

        self.admin_role.permissions.add(
            self.permission_group_manage
        )

        self.admin_user = User.objects.create_user(
            username="admin",
            email="admin@example.com",
            password=self.password,
            organization=self.organization_a,
            is_staff=True,
            is_superuser=True,
            is_verified=True,
        )

        self.admin_user.roles.add(
            self.admin_role
        )

        self.viewer_user = User.objects.create_user(
            username="viewer",
            email="viewer@example.com",
            password=self.password,
            organization=self.organization_a,
            is_verified=True,
        )

        self.group_a = Group.objects.create(
            name="Developers",
            description="Developers group",
            organization=self.organization_a,
        )

        self.group_other_org = Group.objects.create(
            name="Other Group",
            description="Other organization group",
            organization=self.organization_b,
        )
    # ==========================================================
    # LIST
    # ==========================================================

    def test_admin_can_list_groups(self):

        self.client.force_authenticate(
            user=self.admin_user
        )

        response = self.client.get(
            "/api/users/groups/"
        )

        self.assertEqual(
            response.status_code,
            200
        )

        names = [
            group["name"]
            for group in response.data
        ]

        self.assertIn(
            "Developers",
            names
        )

        self.assertNotIn(
            "Other Group",
            names
        )

    # ==========================================================
    # CREATE
    # ==========================================================

    def test_admin_can_create_group(self):

        self.client.force_authenticate(
            user=self.admin_user
        )

        response = self.client.post(
            "/api/users/groups/",
            {
                "name": "Managers",
                "description": "Managers group",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            201
        )

        self.assertTrue(
            Group.objects.filter(
                organization=self.organization_a,
                name="Managers",
            ).exists()
        )

    # ==========================================================
    # GET DETAIL
    # ==========================================================

    def test_admin_can_get_group_detail(self):

        self.client.force_authenticate(
            user=self.admin_user
        )

        response = self.client.get(
            f"/api/users/groups/{self.group_a.id}/"
        )

        self.assertEqual(
            response.status_code,
            200
        )

        self.assertEqual(
            response.data["name"],
            "Developers"
        )

    # ==========================================================
    # UPDATE
    # ==========================================================

    def test_admin_can_update_group(self):

        self.client.force_authenticate(
            user=self.admin_user
        )

        response = self.client.patch(
            f"/api/users/groups/{self.group_a.id}/",
            {
                "name": "Backend Developers",
                "description": "Updated description",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200
        )

        self.group_a.refresh_from_db()

        self.assertEqual(
            self.group_a.name,
            "Backend Developers"
        )

        self.assertEqual(
            self.group_a.description,
            "Updated description"
        )

    # ==========================================================
    # DELETE
    # ==========================================================

    def test_admin_can_delete_group(self):

        self.client.force_authenticate(
            user=self.admin_user
        )

        group_id = self.group_a.id

        response = self.client.delete(
            f"/api/users/groups/{group_id}/"
        )

        self.assertEqual(
            response.status_code,
            204
        )

        self.assertFalse(
            Group.objects.filter(
                id=group_id
            ).exists()
        )

    # ==========================================================
    # OTHER ORGANIZATION - GET
    # ==========================================================

    def test_admin_cannot_get_other_organization_group(self):

        self.client.force_authenticate(
            user=self.admin_user
        )

        response = self.client.get(
            f"/api/users/groups/{self.group_other_org.id}/"
        )

        self.assertEqual(
            response.status_code,
            404
        )

    # ==========================================================
    # OTHER ORGANIZATION - UPDATE
    # ==========================================================

    def test_admin_cannot_update_other_organization_group(self):

        self.client.force_authenticate(
            user=self.admin_user
        )

        response = self.client.patch(
            f"/api/users/groups/{self.group_other_org.id}/",
            {
                "name": "Hacked Group",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            404
        )

        self.group_other_org.refresh_from_db()

        self.assertEqual(
            self.group_other_org.name,
            "Other Group"
        )

    # ==========================================================
    # OTHER ORGANIZATION - DELETE
    # ==========================================================

    def test_admin_cannot_delete_other_organization_group(self):

        self.client.force_authenticate(
            user=self.admin_user
        )

        group_id = self.group_other_org.id

        response = self.client.delete(
            f"/api/users/groups/{group_id}/"
        )

        self.assertEqual(
            response.status_code,
            404
        )

        self.assertTrue(
            Group.objects.filter(
                id=group_id
            ).exists()
        )

    # ==========================================================
    # UNAUTHENTICATED
    # ==========================================================

    def test_unauthenticated_user_cannot_list_groups(self):

        response = self.client.get(
            "/api/users/groups/"
        )

        self.assertEqual(
            response.status_code,
            401
        )

    # ==========================================================
    # DUPLICATE GROUP
    # ==========================================================

    def test_cannot_create_duplicate_group_in_same_organization(self):

        self.client.force_authenticate(
            user=self.admin_user
        )

        response = self.client.post(
            "/api/users/groups/",
            {
                "name": "Developers",
                "description": "Another developers group",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            400
        )

    # ==========================================================
    # SAME NAME IN DIFFERENT ORGANIZATION
    # ==========================================================

    def test_same_group_name_allowed_in_different_organization(self):

        group = Group.objects.create(
            name="Developers",
            description="Developers of organization B",
            organization=self.organization_b,
        )

        self.assertTrue(
            Group.objects.filter(
                organization=self.organization_b,
                name="Developers",
            ).exists()
        )

        self.assertEqual(
            group.organization,
            self.organization_b
        )

    # ==========================================================
    # VIEWER CANNOT LIST
    # ==========================================================

    def test_viewer_cannot_list_groups(self):

        self.client.force_authenticate(
            user=self.viewer_user
        )

        response = self.client.get(
            "/api/users/groups/"
        )

        self.assertEqual(
            response.status_code,
            403
        )

    # ==========================================================
    # VIEWER CANNOT CREATE
    # ==========================================================

    def test_viewer_cannot_create_group(self):

        self.client.force_authenticate(
            user=self.viewer_user
        )

        response = self.client.post(
            "/api/users/groups/",
            {
                "name": "Unauthorized Group",
                "description": "Should not be created",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            403
        )

    # ==========================================================
    # ORGANIZATION IS AUTOMATICALLY ASSIGNED
    # ==========================================================

    def test_created_group_belongs_to_authenticated_user_organization(self):

        self.client.force_authenticate(
            user=self.admin_user
        )

        response = self.client.post(
            "/api/users/groups/",
            {
                "name": "Security",
                "description": "Security group",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            201
        )

        group = Group.objects.get(
            name="Security"
        )

        self.assertEqual(
            group.organization,
            self.organization_a
        )
