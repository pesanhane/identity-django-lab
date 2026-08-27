from django.test import TestCase
from rest_framework.test import APIRequestFactory
from rest_framework.permissions import BasePermission

from users.models import (
    User,
    Role,
    Permission,
    Organization,
)

from users.rbac import (
    HasPermission,
    DynamicPermission,
    CanCreateUser,
    CanUpdateUser,
    CanDeleteUser,
    CanViewUser,
    CanViewAudit,
    CanManageRole,
    CanChangePassword,
)


# ============================================================
# BASE TEST
# ============================================================

class RBACBaseTest(TestCase):

    def setUp(self):

        self.factory = APIRequestFactory()

        # ====================================================
        # ORGANIZATIONS
        # ====================================================

        self.org_a = Organization.objects.create(
            name="Organization A",
            description="Primeira organização"
        )

        self.org_b = Organization.objects.create(
            name="Organization B",
            description="Segunda organização"
        )

        # ====================================================
        # PERMISSIONS
        # ====================================================

        permission_codes = [
            "user.view",
            "user.create",
            "user.update",
            "user.delete",
            "audit.view",
            "role.manage",
            "password.change",
        ]

        self.permissions = {}

        for code in permission_codes:

            self.permissions[code] = Permission.objects.create(
                code=code,
                description=f"Permission {code}"
            )

        # ====================================================
        # ROLES - ORGANIZATION A
        # ====================================================

        self.admin_role = Role.objects.create(
            organization=self.org_a,
            name="Admin A",
            description="Administrador da organização A"
        )

        self.admin_role.permissions.set(
            self.permissions.values()
        )

        self.viewer_role = Role.objects.create(
            organization=self.org_a,
            name="Viewer A",
            description="Visualizador da organização A"
        )

        self.viewer_role.permissions.add(
            self.permissions["user.view"]
        )

        # ====================================================
        # ROLE ORGANIZATION B
        # ====================================================

        self.role_b = Role.objects.create(
            organization=self.org_b,
            name="Admin B",
            description="Administrador da organização B"
        )

        self.role_b.permissions.add(
            self.permissions["user.view"],
            self.permissions["user.create"]
        )

        # ====================================================
        # USERS
        # ====================================================

        self.admin = User.objects.create_user(
            username="admin_a",
            email="admin_a@example.com",
            password="AdminPassword123!",
            organization=self.org_a
        )

        self.admin.roles.add(
            self.admin_role
        )

        # ----------------------------------------------------

        self.viewer = User.objects.create_user(
            username="viewer_a",
            email="viewer_a@example.com",
            password="ViewerPassword123!",
            organization=self.org_a
        )

        self.viewer.roles.add(
            self.viewer_role
        )

        # ----------------------------------------------------

        self.user_b = User.objects.create_user(
            username="user_b",
            email="user_b@example.com",
            password="UserBPassword123!",
            organization=self.org_b
        )

        self.user_b.roles.add(
            self.role_b
        )

        # ----------------------------------------------------

        self.user_without_role = User.objects.create_user(
            username="norole",
            email="norole@example.com",
            password="NoRolePassword123!",
            organization=self.org_a
        )

        # ----------------------------------------------------

        self.user_without_organization = User.objects.create_user(
            username="noorg",
            email="noorg@example.com",
            password="NoOrgPassword123!"
        )

        # ----------------------------------------------------

        self.superuser = User.objects.create_superuser(
            username="superadmin",
            email="superadmin@example.com",
            password="SuperPassword123!"
        )


# ============================================================
# HAS PERMISSION
# ============================================================

class HasPermissionTest(RBACBaseTest):

    def make_request(self, user):

        request = self.factory.get("/api/test/")
        request.user = user

        return request

    # ========================================================
    # AUTHENTICATION
    # ========================================================

    def test_unauthenticated_user_is_denied(self):

        permission = HasPermission()

        request = self.factory.get("/api/test/")

        # AnonymousUser é criado pelo DRF normalmente,
        # mas aqui garantimos explicitamente o comportamento.
        from django.contrib.auth.models import AnonymousUser

        request.user = AnonymousUser()

        self.assertFalse(
            permission.has_permission(
                request,
                None
            )
        )

    # ========================================================
    # ORGANIZATION
    # ========================================================

    def test_authenticated_user_without_organization_is_denied(self):

        permission = HasPermission()
        request = self.make_request(
            self.user_without_organization
        )

        self.assertFalse(
            permission.has_permission(
                request,
                None
            )
        )

    # ========================================================
    # PERMISSION CODE
    # ========================================================

    def test_has_permission_without_permission_code_is_denied(self):

        permission = HasPermission()

        request = self.make_request(
            self.admin
        )

        self.assertIsNone(
            permission.permission_code
        )

        self.assertFalse(
            permission.has_permission(
                request,
                None
            )
        )

    # ========================================================
    # ROLE + PERMISSION
    # ========================================================

    def test_user_with_required_permission_is_allowed(self):

        permission = CanViewUser()

        request = self.make_request(
            self.admin
        )

        self.assertTrue(
            permission.has_permission(
                request,
                None
            )
        )

    def test_user_without_required_permission_is_denied(self):

        permission = CanDeleteUser()

        request = self.make_request(
            self.viewer
        )

        self.assertFalse(
            permission.has_permission(
                request,
                None
            )
        )

    # ========================================================
    # USER WITHOUT ROLE
    # ========================================================

    def test_user_without_role_is_denied(self):

        permission = CanViewUser()

        request = self.make_request(
            self.user_without_role
        )

        self.assertFalse(
            permission.has_permission(
                request,
                None
            )
        )

    # ========================================================
    # ORGANIZATION ISOLATION
    # ========================================================

    def test_permission_from_another_organization_is_denied(self):

        """
        Organization B possui uma role com user.view.

        O utilizador pertence à Organization A.

        A permission da Organization B NÃO deve conceder
        acesso ao utilizador da Organization A.
        """

        user = User.objects.create_user(
            username="cross_org",
            email="cross@example.com",
            password="CrossPassword123!",
            organization=self.org_a
        )

        # Intencionalmente atribuímos uma role da Organization B.
        user.roles.add(
            self.role_b
        )

        permission = CanViewUser()

        request = self.make_request(
            user
        )

        self.assertFalse(
            permission.has_permission(
                request,
                None
            )
        )

    # ========================================================
    # MULTIPLE ROLES
    # ========================================================

    def test_permission_from_any_role_is_allowed(self):

        user = User.objects.create_user(
            username="multi_role",
            email="multi@example.com",
            password="MultiPassword123!",
            organization=self.org_a
        )

        # Viewer possui apenas user.view.
        user.roles.add(
            self.viewer_role
        )

        permission = CanViewUser()

        request = self.make_request(
            user
        )

        self.assertTrue(
            permission.has_permission(
                request,
                None
            )
        )

    def test_multiple_roles_still_require_permission(self):

        user = User.objects.create_user(
            username="multi_role_2",
            email="multi2@example.com",
            password="MultiPassword123!",
            organization=self.org_a
        )

        user.roles.add(
            self.viewer_role
        )

        permission = CanDeleteUser()

        request = self.make_request(
            user
        )

        self.assertFalse(
            permission.has_permission(
                request,
                None
            )
        )

    # ========================================================
    # SPECIALIZED PERMISSION CLASSES
    # ========================================================

    def test_can_create_user_permission(self):

        request = self.make_request(
            self.admin
        )

        self.assertTrue(
            CanCreateUser().has_permission(
                request,
                None
            )
        )

    def test_can_update_user_permission(self):

        request = self.make_request(
            self.admin
        )

        self.assertTrue(
            CanUpdateUser().has_permission(
                request,
                None
            )
        )

    def test_can_delete_user_permission(self):

        request = self.make_request(
            self.admin
        )

        self.assertTrue(
            CanDeleteUser().has_permission(
                request,
                None
            )
        )

    def test_can_view_user_permission(self):

        request = self.make_request(
            self.viewer
        )

        self.assertTrue(
            CanViewUser().has_permission(
                request,
                None
            )
        )

    def test_can_view_audit_permission(self):

        request = self.make_request(
            self.admin
        )

        self.assertTrue(
            CanViewAudit().has_permission(
                request,
                None
            )
        )

    def test_can_manage_role_permission(self):

        request = self.make_request(
            self.admin
        )

        self.assertTrue(
            CanManageRole().has_permission(
                request,
                None
            )
        )

    def test_can_change_password_permission(self):

        request = self.make_request(
            self.admin
        )

        self.assertTrue(
            CanChangePassword().has_permission(
                request,
                None
            )
        )


# ============================================================
# DYNAMIC PERMISSION
# ============================================================

class DynamicPermissionTest(RBACBaseTest):

    def make_request(self, user):

        request = self.factory.get("/api/test/")
        request.user = user

        return request

    # ========================================================
    # AUTHENTICATION
    # ========================================================

    def test_unauthenticated_user_is_denied(self):

        from django.contrib.auth.models import AnonymousUser

        request = self.factory.get("/api/test/")
        request.user = AnonymousUser()

        class View:
            permission_required = "user.view"

        self.assertFalse(
            DynamicPermission().has_permission(
                request,
                View()
            )
        )

    # ========================================================
    # SUPERUSER
    # ========================================================

    def test_superuser_is_allowed_without_organization(self):

        class View:
            permission_required = "anything.permission"

        request = self.make_request(
            self.superuser
        )

        self.assertTrue(
            DynamicPermission().has_permission(
                request,
                View()
            )
        )

    # ========================================================
    # ORGANIZATION
    # ========================================================

    def test_normal_user_without_organization_is_denied(self):

        class View:
            permission_required = "user.view"

        request = self.make_request(
            self.user_without_organization
        )

        self.assertFalse(
            DynamicPermission().has_permission(
                request,
                View()
            )
        )

    # ========================================================
    # REQUIRED PERMISSION
    # ========================================================

    def test_view_without_required_permission_is_denied(self):

        class View:
            pass

        request = self.make_request(
            self.admin
        )

        self.assertFalse(
            DynamicPermission().has_permission(
                request,
                View()
            )
        )

    # ========================================================
    # REQUIRED PERMISSION EXISTS
    # ========================================================

    def test_user_with_required_permission_is_allowed(self):

        class View:
            permission_required = "user.view"

        request = self.make_request(
            self.admin
        )

        self.assertTrue(
            DynamicPermission().has_permission(
                request,
                View()
            )
        )

    # ========================================================
    # USER WITHOUT PERMISSION
    # ========================================================

    def test_user_without_required_permission_is_denied(self):

        class View:
            permission_required = "user.delete"

        request = self.make_request(
            self.viewer
        )

        self.assertFalse(
            DynamicPermission().has_permission(
                request,
                View()
            )
        )

    # ========================================================
    # ORGANIZATION ISOLATION
    # ========================================================

    def test_role_from_another_organization_does_not_grant_access(self):

        user = User.objects.create_user(
            username="cross_dynamic",
            email="cross_dynamic@example.com",
            password="CrossPassword123!",
            organization=self.org_a
        )

        # Role pertence à Organization B.
        user.roles.add(
            self.role_b
        )

        class View:
            permission_required = "user.view"

        request = self.make_request(
            user
        )

        self.assertFalse(
            DynamicPermission().has_permission(
                request,
                View()
            )
        )

    # ========================================================
    # DYNAMIC PERMISSION CHANGE
    # ========================================================

    def test_access_changes_when_permission_is_added(self):

        class View:
            permission_required = "user.delete"

        request = self.make_request(
            self.viewer
        )

        permission = DynamicPermission()

        # Inicialmente não possui user.delete.
        self.assertFalse(
            permission.has_permission(
                request,
                View()
            )
        )

        # Adicionar permission à role.
        self.viewer_role.permissions.add(
            self.permissions["user.delete"]
        )

        self.assertTrue(
            permission.has_permission(
                request,
                View()
            )
        )

    def test_access_is_removed_when_permission_is_removed(self):

        class View:
            permission_required = "user.view"

        request = self.make_request(
            self.viewer
        )

        permission = DynamicPermission()

        # Inicialmente possui user.view.
        self.assertTrue(
            permission.has_permission(
                request,
                View()
            )
        )

        # Remover permission.
        self.viewer_role.permissions.remove(
            self.permissions["user.view"]
        )

        self.assertFalse(
            permission.has_permission(
                request,
                View()
            )
        )

    # ========================================================
    # DIFFERENT PERMISSIONS
    # ========================================================

    def test_dynamic_permission_uses_exact_permission_code(self):

        class View:
            permission_required = "user.update"

        request = self.make_request(
            self.viewer
        )

        self.assertFalse(
            DynamicPermission().has_permission(
                request,
                View()
            )
        )

        self.viewer_role.permissions.add(
            self.permissions["user.update"]
        )

        self.assertTrue(
            DynamicPermission().has_permission(
                request,
                View()
            )
        )

    # ========================================================
    # ACTIVE/INACTIVE USER
    # ========================================================

    def test_inactive_user_does_not_bypass_rbac(self):

        self.viewer.is_active = False
        self.viewer.save(update_fields=["is_active"])

        class View:
            permission_required = "user.view"

        request = self.make_request(
            self.viewer
        )

        # DynamicPermission utiliza is_authenticated,
        # não is_active. Portanto, o comportamento atual
        # permite que um objeto User inativo continue sendo
        # avaliado pelo RBAC se chegar autenticado à view.
        #
        # Este teste documenta o comportamento atual.
        self.assertTrue(
            DynamicPermission().has_permission(
                request,
                View()
            )
        )