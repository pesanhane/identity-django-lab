from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory
from rest_framework.exceptions import ValidationError

from users.models import (
    Organization,
    Role,
    Permission,
    Group,
)

from users.serializers import (
    UserSerializer,
    UserUpdateSerializer,
    AdminUserUpdateSerializer,
    ChangePasswordSerializer,
    LogoutSerializer,
    PermissionSerializer,
    RoleSerializer,
    RoleCreateSerializer,
    GroupSerializer,
    GroupCreateSerializer,
)


User = get_user_model()


# ============================================================
# BASE
# ============================================================

class SerializerTestBase(TestCase):

    def setUp(self):

        self.factory = APIRequestFactory()

        # ----------------------------------------------------
        # ORGANIZATIONS
        # ----------------------------------------------------

        self.organization = Organization.objects.create(
            name="Organization A",
            description="Primary organization"
        )

        self.organization_b = Organization.objects.create(
            name="Organization B",
            description="Secondary organization"
        )

        # ----------------------------------------------------
        # PERMISSIONS
        # ----------------------------------------------------

        self.permission_view = Permission.objects.create(
            code="user.view",
            description="View users"
        )

        self.permission_create = Permission.objects.create(
            code="user.create",
            description="Create users"
        )

        self.permission_update = Permission.objects.create(
            code="user.update",
            description="Update users"
        )

        # ----------------------------------------------------
        # ROLES
        # ----------------------------------------------------

        self.admin_role = Role.objects.create(
            organization=self.organization,
            name="Admin",
            description="Administrator"
        )

        self.admin_role.permissions.add(
            self.permission_view,
            self.permission_create,
            self.permission_update
        )

        self.user_role = Role.objects.create(
            organization=self.organization,
            name="User",
            description="Normal user"
        )

        self.other_org_role = Role.objects.create(
            organization=self.organization_b,
            name="Admin",
            description="Administrator from another organization"
        )

        self.other_org_role.permissions.add(
            self.permission_view
        )

        # ----------------------------------------------------
        # USERS
        # ----------------------------------------------------

        self.admin = User.objects.create_user(
            username="admin",
            email="admin@example.com",
            password="AdminPassword123!",
            organization=self.organization
        )

        self.admin.roles.add(
            self.admin_role
        )

        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPassword123!",
            organization=self.organization
        )

        self.user.roles.add(
            self.user_role
        )

        self.other_org_user = User.objects.create_user(
            username="otheruser",
            email="other@example.com",
            password="OtherPassword123!",
            organization=self.organization_b
        )

    # --------------------------------------------------------
    # REQUEST
    # --------------------------------------------------------

    def get_request(self, user):

        request = self.factory.get(
            "/api/users/"
        )

        request.user = user

        return request


# ============================================================
# USER SERIALIZER
# ============================================================

class UserSerializerTest(SerializerTestBase):

    def test_create_user_successfully(self):

        data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "NewPassword123!",
            "first_name": "New",
            "last_name": "User",
            "phone_number": "841234567",
        }

        serializer = UserSerializer(
            data=data,
            context={
                "request": self.get_request(self.admin)
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        user = serializer.save(
            organization=self.organization
        )

        self.assertEqual(
            user.username,
            "newuser"
        )

        self.assertEqual(
            user.organization,
            self.organization
        )

        self.assertTrue(
            user.check_password(
                "NewPassword123!"
            )
        )

    def test_create_user_with_role_from_same_organization(self):

        data = {
            "username": "roleuser",
            "email": "roleuser@example.com",
            "password": "RolePassword123!",
            "roles": [self.user_role.id],
        }

        serializer = UserSerializer(
            data=data,
            context={
                "request": self.get_request(self.admin)
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        user = serializer.save(
            organization=self.organization
        )

        self.assertTrue(
            user.roles.filter(
                id=self.user_role.id
            ).exists()
        )

    def test_create_user_without_roles(self):

        data = {
            "username": "noroleuser",
            "email": "norole@example.com",
            "password": "NoRolePassword123!",
        }

        serializer = UserSerializer(
            data=data,
            context={
                "request": self.get_request(self.admin)
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        user = serializer.save(
            organization=self.organization
        )

        self.assertEqual(
            user.roles.count(),
            0
        )

    def test_created_at_is_read_only(self):

        serializer = UserSerializer(
            context={
                "request": self.get_request(self.admin)
            }
        )

        self.assertTrue(
            serializer.fields["created_at"].read_only
        )

    def test_organization_field_is_read_only(self):

        serializer = UserSerializer(
            context={
                "request": self.get_request(self.admin)
            }
        )

        self.assertTrue(
            serializer.fields["organization"].read_only
        )

    def test_organization_is_read_only(self):

        data = {
            "username": "orgtest",
            "email": "orgtest@example.com",
            "password": "OrgPassword123!",
            "organization": self.organization_b.id,
        }

        serializer = UserSerializer(
            data=data,
            context={
                "request": self.get_request(self.admin)
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        user = serializer.save(
            organization=self.organization
        )

        self.assertEqual(
            user.organization,
            self.organization
        )

    def test_password_is_hashed(self):

        raw_password = "Password123!"

        data = {
            "username": "hasheduser",
            "email": "hashed@example.com",
            "password": raw_password,
        }

        serializer = UserSerializer(
            data=data,
            context={
                "request": self.get_request(self.admin)
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        user = serializer.save(
            organization=self.organization
        )

        self.assertNotEqual(
            user.password,
            raw_password
        )

        self.assertTrue(
            user.check_password(raw_password)
        )

    def test_role_queryset_is_limited_to_current_organization(self):

        request = self.get_request(
            self.admin
        )

        serializer = UserSerializer(
            context={
                "request": request
            }
        )

        role_queryset = serializer.fields[
            "roles"
        ].queryset

        role_ids = list(
            role_queryset.values_list(
                "id",
                flat=True
            )
        )

        # Role da organização atual deve aparecer
        self.assertIn(
            self.admin_role.id,
            role_ids
        )

        # Role da outra organização NÃO pode aparecer
        self.assertNotIn(
            self.other_org_role.id,
            role_ids
        )


# ============================================================
# USER UPDATE SERIALIZER
# ============================================================

class UserUpdateSerializerTest(
    SerializerTestBase
):

    def test_update_basic_user_information(self):

        serializer = UserUpdateSerializer(
            self.user,
            data={
                "first_name": "Updated",
                "last_name": "User",
                "phone_number": "821234567",
            },
            partial=True
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        user = serializer.save()

        self.assertEqual(
            user.first_name,
            "Updated"
        )

        self.assertEqual(
            user.last_name,
            "User"
        )

        self.assertEqual(
            user.phone_number,
            "821234567"
        )

    def test_user_update_serializer_does_not_expose_organization(
        self
    ):

        serializer = UserUpdateSerializer(
            self.user
        )

        self.assertNotIn(
            "organization",
            serializer.fields
        )

    def test_user_update_serializer_does_not_expose_roles(
        self
    ):

        serializer = UserUpdateSerializer(
            self.user
        )

        self.assertNotIn(
            "roles",
            serializer.fields
        )


# ============================================================
# ADMIN USER UPDATE SERIALIZER
# ============================================================

class AdminUserUpdateSerializerTest(
    SerializerTestBase
):

    def test_update_user_successfully(self):

        request = self.get_request(
            self.admin
        )

        serializer = AdminUserUpdateSerializer(
            self.user,
            data={
                "first_name": "Updated",
                "last_name": "Administrator",
                "phone_number": "841111111",
            },
            partial=True,
            context={
                "request": request
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        user = serializer.save()

        self.assertEqual(
            user.first_name,
            "Updated"
        )

        self.assertEqual(
            user.last_name,
            "Administrator"
        )

        self.assertEqual(
            user.phone_number,
            "841111111"
        )

    def test_update_user_roles_from_same_organization(
        self
    ):

        request = self.get_request(
            self.admin
        )

        serializer = AdminUserUpdateSerializer(
            self.user,
            data={
                "roles": [
                    self.admin_role.id
                ]
            },
            partial=True,
            context={
                "request": request
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        user = serializer.save()

        self.assertTrue(
            user.roles.filter(
                id=self.admin_role.id
            ).exists()
        )

    def test_cannot_assign_role_from_another_organization(
        self
    ):

        request = self.get_request(
            self.admin
        )

        serializer = AdminUserUpdateSerializer(
            self.user,
            data={
                "roles": [
                    self.other_org_role.id
                ]
            },
            partial=True,
            context={
                "request": request
            }
        )

        self.assertFalse(
            serializer.is_valid()
        )

        self.assertIn(
            "roles",
            serializer.errors
        )

    def test_roles_queryset_is_limited_to_current_organization(
        self
    ):

        request = self.get_request(
            self.admin
        )

        serializer = AdminUserUpdateSerializer(
            self.user,
            context={
                "request": request
            }
        )

        role_queryset = serializer.fields[
            "roles"
        ].queryset

        role_ids = list(
            role_queryset.values_list(
                "id",
                flat=True
            )
        )

        self.assertIn(
            self.admin_role.id,
            role_ids
        )

        self.assertNotIn(
            self.other_org_role.id,
            role_ids
        )

    def test_update_is_verified(self):

        request = self.get_request(
            self.admin
        )

        serializer = AdminUserUpdateSerializer(
            self.user,
            data={
                "is_verified": True
            },
            partial=True,
            context={
                "request": request
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        user = serializer.save()

        self.assertTrue(
            user.is_verified
        )

    def test_update_without_request_is_rejected_when_roles_are_validated(
        self
    ):

        serializer = AdminUserUpdateSerializer(
            self.user,
            data={
                "roles": [
                    self.admin_role.id
                ]
            },
            partial=True
        )

        self.assertFalse(
            serializer.is_valid()
        )

        self.assertIn(
            "roles",
            serializer.errors
        )


# ============================================================
# CHANGE PASSWORD
# ============================================================

class ChangePasswordSerializerTest(
    TestCase
):

    def test_valid_password_change_data(self):

        serializer = ChangePasswordSerializer(
            data={
                "old_password": "OldPassword123!",
                "new_password": "NewPassword456!",
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

    def test_old_password_is_required(self):

        serializer = ChangePasswordSerializer(
            data={
                "new_password": "NewPassword456!"
            }
        )

        self.assertFalse(
            serializer.is_valid()
        )

        self.assertIn(
            "old_password",
            serializer.errors
        )

    def test_new_password_is_required(self):

        serializer = ChangePasswordSerializer(
            data={
                "old_password": "OldPassword123!"
            }
        )

        self.assertFalse(
            serializer.is_valid()
        )

        self.assertIn(
            "new_password",
            serializer.errors
        )

    def test_new_password_cannot_equal_old_password(
        self
    ):

        serializer = ChangePasswordSerializer(
            data={
                "old_password": "SamePassword123!",
                "new_password": "SamePassword123!",
            }
        )

        self.assertFalse(
            serializer.is_valid()
        )

        self.assertIn(
            "new_password",
            serializer.errors
        )

    def test_weak_password_is_rejected(self):

        serializer = ChangePasswordSerializer(
            data={
                "old_password": "OldPassword123!",
                "new_password": "123"
            }
        )

        self.assertFalse(
            serializer.is_valid()
        )

        self.assertIn(
            "new_password",
            serializer.errors
        )


# ============================================================
# LOGOUT
# ============================================================

class LogoutSerializerTest(
    TestCase
):

    def test_refresh_token_is_required(self):

        serializer = LogoutSerializer(
            data={}
        )

        self.assertFalse(
            serializer.is_valid()
        )

        self.assertIn(
            "refresh",
            serializer.errors
        )

    def test_refresh_token_is_accepted(self):

        serializer = LogoutSerializer(
            data={
                "refresh": "fake-refresh-token"
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        self.assertEqual(
            serializer.validated_data["refresh"],
            "fake-refresh-token"
        )


# ============================================================
# PERMISSION SERIALIZER
# ============================================================

class PermissionSerializerTest(
    TestCase
):

    def test_serialize_permission(self):

        permission = Permission.objects.create(
            code="user.view",
            description="View users"
        )

        serializer = PermissionSerializer(
            permission
        )

        self.assertEqual(
            serializer.data["code"],
            "user.view"
        )

        self.assertEqual(
            serializer.data["description"],
            "View users"
        )

        self.assertEqual(
            serializer.data["id"],
            permission.id
        )

    def test_create_permission(self):

        serializer = PermissionSerializer(
            data={
                "code": "user.create",
                "description": "Create users"
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        permission = serializer.save()

        self.assertEqual(
            permission.code,
            "user.create"
        )

    def test_permission_code_is_required(self):

        serializer = PermissionSerializer(
            data={
                "description": "Permission without code"
            }
        )

        self.assertFalse(
            serializer.is_valid()
        )

        self.assertIn(
            "code",
            serializer.errors
        )


# ============================================================
# ROLE SERIALIZER
# ============================================================

class RoleSerializerTest(
    SerializerTestBase
):

    def test_serialize_role(self):

        self.admin_role.permissions.add(
            self.permission_view
        )

        serializer = RoleSerializer(
            self.admin_role
        )

        self.assertEqual(
            serializer.data["name"],
            "Admin"
        )

        self.assertEqual(
            serializer.data["organization"],
            self.organization.id
        )

        self.assertEqual(
            len(serializer.data["permissions"]),
            self.admin_role.permissions.count()
        )

    def test_role_id_is_read_only(self):

        serializer = RoleSerializer(
            self.admin_role
        )

        self.assertTrue(
            serializer.fields["id"].read_only
        )

    def test_role_organization_is_read_only(self):

        serializer = RoleSerializer(
            self.admin_role
        )

        self.assertTrue(
            serializer.fields["organization"].read_only
        )


# ============================================================
# ROLE CREATE / UPDATE SERIALIZER
# ============================================================

class RoleCreateSerializerTest(
    SerializerTestBase
):

    def test_create_role_successfully(self):

        data = {
            "name": "Manager",
            "description": "System manager",
            "permissions": [
                self.permission_view.id
            ],
        }

        serializer = RoleCreateSerializer(
            data=data,
            context={
                "organization": self.organization
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        role = serializer.save(
            organization=self.organization
        )

        self.assertEqual(
            role.name,
            "Manager"
        )

        self.assertEqual(
            role.organization,
            self.organization
        )

        self.assertTrue(
            role.permissions.filter(
                id=self.permission_view.id
            ).exists()
        )

    def test_duplicate_role_name_in_same_organization_is_rejected(
        self
    ):

        data = {
            "name": self.admin_role.name,
            "description": "Duplicate role",
            "permissions": [
                self.permission_view.id
            ],
        }

        serializer = RoleCreateSerializer(
            data=data,
            context={
                "organization": self.organization
            }
        )

        self.assertFalse(
            serializer.is_valid()
        )

        self.assertIn(
            "name",
            serializer.errors
        )

    def test_same_role_name_is_allowed_in_different_organization(
    self
    ):

        # ----------------------------------------------------
        # Organization A possui uma role "Manager"
        # ----------------------------------------------------

        role_a = Role.objects.create(
            organization=self.organization,
            name="Manager",
            description="Manager in Organization A"
        )

        role_a.permissions.add(
            self.permission_view
        )

        self.assertTrue(
            Role.objects.filter(
                organization=self.organization,
                name="Manager"
            ).exists()
        )

        # ----------------------------------------------------
        # O mesmo nome deve ser permitido na Organization B
        # ----------------------------------------------------

        data = {
            "name": "Manager",
            "description": "Manager in Organization B",
            "permissions": [
                self.permission_view.id
            ],
        }

        serializer = RoleCreateSerializer(
            data=data,
            context={
                "organization": self.organization_b
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        role_b = serializer.save(
            organization=self.organization_b
        )

        # ----------------------------------------------------
        # Verificações
        # ----------------------------------------------------

        self.assertEqual(
            role_b.name,
            "Manager"
        )

        self.assertEqual(
            role_b.organization,
            self.organization_b
        )

        self.assertTrue(
            role_b.permissions.filter(
                id=self.permission_view.id
            ).exists()
        )

        # ----------------------------------------------------
        # Devem existir duas "Manager":
        # uma em cada organização
        # ----------------------------------------------------

        self.assertEqual(
            Role.objects.filter(
                name="Manager"
            ).count(),
            2
        )

        self.assertTrue(
            Role.objects.filter(
                organization=self.organization,
                name="Manager"
            ).exists()
        )

        self.assertTrue(
            Role.objects.filter(
                organization=self.organization_b,
                name="Manager"
            ).exists()
        )

    def test_role_requires_organization_context(self):

        serializer = RoleCreateSerializer(
            data={
                "name": "Manager",
                "description": "Manager",
                "permissions": [
                    self.permission_view.id
                ],
            },
            context={}
        )

        self.assertFalse(
            serializer.is_valid()
        )

        self.assertIn(
            "name",
            serializer.errors
        )

    def test_permissions_are_required(self):

        serializer = RoleCreateSerializer(
            data={
                "name": "Manager",
                "description": "Manager",
            },
            context={
                "organization": self.organization
            }
        )

        self.assertFalse(
            serializer.is_valid()
        )

        self.assertIn(
            "permissions",
            serializer.errors
        )

    def test_update_role_to_existing_name_is_rejected(
        self
    ):

        role_a = Role.objects.create(
            organization=self.organization,
            name="Teacher",
            description="Teacher"
        )

        role_b = Role.objects.create(
            organization=self.organization,
            name="Manager",
            description="Manager"
        )

        serializer = RoleCreateSerializer(
            role_b,
            data={
                "name": "Teacher",
                "description": "Updated",
                "permissions": [
                    self.permission_view.id
                ],
            },
            context={
                "organization": self.organization
            }
        )

        self.assertFalse(
            serializer.is_valid()
        )

        self.assertIn(
            "name",
            serializer.errors
        )

        # Evita warning de variável não utilizada
        self.assertIsNotNone(role_a)

    def test_update_role_with_same_name_is_allowed(
        self
    ):

        serializer = RoleCreateSerializer(
            self.admin_role,
            data={
                "name": "Admin",
                "description": "Updated administrator",
                "permissions": [
                    self.permission_view.id
                ],
            },
            context={
                "organization": self.organization
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        role = serializer.save()

        self.assertEqual(
            role.name,
            "Admin"
        )

        self.assertEqual(
            role.description,
            "Updated administrator"
        )


# ============================================================
# GROUP SERIALIZER
# ============================================================

class GroupSerializerTest(
    SerializerTestBase
):

    def test_serialize_group(self):

        group = Group.objects.create(
            organization=self.organization,
            name="Developers",
            description="Development team"
        )

        serializer = GroupSerializer(
            group
        )

        self.assertEqual(
            serializer.data["name"],
            "Developers"
        )

        self.assertEqual(
            serializer.data["description"],
            "Development team"
        )

        self.assertEqual(
            serializer.data["organization"],
            self.organization.id
        )

        self.assertTrue(
            serializer.data["is_active"]
        )

    def test_group_organization_is_read_only(self):

        group = Group.objects.create(
            organization=self.organization,
            name="Developers"
        )

        serializer = GroupSerializer(
            group
        )

        self.assertTrue(
            serializer.fields[
                "organization"
            ].read_only
        )

    def test_group_created_at_is_read_only(self):

        serializer = GroupSerializer()

        self.assertTrue(
            serializer.fields[
                "created_at"
            ].read_only
        )

    def test_group_updated_at_is_read_only(self):

        serializer = GroupSerializer()

        self.assertTrue(
            serializer.fields[
                "updated_at"
            ].read_only
        )


# ============================================================
# GROUP CREATE / UPDATE SERIALIZER
# ============================================================

class GroupCreateSerializerTest(
    SerializerTestBase
):

    def test_create_group_successfully(self):

        serializer = GroupCreateSerializer(
            data={
                "name": "Developers",
                "description": "Development team",
                "is_active": True,
            },
            context={
                "organization": self.organization
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        group = serializer.save(
            organization=self.organization
        )

        self.assertEqual(
            group.name,
            "Developers"
        )

        self.assertEqual(
            group.organization,
            self.organization
        )

    def test_duplicate_group_name_in_same_organization_is_rejected(
        self
    ):

        Group.objects.create(
            organization=self.organization,
            name="Developers"
        )

        serializer = GroupCreateSerializer(
            data={
                "name": "Developers",
                "description": "Duplicate"
            },
            context={
                "organization": self.organization
            }
        )

        self.assertFalse(
            serializer.is_valid()
        )

        self.assertIn(
            "name",
            serializer.errors
        )

    def test_same_group_name_is_allowed_in_different_organization(
        self
    ):

        Group.objects.create(
            organization=self.organization,
            name="Developers"
        )

        serializer = GroupCreateSerializer(
            data={
                "name": "Developers",
                "description": "Developers B"
            },
            context={
                "organization": self.organization_b
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        group = serializer.save(
            organization=self.organization_b
        )

        self.assertEqual(
            group.organization,
            self.organization_b
        )

    def test_group_requires_organization_context(
        self
    ):

        serializer = GroupCreateSerializer(
            data={
                "name": "Developers",
                "description": "Development team"
            },
            context={}
        )

        self.assertFalse(
            serializer.is_valid()
        )

        self.assertIn(
            "name",
            serializer.errors
        )

    def test_update_group_to_existing_name_is_rejected(
        self
    ):

        group_a = Group.objects.create(
            organization=self.organization,
            name="Developers"
        )

        group_b = Group.objects.create(
            organization=self.organization,
            name="Managers"
        )

        serializer = GroupCreateSerializer(
            group_b,
            data={
                "name": "Developers",
                "description": "Updated"
            },
            context={
                "organization": self.organization
            }
        )

        self.assertFalse(
            serializer.is_valid()
        )

        self.assertIn(
            "name",
            serializer.errors
        )

        self.assertIsNotNone(
            group_a
        )

    def test_update_group_with_same_name_is_allowed(
        self
    ):

        group = Group.objects.create(
            organization=self.organization,
            name="Developers",
            description="Original"
        )

        serializer = GroupCreateSerializer(
            group,
            data={
                "name": "Developers",
                "description": "Updated"
            },
            context={
                "organization": self.organization
            }
        )

        self.assertTrue(
            serializer.is_valid(),
            serializer.errors
        )

        updated_group = serializer.save()

        self.assertEqual(
            updated_group.name,
            "Developers"
        )

        self.assertEqual(
            updated_group.description,
            "Updated"
        )