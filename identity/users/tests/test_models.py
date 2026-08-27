from django.test import TestCase
from django.db import IntegrityError, transaction
from django.contrib.auth import get_user_model

from users.models import (
    Organization,
    Permission,
    Role,
    Group,
    AuditLog,
)


User = get_user_model()


# ============================================================
# ORGANIZATION
# ============================================================

class OrganizationModelTest(TestCase):

    def test_create_organization(self):
        organization = Organization.objects.create(
            name="Organization A",
            description="Primary organization"
        )

        self.assertEqual(
            organization.name,
            "Organization A"
        )

        self.assertEqual(
            organization.description,
            "Primary organization"
        )

        self.assertTrue(
            organization.is_active
        )

    def test_organization_name_is_unique(self):

        Organization.objects.create(
            name="Organization A"
        )

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Organization.objects.create(
                    name="Organization A"
                )

    def test_organization_str(self):

        organization = Organization.objects.create(
            name="Organization A"
        )

        self.assertEqual(
            str(organization),
            "Organization A"
        )

    def test_organization_is_active_defaults_to_true(self):

        organization = Organization.objects.create(
            name="Organization A"
        )

        self.assertTrue(
            organization.is_active
        )

    def test_organization_can_be_deactivated(self):

        organization = Organization.objects.create(
            name="Organization A"
        )

        organization.is_active = False
        organization.save()

        organization.refresh_from_db()

        self.assertFalse(
            organization.is_active
        )

    def test_organization_timestamps_are_created(self):

        organization = Organization.objects.create(
            name="Organization A"
        )

        self.assertIsNotNone(
            organization.created_at
        )

        self.assertIsNotNone(
            organization.updated_at
        )


# ============================================================
# PERMISSION
# ============================================================

class PermissionModelTest(TestCase):

    def test_create_permission(self):

        permission = Permission.objects.create(
            code="user.view",
            description="View users"
        )

        self.assertEqual(
            permission.code,
            "user.view"
        )

        self.assertEqual(
            permission.description,
            "View users"
        )

    def test_permission_code_is_unique(self):

        Permission.objects.create(
            code="user.view",
            description="View users"
        )

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Permission.objects.create(
                    code="user.view",
                    description="Another description"
                )

    def test_permission_str(self):

        permission = Permission.objects.create(
            code="user.create",
            description="Create users"
        )

        self.assertEqual(
            str(permission),
            "user.create"
        )


# ============================================================
# ROLE
# ============================================================

class RoleModelTest(TestCase):

    def setUp(self):

        self.organization = Organization.objects.create(
            name="Organization A"
        )

        self.organization_b = Organization.objects.create(
            name="Organization B"
        )

        self.permission_view = Permission.objects.create(
            code="user.view",
            description="View users"
        )

        self.permission_create = Permission.objects.create(
            code="user.create",
            description="Create users"
        )

    def test_create_role(self):

        role = Role.objects.create(
            organization=self.organization,
            name="Admin",
            description="Administrator"
        )

        self.assertEqual(
            role.name,
            "Admin"
        )

        self.assertEqual(
            role.organization,
            self.organization
        )

    def test_role_str(self):

        role = Role.objects.create(
            organization=self.organization,
            name="Admin"
        )

        self.assertEqual(
            str(role),
            "Admin"
        )

    def test_role_name_must_be_unique_inside_organization(self):

        Role.objects.create(
            organization=self.organization,
            name="Admin"
        )

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Role.objects.create(
                    organization=self.organization,
                    name="Admin"
                )

    def test_same_role_name_is_allowed_in_different_organizations(self):

        role_a = Role.objects.create(
            organization=self.organization,
            name="Admin"
        )

        role_b = Role.objects.create(
            organization=self.organization_b,
            name="Admin"
        )

        self.assertNotEqual(
            role_a.organization,
            role_b.organization
        )

        self.assertEqual(
            role_a.name,
            role_b.name
        )

    def test_role_can_have_multiple_permissions(self):

        role = Role.objects.create(
            organization=self.organization,
            name="Admin"
        )

        role.permissions.add(
            self.permission_view,
            self.permission_create
        )

        self.assertEqual(
            role.permissions.count(),
            2
        )

        self.assertTrue(
            role.permissions.filter(
                code="user.view"
            ).exists()
        )

        self.assertTrue(
            role.permissions.filter(
                code="user.create"
            ).exists()
        )

    def test_permission_can_belong_to_multiple_roles(self):

        role_a = Role.objects.create(
            organization=self.organization,
            name="Admin"
        )

        role_b = Role.objects.create(
            organization=self.organization,
            name="Manager"
        )

        role_a.permissions.add(
            self.permission_view
        )

        role_b.permissions.add(
            self.permission_view
        )

        self.assertEqual(
            self.permission_view.roles.count(),
            2
        )

    def test_role_without_organization_is_allowed(self):

        role = Role.objects.create(
            organization=None,
            name="GlobalRole"
        )

        self.assertIsNone(
            role.organization
        )

    def test_role_permissions_can_be_removed(self):

        role = Role.objects.create(
            organization=self.organization,
            name="Admin"
        )

        role.permissions.add(
            self.permission_view,
            self.permission_create
        )

        role.permissions.remove(
            self.permission_create
        )

        self.assertTrue(
            role.permissions.filter(
                code="user.view"
            ).exists()
        )

        self.assertFalse(
            role.permissions.filter(
                code="user.create"
            ).exists()
        )


# ============================================================
# GROUP
# ============================================================

class GroupModelTest(TestCase):

    def setUp(self):

        self.organization = Organization.objects.create(
            name="Organization A"
        )

        self.organization_b = Organization.objects.create(
            name="Organization B"
        )

    def test_create_group(self):

        group = Group.objects.create(
            organization=self.organization,
            name="Developers",
            description="Development team"
        )

        self.assertEqual(
            group.name,
            "Developers"
        )

        self.assertEqual(
            group.organization,
            self.organization
        )

        self.assertTrue(
            group.is_active
        )

    def test_group_str(self):

        group = Group.objects.create(
            organization=self.organization,
            name="Developers"
        )

        self.assertEqual(
            str(group),
            "Developers"
        )

    def test_group_name_is_unique_inside_organization(self):

        Group.objects.create(
            organization=self.organization,
            name="Developers"
        )

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Group.objects.create(
                    organization=self.organization,
                    name="Developers"
                )

    def test_same_group_name_is_allowed_in_different_organizations(self):

        group_a = Group.objects.create(
            organization=self.organization,
            name="Developers"
        )

        group_b = Group.objects.create(
            organization=self.organization_b,
            name="Developers"
        )

        self.assertEqual(
            group_a.name,
            group_b.name
        )

        self.assertNotEqual(
            group_a.organization,
            group_b.organization
        )

    def test_group_is_active_defaults_to_true(self):

        group = Group.objects.create(
            organization=self.organization,
            name="Developers"
        )

        self.assertTrue(
            group.is_active
        )

    def test_group_can_be_deactivated(self):

        group = Group.objects.create(
            organization=self.organization,
            name="Developers"
        )

        group.is_active = False
        group.save()

        group.refresh_from_db()

        self.assertFalse(
            group.is_active
        )

    def test_group_timestamps_are_created(self):

        group = Group.objects.create(
            organization=self.organization,
            name="Developers"
        )

        self.assertIsNotNone(
            group.created_at
        )

        self.assertIsNotNone(
            group.updated_at
        )


# ============================================================
# USER
# ============================================================

class UserModelTest(TestCase):

    def setUp(self):

        self.organization = Organization.objects.create(
            name="Organization A"
        )

        self.organization_b = Organization.objects.create(
            name="Organization B"
        )

        self.permission_view = Permission.objects.create(
            code="user.view",
            description="View users"
        )

        self.role = Role.objects.create(
            organization=self.organization,
            name="Admin"
        )

        self.role.permissions.add(
            self.permission_view
        )

        self.group = Group.objects.create(
            organization=self.organization,
            name="Developers"
        )

    def test_create_user(self):

        user = User.objects.create_user(
            username="john",
            email="john@example.com",
            password="StrongPassword123!",
            organization=self.organization
        )

        self.assertEqual(
            user.username,
            "john"
        )

        self.assertEqual(
            user.organization,
            self.organization
        )

    def test_user_password_is_hashed(self):

        user = User.objects.create_user(
            username="john",
            password="StrongPassword123!"
        )

        self.assertNotEqual(
            user.password,
            "StrongPassword123!"
        )

        self.assertTrue(
            user.check_password(
                "StrongPassword123!"
            )
        )

    def test_user_str(self):

        user = User.objects.create_user(
            username="john",
            password="StrongPassword123!"
        )

        self.assertEqual(
            str(user),
            "john"
        )

    def test_user_can_have_roles(self):

        user = User.objects.create_user(
            username="john",
            password="StrongPassword123!",
            organization=self.organization
        )

        user.roles.add(
            self.role
        )

        self.assertEqual(
            user.roles.count(),
            1
        )

        self.assertTrue(
            user.roles.filter(
                name="Admin"
            ).exists()
        )

    def test_user_can_have_multiple_roles(self):

        role_two = Role.objects.create(
            organization=self.organization,
            name="Manager"
        )

        user = User.objects.create_user(
            username="john",
            password="StrongPassword123!",
            organization=self.organization
        )

        user.roles.add(
            self.role,
            role_two
        )

        self.assertEqual(
            user.roles.count(),
            2
        )

    def test_user_can_have_iam_groups(self):

        user = User.objects.create_user(
            username="john",
            password="StrongPassword123!",
            organization=self.organization
        )

        user.iam_groups.add(
            self.group
        )

        self.assertEqual(
            user.iam_groups.count(),
            1
        )

        self.assertTrue(
            user.iam_groups.filter(
                name="Developers"
            ).exists()
        )

    def test_user_is_verified_defaults_to_false(self):

        user = User.objects.create_user(
            username="john",
            password="StrongPassword123!"
        )

        self.assertFalse(
            user.is_verified
        )

    def test_user_can_be_verified(self):

        user = User.objects.create_user(
            username="john",
            password="StrongPassword123!"
        )

        user.is_verified = True
        user.save()

        user.refresh_from_db()

        self.assertTrue(
            user.is_verified
        )

    def test_user_can_be_inactive(self):

        user = User.objects.create_user(
            username="john",
            password="StrongPassword123!"
        )

        user.is_active = False
        user.save()

        user.refresh_from_db()

        self.assertFalse(
            user.is_active
        )

    def test_user_can_have_phone_number(self):

        user = User.objects.create_user(
            username="john",
            password="StrongPassword123!",
            phone_number="841234567"
        )

        self.assertEqual(
            user.phone_number,
            "841234567"
        )

    def test_user_can_have_last_login_ip(self):

        user = User.objects.create_user(
            username="john",
            password="StrongPassword123!",
            last_login_ip="192.168.1.10"
        )

        self.assertEqual(
            user.last_login_ip,
            "192.168.1.10"
        )

    def test_user_organization_can_be_null(self):

        user = User.objects.create_user(
            username="john",
            password="StrongPassword123!"
        )

        self.assertIsNone(
            user.organization
        )

    def test_user_timestamps_are_created(self):

        user = User.objects.create_user(
            username="john",
            password="StrongPassword123!"
        )

        self.assertIsNotNone(
            user.created_at
        )

        self.assertIsNotNone(
            user.updated_at
        )

    def test_role_from_another_organization_can_exist_but_rbac_must_filter_it(self):

        other_role = Role.objects.create(
            organization=self.organization_b,
            name="OtherAdmin"
        )

        user = User.objects.create_user(
            username="john",
            password="StrongPassword123!",
            organization=self.organization
        )

        user.roles.add(
            other_role
        )

        self.assertTrue(
            user.roles.filter(
                id=other_role.id
            ).exists()
        )

        self.assertNotEqual(
            other_role.organization,
            user.organization
        )


# ============================================================
# AUDIT LOG
# ============================================================

class AuditLogModelTest(TestCase):

    def setUp(self):

        self.organization = Organization.objects.create(
            name="Organization A"
        )

        self.user = User.objects.create_user(
            username="admin",
            email="admin@example.com",
            password="AdminPassword123!",
            organization=self.organization
        )

    def test_create_audit_log(self):

        log = AuditLog.objects.create(
            organization=self.organization,
            user=self.user,
            action="CREATE",
            description="User created",
            ip_address="192.168.1.10",
            endpoint="/api/users/",
            http_method="POST",
            object_id="10",
            object_type="User",
            result="SUCCESS",
            status_code=201,
            user_agent="TestAgent"
        )

        self.assertEqual(
            log.organization,
            self.organization
        )

        self.assertEqual(
            log.user,
            self.user
        )

        self.assertEqual(
            log.action,
            "CREATE"
        )

        self.assertEqual(
            log.description,
            "User created"
        )

    def test_audit_log_can_have_null_user(self):

        log = AuditLog.objects.create(
            organization=self.organization,
            user=None,
            action="SYSTEM",
            description="System action"
        )

        self.assertIsNone(
            log.user
        )

    def test_audit_log_optional_fields_can_be_null(self):

        log = AuditLog.objects.create(
            organization=self.organization,
            action="TEST",
            description="Test log"
        )

        self.assertIsNone(
            log.user
        )

        self.assertIsNone(
            log.ip_address
        )

        self.assertIsNone(
            log.endpoint
        )

        self.assertIsNone(
            log.http_method
        )

        self.assertIsNone(
            log.object_id
        )

        self.assertIsNone(
            log.object_type
        )

        self.assertIsNone(
            log.result
        )

        self.assertIsNone(
            log.status_code
        )

        self.assertIsNone(
            log.user_agent
        )

    def test_audit_log_timestamp_is_created(self):

        log = AuditLog.objects.create(
            organization=self.organization,
            action="LOGIN",
            description="User login"
        )

        self.assertIsNotNone(
            log.created_at
        )

    def test_audit_log_requires_organization(self):

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                AuditLog.objects.create(
                    organization=None,
                    action="TEST",
                    description="Invalid audit log"
                )

    def test_deleting_user_sets_audit_log_user_to_null(self):

        log = AuditLog.objects.create(
            organization=self.organization,
            user=self.user,
            action="DELETE",
            description="Test"
        )

        self.user.delete()

        log.refresh_from_db()

        self.assertIsNone(
            log.user
        )

    def test_deleting_organization_is_protected_by_audit_logs(self):

        AuditLog.objects.create(
            organization=self.organization,
            user=self.user,
            action="TEST",
            description="Organization protection test"
        )

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                self.organization.delete()