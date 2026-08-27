from django.test import TestCase
from rest_framework.test import APIClient, APIRequestFactory
from django.utils import timezone

from users.models import User, AuditLog, Organization
from users.utils import create_audit_log


class AuditLogTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.factory = APIRequestFactory()

        self.password = "TestPassword123!"

        self.organization = Organization.objects.create(
            name="Audit Test Organization"
        )

        self.user = User.objects.create_user(
            username="audituser",
            email="audit@example.com",
            password=self.password,
            organization=self.organization,
        )

    def create_request(self, ip="127.0.0.1"):
        request = self.factory.get("/")

        request.user = self.user
        request.META["REMOTE_ADDR"] = ip

        return request

    def test_create_audit_log(self):
        request = self.create_request()

        create_audit_log(
            request,
            "LOGIN",
            "Utilizador efetuou login"
        )

        self.assertEqual(
            AuditLog.objects.count(),
            1
        )

        log = AuditLog.objects.first()

        self.assertEqual(
            log.user,
            self.user
        )

        self.assertEqual(
            log.organization,
            self.organization
        )

        self.assertEqual(
            log.action,
            "LOGIN"
        )

        self.assertEqual(
            log.description,
            "Utilizador efetuou login"
        )

        self.assertEqual(
            log.ip_address,
            "127.0.0.1"
        )

    def test_audit_log_is_created_with_timestamp(self):
        request = self.create_request()

        before = timezone.now()

        create_audit_log(
            request,
            "LOGIN",
            "Teste de timestamp"
        )

        after = timezone.now()

        log = AuditLog.objects.first()

        self.assertIsNotNone(
            log.created_at
        )

        self.assertGreaterEqual(
            log.created_at,
            before
        )

        self.assertLessEqual(
            log.created_at,
            after
        )

        self.assertEqual(
            log.organization,
            self.organization
        )

    def test_multiple_audit_logs_are_created(self):
        request = self.create_request()

        create_audit_log(
            request,
            "LOGIN",
            "Primeiro evento"
        )

        create_audit_log(
            request,
            "LOGOUT",
            "Segundo evento"
        )

        create_audit_log(
            request,
            "CHANGE_PASSWORD",
            "Terceiro evento"
        )

        self.assertEqual(
            AuditLog.objects.count(),
            3
        )

        logs = AuditLog.objects.order_by("id")

        self.assertEqual(
            logs[0].action,
            "LOGIN"
        )

        self.assertEqual(
            logs[1].action,
            "LOGOUT"
        )

        self.assertEqual(
            logs[2].action,
            "CHANGE_PASSWORD"
        )

        self.assertEqual(
            logs[0].organization,
            self.organization
        )

        self.assertEqual(
            logs[1].organization,
            self.organization
        )

        self.assertEqual(
            logs[2].organization,
            self.organization
        )

    def test_audit_log_survives_user_deletion(self):
        request = self.create_request()

        create_audit_log(
            request,
            "CREATE_USER",
            "Teste de preservação do audit log"
        )

        audit_log = AuditLog.objects.get(
            user=self.user
        )

        self.assertEqual(
            AuditLog.objects.count(),
            1
        )

        self.assertEqual(
            audit_log.organization,
            self.organization
        )

        self.user.delete()

        audit_log.refresh_from_db()

        self.assertEqual(
            AuditLog.objects.count(),
            1
        )

        self.assertIsNone(
            audit_log.user
        )

        self.assertEqual(
            audit_log.organization,
            self.organization
        )

        self.assertEqual(
            audit_log.action,
            "CREATE_USER"
        )

        self.assertEqual(
            audit_log.description,
            "Teste de preservação do audit log"
        )