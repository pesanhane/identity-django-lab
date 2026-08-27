from django.test import TestCase
from rest_framework.test import APIRequestFactory

from users.models import User, AuditLog, Organization
from users.utils import create_audit_log


class SecurityAuditTest(TestCase):

    def setUp(self):
        self.organization = Organization.objects.create(
            name="Security Audit Organization"
        )

        self.user = User.objects.create_user(
            username="securityadmin",
            password="StrongPassword123!",
            organization=self.organization
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
            "LOGIN_FAILURE"
        )

        self.assertEqual(
            log.result,
            "FAILURE"
        )

        self.assertEqual(
            log.status_code,
            401
        )

        self.assertEqual(
            log.ip_address,
            "192.168.1.50"
        )

        self.assertEqual(
            log.endpoint,
            "/api/token/"
        )

        self.assertEqual(
            log.http_method,
            "POST"
        )

        self.assertEqual(
            log.user,
            self.user
        )

        self.assertEqual(
            log.organization,
            self.organization
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
            "ACCESS_DENIED"
        )

        self.assertEqual(
            log.result,
            "FAILURE"
        )

        self.assertEqual(
            log.status_code,
            403
        )

        self.assertEqual(
            log.endpoint,
            "/api/admin/users/"
        )

        self.assertEqual(
            log.http_method,
            "GET"
        )

        self.assertEqual(
            log.ip_address,
            "192.168.1.51"
        )

        self.assertEqual(
            log.user,
            self.user
        )

        self.assertEqual(
            log.organization,
            self.organization
        )

    def test_privilege_escalation_attempt_is_audited(self):

        request = self.factory.patch(
            "/api/users/10/",
            {
                "role": "admin"
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
            "PRIVILEGE_ESCALATION_ATTEMPT"
        )

        self.assertEqual(
            log.result,
            "FAILURE"
        )

        self.assertEqual(
            log.status_code,
            403
        )

        self.assertEqual(
            log.object_type,
            "User"
        )

        self.assertEqual(
            log.object_id,
            "10"
        )

        self.assertEqual(
            log.ip_address,
            "192.168.1.52"
        )

        self.assertEqual(
            log.endpoint,
            "/api/users/10/"
        )

        self.assertEqual(
            log.http_method,
            "PATCH"
        )

        self.assertEqual(
            log.user,
            self.user
        )

        self.assertEqual(
            log.organization,
            self.organization
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
            "TOKEN_INVALID"
        )

        self.assertEqual(
            log.result,
            "FAILURE"
        )

        self.assertEqual(
            log.status_code,
            401
        )

        self.assertEqual(
            log.endpoint,
            "/api/users/"
        )

        self.assertEqual(
            log.http_method,
            "GET"
        )

        self.assertEqual(
            log.ip_address,
            "192.168.1.53"
        )

        self.assertEqual(
            log.user,
            self.user
        )

        self.assertEqual(
            log.organization,
            self.organization
        )