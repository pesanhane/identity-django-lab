
import os

from unittest.mock import patch
from django.core.cache import cache
from rest_framework.test import APITestCase

from users.models import (
    User,
    Organization,
    AuditLog,
    MFARecoveryCode,
)
from users.mfa import generate_secret
from users.mfa_recovery import generate_recovery_codes


class MFARecoveryAPITest(APITestCase):

    def setUp(self):
        cache.clear()

        self.organization = Organization.objects.create(
            name="Recovery API Organization"
        )

        self.user = User.objects.create_user(
            username="recoveryapi",
            email="recoveryapi@example.com",
            password="TestPassword123!",
            organization=self.organization,
        )

        self.other_user = User.objects.create_user(
            username="recoveryother",
            email="recoveryother@example.com",
            password="TestPassword123!",
            organization=self.organization,
        )

        self.token_url = "/api/token/"
        self.recovery_token_url = "/api/token/mfa/recovery/"
        self.recovery_codes_url = (
            "/api/users/me/mfa/recovery-codes/"
        )

    def tearDown(self):
        cache.clear()

    def enable_mfa(self, user=None):
        user = user or self.user

        user.mfa_secret = generate_secret()
        user.mfa_enabled = True
        user.mfa_last_used_counter = None

        user.save(
            update_fields=[
                "mfa_secret",
                "mfa_enabled",
                "mfa_last_used_counter",
            ]
        )

    def authenticate(self):
        response = self.client.post(
            self.token_url,
            {
                "username": self.user.username,
                "password": "TestPassword123!",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {response.data['access']}"
            )
        )

    # ==========================================================
    # GENERATION
    # ==========================================================

    def test_recovery_codes_require_authentication(self):
        response = self.client.post(
            self.recovery_codes_url,
            {},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            401,
        )

    def test_recovery_codes_require_enabled_mfa(self):
        self.authenticate()

        response = self.client.post(
            self.recovery_codes_url,
            {},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            400,
            response.data,
        )

    def test_recovery_codes_can_be_generated_when_mfa_enabled(self):
        self.enable_mfa()
        self.client.force_authenticate(
            user=self.user
        )

        response = self.client.post(
            self.recovery_codes_url,
            {},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        self.assertIn(
            "recovery_codes",
            response.data,
        )

        self.assertEqual(
            len(response.data["recovery_codes"]),
            10,
        )

        self.assertEqual(
            MFARecoveryCode.objects.filter(
                user=self.user
            ).count(),
            10,
        )

    def test_recovery_code_generation_is_audited(self):
        self.enable_mfa()
        self.client.force_authenticate(
            user=self.user
        )

        response = self.client.post(
            self.recovery_codes_url,
            {},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        self.assertTrue(
            AuditLog.objects.filter(
                user=self.user,
                action="MFA_RECOVERY_CODES_GENERATED",
            ).exists()
        )

    # ==========================================================
    # LOGIN
    # ==========================================================

    def test_valid_recovery_code_can_authenticate(self):
        self.enable_mfa()

        codes = generate_recovery_codes(
            self.user
        )

        response = self.client.post(
            self.recovery_token_url,
            {
                "username": self.user.username,
                "password": "TestPassword123!",
                "recovery_code": codes[0],
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        self.assertIn(
            "access",
            response.data,
        )

        self.assertIn(
            "refresh",
            response.data,
        )

    def test_recovery_code_cannot_be_reused(self):
        self.enable_mfa()

        codes = generate_recovery_codes(
            self.user
        )

        first_response = self.client.post(
            self.recovery_token_url,
            {
                "username": self.user.username,
                "password": "TestPassword123!",
                "recovery_code": codes[0],
            },
            format="json",
        )

        self.assertEqual(
            first_response.status_code,
            200,
            first_response.data,
        )

        second_response = self.client.post(
            self.recovery_token_url,
            {
                "username": self.user.username,
                "password": "TestPassword123!",
                "recovery_code": codes[0],
            },
            format="json",
        )

        self.assertEqual(
            second_response.status_code,
            400,
            second_response.data,
        )

        self.assertNotIn(
            "access",
            second_response.data,
        )

        self.assertNotIn(
            "refresh",
            second_response.data,
        )

    def test_invalid_recovery_code_is_rejected(self):
        self.enable_mfa()

        generate_recovery_codes(
            self.user
        )

        response = self.client.post(
            self.recovery_token_url,
            {
                "username": self.user.username,
                "password": "TestPassword123!",
                "recovery_code": "FFFF-FFFF-FFFF",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            400,
            response.data,
        )

    def test_wrong_password_is_rejected(self):
        self.enable_mfa()

        codes = generate_recovery_codes(
            self.user
        )

        response = self.client.post(
            self.recovery_token_url,
            {
                "username": self.user.username,
                "password": "WrongPassword123!",
                "recovery_code": codes[0],
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            401,
            response.data,
        )

    def test_other_users_recovery_code_is_rejected(self):
        self.enable_mfa(
            self.user
        )

        self.enable_mfa(
            self.other_user
        )

        other_codes = generate_recovery_codes(
            self.other_user
        )

        response = self.client.post(
            self.recovery_token_url,
            {
                "username": self.user.username,
                "password": "TestPassword123!",
                "recovery_code": other_codes[0],
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            400,
            response.data,
        )

    def test_regeneration_invalidates_old_recovery_codes(self):
        self.enable_mfa()
        self.client.force_authenticate(
            user=self.user
        )

        old_codes = generate_recovery_codes(
            self.user
        )

        response = self.client.post(
            self.recovery_codes_url,
            {},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        self.client.force_authenticate(
            user=None
        )

        response = self.client.post(
            self.recovery_token_url,
            {
                "username": self.user.username,
                "password": "TestPassword123!",
                "recovery_code": old_codes[0],
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            400,
            response.data,
        )
        # ==========================================================
    # RECOVERY LOGIN AUDIT
    # ==========================================================

    def test_successful_recovery_login_is_audited(self):

        self.enable_mfa()

        codes = generate_recovery_codes(
            self.user
        )

        response = self.client.post(
            self.recovery_token_url,
            {
                "username": self.user.username,
                "password": "TestPassword123!",
                "recovery_code": codes[0],
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        audit = AuditLog.objects.filter(
            user=self.user,
            action="MFA_RECOVERY_LOGIN_SUCCESS",
        ).first()

        self.assertIsNotNone(
            audit
        )

        self.assertEqual(
            audit.result,
            "SUCCESS",
        )

        self.assertEqual(
            audit.status_code,
            200,
        )

        self.assertEqual(
            audit.endpoint,
            self.recovery_token_url,
        )


    def test_failed_recovery_login_is_audited(self):

        self.enable_mfa()

        generate_recovery_codes(
            self.user
        )

        response = self.client.post(
            self.recovery_token_url,
            {
                "username": self.user.username,
                "password": "TestPassword123!",
                "recovery_code": "FFFF-FFFF-FFFF",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            400,
            response.data,
        )

        audit = AuditLog.objects.filter(
            user=self.user,
            action="MFA_RECOVERY_LOGIN_FAILED",
        ).first()

        self.assertIsNotNone(
            audit
        )

        self.assertEqual(
            audit.result,
            "FAILURE",
        )

        self.assertEqual(
            audit.status_code,
            400,
        )

        self.assertEqual(
            audit.endpoint,
            self.recovery_token_url,
        )
        # ==========================================================
    # RECOVERY LOGIN RATE LIMIT
    # ==========================================================

    @patch.dict(
        os.environ,
        {
            "MFA_RATE_LIMIT_USER": "2",
            "MFA_RATE_LIMIT_IP": "100",
            "RATE_LIMIT_WINDOW": "60",
            "RATE_LIMIT_BLOCK": "300",
        },
        clear=False,
    )
    def test_recovery_login_rate_limit_returns_429(self):

        cache.clear()

        self.enable_mfa()

        generate_recovery_codes(
            self.user
        )

        payload = {
            "username": self.user.username,
            "password": "TestPassword123!",
            "recovery_code": "FFFF-FFFF-FFFF",
        }

        # 1ª tentativa
        response1 = self.client.post(
            self.recovery_token_url,
            payload,
            format="json",
        )

        self.assertEqual(
            response1.status_code,
            400,
            response1.data,
        )

        # 2ª tentativa
        response2 = self.client.post(
            self.recovery_token_url,
            payload,
            format="json",
        )

        self.assertEqual(
            response2.status_code,
            400,
            response2.data,
        )

        # 3ª tentativa deve ser bloqueada
        response3 = self.client.post(
            self.recovery_token_url,
            payload,
            format="json",
        )

        self.assertEqual(
            response3.status_code,
            429,
        )

        self.assertNotIn(
            "access",
            getattr(
                response3,
                "data",
                {},
            ),
        )
    def test_rate_limited_recovery_login_is_audited(self):

        cache.clear()

        self.enable_mfa()

        generate_recovery_codes(
            self.user
        )

        payload = {
            "username": self.user.username,
            "password": "TestPassword123!",
            "recovery_code": "FFFF-FFFF-FFFF",
        }

        with patch.dict(
            os.environ,
            {
                "MFA_RATE_LIMIT_USER": "2",
                "MFA_RATE_LIMIT_IP": "100",
                "RATE_LIMIT_WINDOW": "60",
                "RATE_LIMIT_BLOCK": "300",
            },
            clear=False,
        ):

            response1 = self.client.post(
                self.recovery_token_url,
                payload,
                format="json",
            )

            self.assertEqual(
                response1.status_code,
                400,
                response1.data,
            )

            response2 = self.client.post(
                self.recovery_token_url,
                payload,
                format="json",
            )

            self.assertEqual(
                response2.status_code,
                400,
                response2.data,
            )

            response3 = self.client.post(
                self.recovery_token_url,
                payload,
                format="json",
            )

        self.assertEqual(
            response3.status_code,
            429,
        )

        audit = (
            AuditLog.objects
            .filter(
                user=self.user,
                action="MFA_RECOVERY_RATE_LIMITED",
            )
            .order_by("-created_at")
            .first()
        )

        self.assertIsNotNone(
            audit
        )

        self.assertEqual(
            audit.result,
            "FAILURE",
        )

        self.assertEqual(
            audit.status_code,
            429,
        )

        self.assertEqual(
            audit.endpoint,
            self.recovery_token_url,
        )