from unittest.mock import patch

import pyotp

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from users.models import User, Organization, AuditLog
from users.mfa import generate_secret


class MFAViewsTest(APITestCase):

    def setUp(self):
        self.organization = Organization.objects.create(
            name="MFA Test Organization",
            description="Organization used for MFA tests",
        )

        self.user = User.objects.create_user(
            username="mfatest",
            email="mfatest@example.com",
            password="TestPassword123!",
            organization=self.organization,
        )

        self.setup_url = "/api/users/me/mfa/setup/"
        self.verify_url = "/api/users/me/mfa/verify/"
        self.token_url = "/api/token/mfa/"

    # ==========================================================
    # HELPERS
    # ==========================================================

    def authenticate(self):
        self.client.force_authenticate(user=self.user)

    def initialize_mfa(self):
        self.user.mfa_secret = generate_secret()
        self.user.mfa_enabled = False
        self.user.mfa_verified_at = None
        self.user.mfa_last_used_counter = None

        self.user.save(
            update_fields=[
                "mfa_secret",
                "mfa_enabled",
                "mfa_verified_at",
                "mfa_last_used_counter",
            ]
        )

    def code_at(self, timestamp):
        return pyotp.TOTP(self.user.mfa_secret).at(timestamp)

    # ==========================================================
    # AUTHENTICATION
    # ==========================================================

    def test_setup_requires_authentication(self):
        response = self.client.get(self.setup_url)

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_verify_requires_authentication(self):
        response = self.client.post(
            self.verify_url,
            {"code": "123456"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    # ==========================================================
    # MFA SETUP
    # ==========================================================

    def test_setup_generates_secret(self):
        self.authenticate()

        self.assertFalse(self.user.mfa_secret)

        response = self.client.get(self.setup_url)

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.user.refresh_from_db()

        self.assertTrue(self.user.mfa_secret)
        self.assertFalse(self.user.mfa_enabled)

        self.assertIn(
            "otpauth_uri",
            response.data,
        )

        self.assertTrue(
            response.data["otpauth_uri"].startswith(
                "otpauth://totp/"
            )
        )

    def test_setup_does_not_activate_mfa(self):
        self.authenticate()

        response = self.client.get(self.setup_url)

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.user.refresh_from_db()

        self.assertFalse(
            self.user.mfa_enabled
        )

        self.assertIsNone(
            self.user.mfa_verified_at
        )

    def test_setup_is_idempotent_and_does_not_rotate_secret(self):
        self.authenticate()

        first_response = self.client.get(
            self.setup_url
        )

        self.assertEqual(
            first_response.status_code,
            status.HTTP_200_OK,
        )

        self.user.refresh_from_db()

        original_secret = self.user.mfa_secret
        original_uri = first_response.data["otpauth_uri"]

        second_response = self.client.get(
            self.setup_url
        )

        self.assertEqual(
            second_response.status_code,
            status.HTTP_200_OK,
        )

        self.user.refresh_from_db()

        self.assertEqual(
            self.user.mfa_secret,
            original_secret,
        )

        self.assertEqual(
            second_response.data["otpauth_uri"],
            original_uri,
        )

    def test_setup_creates_audit_log(self):
        self.authenticate()

        response = self.client.get(
            self.setup_url
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertTrue(
            AuditLog.objects.filter(
                organization=self.organization,
                user=self.user,
                action="MFA_SETUP_REQUEST",
            ).exists()
        )

    # ==========================================================
    # MFA VERIFICATION / ACTIVATION
    # ==========================================================

    def test_verify_without_code_fails(self):
        self.authenticate()
        self.initialize_mfa()

        response = self.client.post(
            self.verify_url,
            {},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        self.assertEqual(
            response.data["error"],
            "MFA code is required.",
        )

    def test_verify_without_secret_fails(self):
        self.authenticate()

        response = self.client.post(
            self.verify_url,
            {"code": "123456"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        self.assertEqual(
            response.data["error"],
            "MFA setup has not been initialized.",
        )

    def test_verify_invalid_code_does_not_activate_mfa(self):
        self.authenticate()
        self.initialize_mfa()

        response = self.client.post(
            self.verify_url,
            {"code": "000000"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        self.user.refresh_from_db()

        self.assertFalse(
            self.user.mfa_enabled
        )

        self.assertIsNone(
            self.user.mfa_verified_at
        )

        self.assertIsNone(
            self.user.mfa_last_used_counter
        )

    def test_verify_valid_code_activates_mfa(self):
        self.authenticate()
        self.initialize_mfa()

        timestamp = 1_900_000_000
        code = self.code_at(timestamp)

        with patch(
            "users.mfa.time.time",
            return_value=timestamp,
        ):
            response = self.client.post(
                self.verify_url,
                {"code": code},
                format="json",
            )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertTrue(
            response.data["mfa_enabled"]
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.mfa_enabled
        )

        self.assertIsNotNone(
            self.user.mfa_verified_at
        )

        self.assertIsNotNone(
            self.user.mfa_last_used_counter
        )

    def test_verify_valid_code_creates_activation_audit_log(self):
        self.authenticate()
        self.initialize_mfa()

        timestamp = 1_900_000_000
        code = self.code_at(timestamp)

        with patch(
            "users.mfa.time.time",
            return_value=timestamp,
        ):
            response = self.client.post(
                self.verify_url,
                {"code": code},
                format="json",
            )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertTrue(
            AuditLog.objects.filter(
                organization=self.organization,
                user=self.user,
                action="MFA_ENABLED",
            ).exists()
        )

    def test_invalid_code_creates_failure_audit_log(self):
        self.authenticate()
        self.initialize_mfa()

        response = self.client.post(
            self.verify_url,
            {"code": "000000"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        self.assertTrue(
            AuditLog.objects.filter(
                organization=self.organization,
                user=self.user,
                action="MFA_VERIFY_FAILED",
            ).exists()
        )

    # ==========================================================
    # ANTI-REPLAY
    # ==========================================================

    def test_same_code_cannot_be_used_twice_during_activation(self):
        self.authenticate()
        self.initialize_mfa()

        timestamp = 1_900_000_000
        code = self.code_at(timestamp)

        with patch(
            "users.mfa.time.time",
            return_value=timestamp,
        ):
            first_response = self.client.post(
                self.verify_url,
                {"code": code},
                format="json",
            )

            second_response = self.client.post(
                self.verify_url,
                {"code": code},
                format="json",
            )

        self.assertEqual(
            first_response.status_code,
            status.HTTP_200_OK,
        )

        self.assertEqual(
            second_response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        self.assertEqual(
            second_response.data["error"],
            "MFA code has already been used.",
        )

    def test_replay_creates_audit_log(self):
        self.authenticate()
        self.initialize_mfa()

        timestamp = 1_900_000_000
        code = self.code_at(timestamp)

        with patch(
            "users.mfa.time.time",
            return_value=timestamp,
        ):
            self.client.post(
                self.verify_url,
                {"code": code},
                format="json",
            )

            replay_response = self.client.post(
                self.verify_url,
                {"code": code},
                format="json",
            )

        self.assertEqual(
            replay_response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        self.assertTrue(
            AuditLog.objects.filter(
                organization=self.organization,
                user=self.user,
                action="MFA_REPLAY_DETECTED",
            ).exists()
        )

    # ==========================================================
    # REACTIVATION
    # ==========================================================

    def test_setup_after_mfa_activation_does_not_rotate_secret(self):
        self.authenticate()
        self.initialize_mfa()

        original_secret = self.user.mfa_secret

        timestamp = 1_900_000_000
        code = self.code_at(timestamp)

        with patch(
            "users.mfa.time.time",
            return_value=timestamp,
        ):
            response = self.client.post(
                self.verify_url,
                {"code": code},
                format="json",
            )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.mfa_enabled
        )

        self.assertEqual(
            self.user.mfa_secret,
            original_secret,
        )

        setup_response = self.client.get(
            self.setup_url
        )

        self.assertEqual(
            setup_response.status_code,
            status.HTTP_200_OK,
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.mfa_enabled
        )

        self.assertEqual(
            self.user.mfa_secret,
            original_secret,
        )

    def test_mfa_can_be_reactivated_with_a_new_code(self):
        self.authenticate()
        self.initialize_mfa()

        first_timestamp = 1_900_000_000
        first_code = self.code_at(first_timestamp)

        with patch(
            "users.mfa.time.time",
            return_value=first_timestamp,
        ):
            first_response = self.client.post(
                self.verify_url,
                {"code": first_code},
                format="json",
            )

        self.assertEqual(
            first_response.status_code,
            status.HTTP_200_OK,
        )

        self.user.refresh_from_db()

        first_counter = self.user.mfa_last_used_counter

        # Simular desativação administrativa do MFA.
        self.user.mfa_enabled = False
        self.user.save(
            update_fields=["mfa_enabled"]
        )

        second_timestamp = first_timestamp + 60
        second_code = self.code_at(second_timestamp)

        with patch(
            "users.mfa.time.time",
            return_value=second_timestamp,
        ):
            second_response = self.client.post(
                self.verify_url,
                {"code": second_code},
                format="json",
            )

        self.assertEqual(
            second_response.status_code,
            status.HTTP_200_OK,
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.mfa_enabled
        )

        self.assertGreater(
            self.user.mfa_last_used_counter,
            first_counter,
        )

    # ==========================================================
    # AUTHENTICATION AFTER MFA ACTIVATION
    # ==========================================================

    def test_mfa_login_works_with_new_totp_code_after_activation(self):
        self.authenticate()
        self.initialize_mfa()

        activation_timestamp = 1_900_000_000
        activation_code = self.code_at(
            activation_timestamp
        )

        with patch(
            "users.mfa.time.time",
            return_value=activation_timestamp,
        ):
            activation_response = self.client.post(
                self.verify_url,
                {"code": activation_code},
                format="json",
            )

        self.assertEqual(
            activation_response.status_code,
            status.HTTP_200_OK,
        )

        self.client.force_authenticate(
            user=None
        )

        login_timestamp = activation_timestamp + 60
        login_code = self.code_at(
            login_timestamp
        )

        with patch(
            "users.mfa.time.time",
            return_value=login_timestamp,
        ):
            login_response = self.client.post(
                self.token_url,
                {
                    "username": "mfatest",
                    "password": "TestPassword123!",
                    "code": login_code,
                },
                format="json",
            )

        self.assertEqual(
            login_response.status_code,
            status.HTTP_200_OK,
        )

        self.assertIn(
            "access",
            login_response.data,
        )

        self.assertIn(
            "refresh",
            login_response.data,
        )

    def test_replayed_activation_code_cannot_be_used_for_mfa_login(self):
        self.authenticate()
        self.initialize_mfa()

        timestamp = 1_900_000_000
        code = self.code_at(timestamp)

        with patch(
            "users.mfa.time.time",
            return_value=timestamp,
        ):
            activation_response = self.client.post(
                self.verify_url,
                {"code": code},
                format="json",
            )

        self.assertEqual(
            activation_response.status_code,
            status.HTTP_200_OK,
        )

        self.client.force_authenticate(
            user=None
        )

        with patch(
            "users.mfa.time.time",
            return_value=timestamp,
        ):
            login_response = self.client.post(
                self.token_url,
                {
                    "username": "mfatest",
                    "password": "TestPassword123!",
                    "code": code,
                },
                format="json",
            )

        self.assertEqual(
            login_response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        self.assertIn(
            "code",
            login_response.data,
        )

        self.assertEqual(
            login_response.data["code"][0],
            "MFA code has already been used.",
        )
