
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.test import APITestCase

from users.mfa import generate_secret, generate_current_code


User = get_user_model()


class MFATokenAuthenticationTest(APITestCase):

    def setUp(self):
        cache.clear()

        self.user = User.objects.create_user(
            username="mfatest",
            email="mfatest@example.com",
            password="TestPassword123!",
        )

    def tearDown(self):
        cache.clear()

    def enable_mfa(self):
        self.user.mfa_secret = generate_secret()
        self.user.mfa_enabled = True
        self.user.mfa_last_used_counter = None
        self.user.save(
            update_fields=[
                "mfa_secret",
                "mfa_enabled",
                "mfa_last_used_counter",
            ]
        )

    # ==========================================================
    # MFA ENDPOINT
    # ==========================================================

    def test_login_without_mfa_succeeds(self):
        response = self.client.post(
            "/api/token/mfa/",
            {
                "username": "mfatest",
                "password": "TestPassword123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_login_with_mfa_valid_code_succeeds(self):
        self.enable_mfa()

        code = generate_current_code(self.user.mfa_secret)

        response = self.client.post(
            "/api/token/mfa/",
            {
                "username": "mfatest",
                "password": "TestPassword123!",
                "code": code,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_login_with_mfa_without_code_fails(self):
        self.enable_mfa()

        response = self.client.post(
            "/api/token/mfa/",
            {
                "username": "mfatest",
                "password": "TestPassword123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("code", response.data)
        self.assertEqual(
            response.data["code"][0],
            "MFA code is required.",
        )

    def test_login_with_mfa_empty_code_fails(self):
        self.enable_mfa()

        response = self.client.post(
            "/api/token/mfa/",
            {
                "username": "mfatest",
                "password": "TestPassword123!",
                "code": "",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("code", response.data)

    def test_login_with_mfa_invalid_code_fails(self):
        self.enable_mfa()

        response = self.client.post(
            "/api/token/mfa/",
            {
                "username": "mfatest",
                "password": "TestPassword123!",
                "code": "000000",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("code", response.data)
        self.assertEqual(
            response.data["code"][0],
            "Invalid MFA code.",
        )

    def test_login_with_mfa_malformed_code_fails(self):
        self.enable_mfa()

        invalid_codes = [
            "12345",
            "1234567",
            "abcdef",
            "12ab56",
        ]

        for code in invalid_codes:
            with self.subTest(code=code):
                response = self.client.post(
                    "/api/token/mfa/",
                    {
                        "username": "mfatest",
                        "password": "TestPassword123!",
                        "code": code,
                    },
                    format="json",
                )

                self.assertEqual(response.status_code, 400)
                self.assertIn("code", response.data)

    # ==========================================================
    # PASSWORD SECURITY
    # ==========================================================

    def test_login_with_mfa_wrong_password_fails(self):
        self.enable_mfa()

        code = generate_current_code(self.user.mfa_secret)

        response = self.client.post(
            "/api/token/mfa/",
            {
                "username": "mfatest",
                "password": "WrongPassword123!",
                "code": code,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 401)

    def test_login_with_mfa_correct_password_but_wrong_code_fails(self):
        self.enable_mfa()

        response = self.client.post(
            "/api/token/mfa/",
            {
                "username": "mfatest",
                "password": "TestPassword123!",
                "code": "000000",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("code", response.data)

    # ==========================================================
    # USER ENUMERATION / INVALID USERS
    # ==========================================================

    def test_login_with_nonexistent_user_fails(self):
        response = self.client.post(
            "/api/token/mfa/",
            {
                "username": "doesnotexist",
                "password": "TestPassword123!",
                "code": "123456",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 401)

    # ==========================================================
    # NORMAL LOGIN MUST NOT BYPASS MFA
    # ==========================================================

    def test_normal_login_cannot_bypass_mfa(self):
        self.enable_mfa()

        response = self.client.post(
            "/api/token/",
            {
                "username": "mfatest",
                "password": "TestPassword123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("code", response.data)
        self.assertEqual(
            response.data["code"][0],
            "MFA is enabled for this account. Use the MFA login endpoint.",
        )

    def test_normal_login_with_mfa_code_still_fails(self):
        self.enable_mfa()

        code = generate_current_code(self.user.mfa_secret)

        response = self.client.post(
            "/api/token/",
            {
                "username": "mfatest",
                "password": "TestPassword123!",
                "code": code,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)

    # ==========================================================
    # MFA STATE
    # ==========================================================

    def test_disabled_mfa_does_not_require_code(self):
        self.user.mfa_enabled = False
        self.user.mfa_secret = generate_secret()
        self.user.save(update_fields=["mfa_enabled", "mfa_secret"])

        response = self.client.post(
            "/api/token/mfa/",
            {
                "username": "mfatest",
                "password": "TestPassword123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_mfa_enabled_without_secret_cannot_authenticate(self):
        self.user.mfa_enabled = True
        self.user.mfa_secret = ""
        self.user.save(update_fields=["mfa_enabled", "mfa_secret"])

        response = self.client.post(
            "/api/token/mfa/",
            {
                "username": "mfatest",
                "password": "TestPassword123!",
                "code": "123456",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("code", response.data)

    # ==========================================================
    # TOKEN STRUCTURE
    # ==========================================================

    def test_valid_mfa_login_returns_access_and_refresh_tokens(self):
        self.enable_mfa()

        code = generate_current_code(self.user.mfa_secret)

        response = self.client.post(
            "/api/token/mfa/",
            {
                "username": "mfatest",
                "password": "TestPassword123!",
                "code": code,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)

        access = response.data["access"]
        refresh = response.data["refresh"]

        self.assertIsInstance(access, str)
        self.assertIsInstance(refresh, str)

        self.assertGreater(len(access), 20)
        self.assertGreater(len(refresh), 20)

    # ==========================================================
    # HTTP METHOD
    # ==========================================================

    def test_mfa_endpoint_rejects_get(self):
        response = self.client.get("/api/token/mfa/")

        self.assertEqual(response.status_code, 405)

    # ==========================================================
    # MFA ANTI-REPLAY
    # ==========================================================

    def test_same_mfa_code_cannot_be_reused(self):
        self.enable_mfa()

        code = generate_current_code(self.user.mfa_secret)

        first_response = self.client.post(
            "/api/token/mfa/",
            {
                "username": "mfatest",
                "password": "TestPassword123!",
                "code": code,
            },
            format="json",
        )

        self.assertEqual(first_response.status_code, 200)

        second_response = self.client.post(
            "/api/token/mfa/",
            {
                "username": "mfatest",
                "password": "TestPassword123!",
                "code": code,
            },
            format="json",
        )

        self.assertEqual(second_response.status_code, 400)
        self.assertIn("code", second_response.data)
        self.assertEqual(
            second_response.data["code"][0],
            "MFA code has already been used.",
        )

    def test_mfa_counter_is_stored_after_successful_login(self):
        self.enable_mfa()

        code = generate_current_code(self.user.mfa_secret)

        response = self.client.post(
            "/api/token/mfa/",
            {
                "username": "mfatest",
                "password": "TestPassword123!",
                "code": code,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)

        self.user.refresh_from_db()

        self.assertIsNotNone(
            self.user.mfa_last_used_counter
        )

    def test_replayed_mfa_code_does_not_issue_tokens(self):
        self.enable_mfa()

        code = generate_current_code(self.user.mfa_secret)

        first_response = self.client.post(
            "/api/token/mfa/",
            {
                "username": "mfatest",
                "password": "TestPassword123!",
                "code": code,
            },
            format="json",
        )

        self.assertEqual(first_response.status_code, 200)
        self.assertIn("access", first_response.data)
        self.assertIn("refresh", first_response.data)

        second_response = self.client.post(
            "/api/token/mfa/",
            {
                "username": "mfatest",
                "password": "TestPassword123!",
                "code": code,
            },
            format="json",
        )

        self.assertEqual(second_response.status_code, 400)
        self.assertNotIn("access", second_response.data)
        self.assertNotIn("refresh", second_response.data)
