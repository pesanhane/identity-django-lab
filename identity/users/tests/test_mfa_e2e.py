import pyotp
import time

from unittest.mock import patch


from django.test import override_settings
from rest_framework.test import APITestCase

from users.models import User, Organization


class MFAEndToEndTest(APITestCase):

    def setUp(self):

        self.organization = Organization.objects.create(
            name="E2E MFA Organization"
        )

        self.user = User.objects.create_user(
            username="mfa_e2e",
            email="mfa_e2e@example.com",
            password="TestPassword123!",
            organization=self.organization,
        )

        self.token_url = "/api/token/"
        self.mfa_token_url = "/api/token/mfa/"
        self.setup_url = "/api/users/me/mfa/setup/"
        self.verify_url = "/api/users/me/mfa/verify/"
        self.me_url = "/api/users/me/"

    # ==========================================================
    # STEP 1 - NORMAL LOGIN
    # ==========================================================

    def test_complete_mfa_flow(self):

        # ------------------------------------------------------
        # 1. Login normal
        # ------------------------------------------------------

        response = self.client.post(
            self.token_url,
            {
                "username": "mfa_e2e",
                "password": "TestPassword123!",
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

        access_token = response.data["access"]

        # ------------------------------------------------------
        # 2. Usar JWT real
        # ------------------------------------------------------

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {access_token}"
        )

        response = self.client.get(
            self.me_url
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        # ------------------------------------------------------
        # 3. MFA setup
        # ------------------------------------------------------

        response = self.client.get(
            self.setup_url
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        self.assertIn(
            "otpauth_uri",
            response.data,
        )

        otpauth_uri = response.data["otpauth_uri"]

        self.assertTrue(
            otpauth_uri.startswith(
                "otpauth://totp/"
            )
        )

        # ------------------------------------------------------
        # 4. Recuperar secret criado
        # ------------------------------------------------------

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.mfa_secret
        )

        self.assertFalse(
            self.user.mfa_enabled
        )

        # ------------------------------------------------------
        # 5. Gerar código TOTP
        # ------------------------------------------------------

        totp = pyotp.TOTP(
            self.user.mfa_secret
        )

        activation_counter = int(time.time()) // 30

        activation_code = totp.at(
            activation_counter * 30
        )

        self.assertEqual(
            len(activation_code),
            6,
        )

        self.assertTrue(
            activation_code.isdigit()
        )

        # ------------------------------------------------------
        # 6. Ativar MFA
        # ------------------------------------------------------

        response = self.client.post(
            self.verify_url,
            {
                "code": activation_code,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        self.assertTrue(
            response.data["mfa_enabled"]
        )

        # ------------------------------------------------------
        # 7. Confirmar estado persistido
        # ------------------------------------------------------

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

        # ------------------------------------------------------
        # 8. Remover autenticação atual
        # ------------------------------------------------------

        self.client.credentials()

        # ------------------------------------------------------
        # 9. Login normal deve ser bloqueado
        # ------------------------------------------------------

        response = self.client.post(
            self.token_url,
            {
                "username": "mfa_e2e",
                "password": "TestPassword123!",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            400,
            response.data,
        )

        self.assertIn(
            "code",
            response.data,
        )

        # ------------------------------------------------------
        # 10. Gerar novo código TOTP
        # ------------------------------------------------------

        self.user.refresh_from_db()

        #
        # O counter utilizado na ativação foi armazenado pelo
        # próprio MFAVerifyView.
        #

        activation_counter = (
            self.user.mfa_last_used_counter
        )

        self.assertIsNotNone(
            activation_counter
        )

        #
        # O próximo counter representa o próximo código TOTP.
        #

        login_counter = activation_counter + 1

        new_code = totp.at(
            login_counter * 30
        )

        self.assertEqual(
            len(new_code),
            6,
        )

        self.assertTrue(
            new_code.isdigit()
        )

        self.assertNotEqual(
            new_code,
            activation_code,
        )

        # ------------------------------------------------------
        # 11. Login MFA
        # ------------------------------------------------------

        #
        # O código do próximo counter deve ser aceito porque
        # verify_totp_code_with_counter() possui janela de
        # tolerância de ±1 intervalo.
        #
        # Para tornar o teste determinístico, simulamos o relógio
        # no próximo intervalo TOTP.
        #

        fake_time = login_counter * 30

        with patch(
            "users.mfa.time.time",
            return_value=fake_time,
        ):

            response = self.client.post(
                self.mfa_token_url,
                {
                    "username": "mfa_e2e",
                    "password": "TestPassword123!",
                    "code": new_code,
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

        # ------------------------------------------------------
        # 12. Guardar novo access token
        # ------------------------------------------------------

        mfa_access_token = response.data["access"]

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {mfa_access_token}"
        )

        response = self.client.get(
            self.me_url
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        self.assertEqual(
            response.data["username"],
            "mfa_e2e",
        )

    # ==========================================================
    # REPLAY
    # ==========================================================

    def test_activation_code_cannot_be_reused_for_login(self):

        # Login normal
        response = self.client.post(
            self.token_url,
            {
                "username": "mfa_e2e",
                "password": "TestPassword123!",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        access_token = response.data["access"]

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {access_token}"
        )

        # Setup
        response = self.client.get(
            self.setup_url
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        self.user.refresh_from_db()

        # Código utilizado para ativação
        activation_code = pyotp.TOTP(
            self.user.mfa_secret
        ).at((int(time.time()) // 30 + 1) * 30)

        # Ativar MFA
        response = self.client.post(
            self.verify_url,
            {
                "code": activation_code,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        # Remover JWT
        self.client.credentials()

        # Tentar reutilizar exatamente o mesmo código
        response = self.client.post(
            self.mfa_token_url,
            {
                "username": "mfa_e2e",
                "password": "TestPassword123!",
                "code": activation_code,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            400,
            response.data,
        )

        self.assertIn(
            "code",
            response.data,
        )

        self.assertEqual(
            response.data["code"][0],
            "MFA code has already been used.",
        )
