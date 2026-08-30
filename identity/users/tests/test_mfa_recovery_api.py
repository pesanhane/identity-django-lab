
import os
import pyotp

from unittest.mock import patch
from django.core.cache import cache
from rest_framework.test import APITestCase


from users.models import (
    User,
    Organization,
    AuditLog,
    MFARecoveryCode,
)
from users.mfa import (
    generate_secret,
    verify_totp_code_with_counter,
)

from users.mfa_recovery import (
    generate_recovery_codes,
    verify_and_consume_recovery_code,
    
)


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
        self.mfa_disable_url = (
            "/api/users/me/mfa/disable/"
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

        # ==========================================================
        # AUTENTICAR ANTES DE ATIVAR MFA
        # ==========================================================

        self.authenticate()

        # ==========================================================
        # ATIVAR MFA
        # ==========================================================

        self.enable_mfa()

        # ==========================================================
        # PRIMEIRO CONJUNTO DE RECOVERY CODES
        # ==========================================================

        old_codes = generate_recovery_codes(
            self.user
        )

        old_code = old_codes[0]

        self.assertEqual(
            MFARecoveryCode.objects.filter(
                user=self.user
            ).count(),
            10,
        )

        # ==========================================================
        # GERAR TOTP VÁLIDO
        # ==========================================================

        totp_code = self.current_totp_code()

        # ==========================================================
        # REGENERAR VIA API COM REAUTENTICAÇÃO FORTE
        # ==========================================================

        response = self.client.post(
            self.recovery_codes_url,
            {
                "password": "TestPassword123!",
                "code": totp_code,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        # ==========================================================
        # NOVO CONJUNTO
        # ==========================================================

        new_codes = response.data[
            "recovery_codes"
        ]

        self.assertEqual(
            len(new_codes),
            10,
        )

        self.assertNotEqual(
            old_codes,
            new_codes,
        )

        # ==========================================================
        # CÓDIGO ANTIGO DEVE ESTAR INVALIDADO
        # ==========================================================

        self.assertFalse(
            verify_and_consume_recovery_code(
                self.user,
                old_code,
            )
        )

        # ==========================================================
        # NOVO CÓDIGO DEVE FUNCIONAR
        # ==========================================================

        self.assertTrue(
            verify_and_consume_recovery_code(
                self.user,
                new_codes[0],
            )
        )

        # ==========================================================
        # BANCO CONTINUA COM APENAS 10 CÓDIGOS
        # ==========================================================

        self.assertEqual(
            MFARecoveryCode.objects.filter(
                user=self.user
            ).count(),
            10,
        )
        # ==========================================================
    # RECOVERY LOGIN AUDIT
    # ==========================================================

    def test_successful_recovery_login_is_audited(self):
        self.authenticate()
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
    
    def current_totp_code(self):

        self.user.refresh_from_db()

        return pyotp.TOTP(
            self.user.mfa_secret
        ).now()

    
    def test_regeneration_requires_current_password(self):

        self.authenticate()
        self.enable_mfa()

        generate_recovery_codes(
            self.user
        )

        response = self.client.post(
            self.recovery_codes_url,
            {
                "code": self.current_totp_code(),
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            400,
            response.data,
        )

        self.assertIn(
            "password",
            response.data,
        )

    def test_regeneration_requires_totp_code(self):

        self.authenticate()
        self.enable_mfa()

        generate_recovery_codes(
            self.user
        )

        response = self.client.post(
            self.recovery_codes_url,
            {
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
    def test_regeneration_rejects_wrong_password(self):

        self.authenticate()
        self.enable_mfa()

        generate_recovery_codes(
            self.user
        )

        response = self.client.post(
            self.recovery_codes_url,
            {
                "password": "WrongPassword123!",
                "code": self.current_totp_code(),
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            400,
            response.data,
        )

        self.assertIn(
            "password",
            response.data,
        )

    def test_regeneration_rejects_invalid_totp(self):

        self.authenticate()
        self.enable_mfa()

        generate_recovery_codes(
            self.user
        )

        response = self.client.post(
            self.recovery_codes_url,
            {
                "password": "TestPassword123!",
                "code": "000000",
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
    def test_regeneration_with_password_and_totp_succeeds(self):

        self.authenticate()
        self.enable_mfa()

        old_codes = generate_recovery_codes(
            self.user
        )

        code = self.current_totp_code()

        response = self.client.post(
            self.recovery_codes_url,
            {
                "password": "TestPassword123!",
                "code": code,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        self.assertEqual(
            len(
                response.data[
                    "recovery_codes"
                ]
            ),
            10,
        )

        new_codes = response.data[
            "recovery_codes"
        ]

        self.assertNotEqual(
            old_codes,
            new_codes,
        )

    def test_successful_recovery_regeneration_is_audited(self):

        self.authenticate()
        self.enable_mfa()

        generate_recovery_codes(
            self.user
        )

        response = self.client.post(
            self.recovery_codes_url,
            {
                "password": "TestPassword123!",
                "code": self.current_totp_code(),
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        reauth_audit = AuditLog.objects.filter(
            user=self.user,
            action="MFA_RECOVERY_REAUTH_SUCCESS",
        ).first()

        self.assertIsNotNone(
            reauth_audit
        )

        regeneration_audit = AuditLog.objects.filter(
            user=self.user,
            action="MFA_RECOVERY_CODES_REGENERATED",
        ).first()

        self.assertIsNotNone(
            regeneration_audit
        )
    def test_mfa_can_be_disabled_with_password_and_totp(self):

        self.authenticate()
        self.enable_mfa()

        generate_recovery_codes(
            self.user
        )

        code = self.current_totp_code()

        response = self.client.post(
            self.mfa_disable_url,
            {
                "password": "TestPassword123!",
                "code": code,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        self.user.refresh_from_db()

        self.assertFalse(
            self.user.mfa_enabled
        )

        self.assertIsNone(
            self.user.mfa_secret
        )

        self.assertIsNone(
            self.user.mfa_verified_at
        )

        self.assertIsNone(
            self.user.mfa_last_used_counter
        )

        self.assertEqual(
            MFARecoveryCode.objects.filter(
                user=self.user
            ).count(),
            0,
        )
    def test_mfa_disable_rejects_wrong_password(self):

        self.authenticate()
        self.enable_mfa()

        response = self.client.post(
            self.mfa_disable_url,
            {
                "password": "WrongPassword123!",
                "code": self.current_totp_code(),
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            400,
            response.data,
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.mfa_enabled
        )

    def test_mfa_disable_rejects_invalid_totp(self):

        self.authenticate()
        self.enable_mfa()

        response = self.client.post(
            self.mfa_disable_url,
            {
                "password": "TestPassword123!",
                "code": "000000",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            400,
            response.data,
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.mfa_enabled
        )

    def test_mfa_disable_requires_password(self):

        self.authenticate()
        self.enable_mfa()

        response = self.client.post(
            self.mfa_disable_url,
            {
                "code": self.current_totp_code(),
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            400,
            response.data,
        )

        self.assertIn(
            "password",
            response.data,
        )
    def test_mfa_disable_requires_totp(self):

        self.authenticate()
        self.enable_mfa()

        response = self.client.post(
            self.mfa_disable_url,
            {
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

    def test_mfa_disable_requires_authentication(self):

        self.enable_mfa()

        response = self.client.post(
            self.mfa_disable_url,
            {
                "password": "TestPassword123!",
                "code": self.current_totp_code(),
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            401,
            response.data,
        )
    def test_successful_mfa_disable_is_audited(self):

        self.authenticate()
        self.enable_mfa()

        response = self.client.post(
            self.mfa_disable_url,
            {
                "password": "TestPassword123!",
                "code": self.current_totp_code(),
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
            action="MFA_DISABLED",
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
    def test_mfa_disable_rejects_replayed_totp(self):

        self.authenticate()
        self.enable_mfa()

        code = self.current_totp_code()

        # Primeiro consumo do TOTP:
        # simulamos que este código já foi usado anteriormente.
        self.user.refresh_from_db()

        counter = verify_totp_code_with_counter(
            self.user.mfa_secret,
            code,
        )

        self.assertIsNotNone(
            counter
        )

        self.user.mfa_last_used_counter = counter
        self.user.save(
            update_fields=[
                "mfa_last_used_counter"
            ]
        )

        # Tentativa de reutilizar exatamente o mesmo TOTP
        response = self.client.post(
            self.mfa_disable_url,
            {
                "password": "TestPassword123!",
                "code": code,
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

        self.user.refresh_from_db()

        # MFA deve continuar ativo
        self.assertTrue(
            self.user.mfa_enabled
        )

        # O secret também não pode ter sido apagado
        self.assertIsNotNone(
            self.user.mfa_secret
        )

        # Deve existir auditoria específica de replay
        audit = AuditLog.objects.filter(
            user=self.user,
            action="MFA_DISABLE_REPLAY_DETECTED",
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
    def test_mfa_disable_rate_limit_returns_429(self):

        self.authenticate()
        self.enable_mfa()

        payload = {
            "password": "WrongPassword123!",
            "code": self.current_totp_code(),
        }

        response1 = self.client.post(
            self.mfa_disable_url,
            payload,
            format="json",
        )

        self.assertEqual(
            response1.status_code,
            400,
            response1.data,
        )

        response2 = self.client.post(
            self.mfa_disable_url,
            payload,
            format="json",
        )

        self.assertEqual(
            response2.status_code,
            400,
            response2.data,
        )

        response3 = self.client.post(
            self.mfa_disable_url,
            payload,
            format="json",
        )

        self.assertEqual(
            response3.status_code,
            429,
            response3.data,
        )

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.mfa_enabled
        )

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
    def test_rate_limited_mfa_disable_is_audited(self):

        self.authenticate()
        self.enable_mfa()

        payload = {
            "password": "WrongPassword123!",
            "code": self.current_totp_code(),
        }

        self.client.post(
            self.mfa_disable_url,
            payload,
            format="json",
        )

        self.client.post(
            self.mfa_disable_url,
            payload,
            format="json",
        )

        response = self.client.post(
            self.mfa_disable_url,
            payload,
            format="json",
        )

        self.assertEqual(
            response.status_code,
            429,
            response.data,
        )

        audit = AuditLog.objects.filter(
            user=self.user,
            action="MFA_DISABLE_RATE_LIMITED",
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
            429,
        )

        self.assertEqual(
            audit.endpoint,
            self.mfa_disable_url,
        )