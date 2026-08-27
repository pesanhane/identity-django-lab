from django.test import SimpleTestCase

import pyotp

from users.mfa import (
    generate_secret,
    generate_current_code,
    verify_totp_code,
)


class MFATest(SimpleTestCase):

    def test_generate_secret_returns_valid_totp_secret(self):
        secret = generate_secret()

        self.assertIsInstance(secret, str)
        self.assertGreaterEqual(len(secret), 16)

        # Deve ser aceito pelo PyOTP
        pyotp.TOTP(secret)

    def test_current_code_is_valid(self):
        secret = generate_secret()

        code = generate_current_code(secret)

        self.assertIsNotNone(code)
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())

        self.assertTrue(
            verify_totp_code(secret, code)
        )

    def test_invalid_code_is_rejected(self):
        secret = generate_secret()

        self.assertFalse(
            verify_totp_code(secret, "000000")
        )

    def test_empty_code_is_rejected(self):
        secret = generate_secret()

        self.assertFalse(
            verify_totp_code(secret, "")
        )

    def test_missing_secret_is_rejected(self):
        self.assertFalse(
            verify_totp_code("", "123456")
        )

    def test_none_secret_is_rejected(self):
        self.assertFalse(
            verify_totp_code(None, "123456")
        )

    def test_none_code_is_rejected(self):
        secret = generate_secret()

        self.assertFalse(
            verify_totp_code(secret, None)
        )

    def test_wrong_secret_rejects_code(self):
        secret1 = generate_secret()
        secret2 = generate_secret()

        code = generate_current_code(secret1)

        self.assertFalse(
            verify_totp_code(secret2, code)
        )

    def test_code_has_six_digits(self):
        secret = generate_secret()

        code = generate_current_code(secret)

        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())
