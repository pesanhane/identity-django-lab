import re

from django.contrib.auth import get_user_model
from django.test import TestCase

from users.mfa_recovery import (
    RECOVERY_CODE_COUNT,
    generate_recovery_code,
    generate_recovery_codes,
    verify_and_consume_recovery_code,
)
from users.models import MFARecoveryCode


User = get_user_model()


class MFARecoveryCodeTest(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username="recoveryuser",
            email="recovery@example.com",
            password="TestPassword123!",
        )

        self.other_user = User.objects.create_user(
            username="otheruser",
            email="other@example.com",
            password="TestPassword123!",
        )

    # ==========================================================
    # GENERATION
    # ==========================================================

    def test_generate_single_recovery_code_has_expected_format(self):
        code = generate_recovery_code()

        self.assertRegex(
            code,
            r"^[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$",
        )

    def test_generate_recovery_codes_returns_default_number(self):
        codes = generate_recovery_codes(
            self.user
        )

        self.assertEqual(
            len(codes),
            RECOVERY_CODE_COUNT,
        )

        self.assertEqual(
            MFARecoveryCode.objects.filter(
                user=self.user
            ).count(),
            RECOVERY_CODE_COUNT,
        )

    def test_generated_recovery_codes_are_unique(self):
        codes = generate_recovery_codes(
            self.user
        )

        self.assertEqual(
            len(codes),
            len(set(codes)),
        )

    # ==========================================================
    # HASH STORAGE
    # ==========================================================

    def test_plain_recovery_code_is_not_stored_in_database(self):
        codes = generate_recovery_codes(
            self.user
        )

        stored_codes = list(
            MFARecoveryCode.objects.filter(
                user=self.user
            )
        )

        for plain_code in codes:
            for stored_code in stored_codes:
                self.assertNotEqual(
                    plain_code,
                    stored_code.code_hash,
                )

    # ==========================================================
    # VALIDATION
    # ==========================================================

    def test_valid_recovery_code_is_accepted(self):
        codes = generate_recovery_codes(
            self.user
        )

        result = verify_and_consume_recovery_code(
            self.user,
            codes[0],
        )

        self.assertTrue(result)

    def test_invalid_recovery_code_is_rejected(self):
        generate_recovery_codes(
            self.user
        )

        result = verify_and_consume_recovery_code(
            self.user,
            "FFFF-FFFF-FFFF",
        )

        self.assertFalse(result)

    def test_empty_recovery_code_is_rejected(self):
        generate_recovery_codes(
            self.user
        )

        self.assertFalse(
            verify_and_consume_recovery_code(
                self.user,
                "",
            )
        )

    def test_none_recovery_code_is_rejected(self):
        generate_recovery_codes(
            self.user
        )

        self.assertFalse(
            verify_and_consume_recovery_code(
                self.user,
                None,
            )
        )

    # ==========================================================
    # SINGLE USE
    # ==========================================================

    def test_recovery_code_is_marked_as_used(self):
        codes = generate_recovery_codes(
            self.user
        )

        verify_and_consume_recovery_code(
            self.user,
            codes[0],
        )

        recovery_code = (
            MFARecoveryCode.objects
            .filter(
                user=self.user,
                used_at__isnull=False,
            )
            .first()
        )

        self.assertIsNotNone(
            recovery_code
        )

        self.assertIsNotNone(
            recovery_code.used_at
        )

    def test_same_recovery_code_cannot_be_reused(self):
        codes = generate_recovery_codes(
            self.user
        )

        first_result = verify_and_consume_recovery_code(
            self.user,
            codes[0],
        )

        second_result = verify_and_consume_recovery_code(
            self.user,
            codes[0],
        )

        self.assertTrue(
            first_result
        )

        self.assertFalse(
            second_result
        )

    # ==========================================================
    # USER ISOLATION
    # ==========================================================

    def test_recovery_code_cannot_be_used_by_another_user(self):
        codes = generate_recovery_codes(
            self.user
        )

        result = verify_and_consume_recovery_code(
            self.other_user,
            codes[0],
        )

        self.assertFalse(result)

    # ==========================================================
    # REGENERATION
    # ==========================================================

    def test_regeneration_invalidates_old_codes(self):
        old_codes = generate_recovery_codes(
            self.user
        )

        new_codes = generate_recovery_codes(
            self.user
        )

        old_result = verify_and_consume_recovery_code(
            self.user,
            old_codes[0],
        )

        new_result = verify_and_consume_recovery_code(
            self.user,
            new_codes[0],
        )

        self.assertFalse(
            old_result
        )

        self.assertTrue(
            new_result
        )

    def test_regeneration_replaces_old_database_records(self):
        generate_recovery_codes(
            self.user
        )

        first_count = MFARecoveryCode.objects.filter(
            user=self.user
        ).count()

        generate_recovery_codes(
            self.user
        )

        second_count = MFARecoveryCode.objects.filter(
            user=self.user
        ).count()

        self.assertEqual(
            first_count,
            RECOVERY_CODE_COUNT,
        )

        self.assertEqual(
            second_count,
            RECOVERY_CODE_COUNT,
        )
