from django.core.cache import cache
from django.test import TestCase
from rest_framework.exceptions import Throttled

from users.rate_limit import check_rate_limit


class RateLimitTest(TestCase):

    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    # ==========================================================
    # BASIC RATE LIMIT
    # ==========================================================

    def test_requests_under_limit_are_allowed(self):
        for i in range(1, 6):
            count = check_rate_limit(
                key="test-user",
                limit=5,
                window=60,
            )

            self.assertEqual(count, i)

    # ==========================================================
    # LIMIT
    # ==========================================================

    def test_request_over_limit_is_blocked(self):
        for _ in range(5):
            check_rate_limit(
                key="test-user",
                limit=5,
                window=60,
            )

        with self.assertRaises(Throttled):
            check_rate_limit(
                key="test-user",
                limit=5,
                window=60,
            )

    # ==========================================================
    # DIFFERENT KEYS
    # ==========================================================

    def test_different_keys_have_independent_limits(self):
        for _ in range(5):
            check_rate_limit(
                key="user-a",
                limit=5,
                window=60,
            )

        count = check_rate_limit(
            key="user-b",
            limit=5,
            window=60,
        )

        self.assertEqual(count, 1)

    # ==========================================================
    # REDIS CACHE
    # ==========================================================

    def test_rate_limit_uses_cache(self):
        check_rate_limit(
            key="redis-test",
            limit=5,
            window=60,
        )

        self.assertEqual(
            cache.get("rate-limit:redis-test"),
            1,
        )


        # ==========================================================
    # TEMPORARY BLOCK
    # ==========================================================

    def test_rate_limit_creates_temporary_block(self):
        for _ in range(5):
            check_rate_limit(
                key="blocked-user",
                limit=5,
                window=60,
            )

        with self.assertRaises(Throttled):
            check_rate_limit(
                key="blocked-user",
                limit=5,
                window=60,
            )

        self.assertTrue(
            cache.get(
                "rate-limit-block:blocked-user"
            )
        )

    # ==========================================================
    # BLOCK IS INDEPENDENT
    # ==========================================================

    def test_block_is_independent_between_keys(self):
        for _ in range(5):
            check_rate_limit(
                key="blocked-user-a",
                limit=5,
                window=60,
            )

        with self.assertRaises(Throttled):
            check_rate_limit(
                key="blocked-user-a",
                limit=5,
                window=60,
            )

        count = check_rate_limit(
            key="blocked-user-b",
            limit=5,
            window=60,
        )

        self.assertEqual(count, 1)

    # ==========================================================
    # BLOCK PREVENTS FURTHER REQUESTS
    # ==========================================================

    def test_block_prevents_further_requests(self):
        for _ in range(5):
            check_rate_limit(
                key="blocked-user",
                limit=5,
                window=60,
            )

        with self.assertRaises(Throttled):
            check_rate_limit(
                key="blocked-user",
                limit=5,
                window=60,
            )

        with self.assertRaises(Throttled):
            check_rate_limit(
                key="blocked-user",
                limit=5,
                window=60,
            )
