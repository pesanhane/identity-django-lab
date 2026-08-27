from django.core.cache import cache
from rest_framework.exceptions import Throttled
import os


def check_rate_limit(
    key,
    limit,
    window,
):
    """
    Rate limiter baseado em Redis.

    - window: período de contagem das tentativas.
    - limit: número máximo de tentativas permitidas.
    - RATE_LIMIT_BLOCK: tempo de bloqueio após exceder o limite.

    Levanta HTTP 429 quando o limite é excedido.
    """

    cache_key = f"rate-limit:{key}"
    block_key = f"rate-limit-block:{key}"

    # ==========================================================
    # VERIFICAR BLOQUEIO
    # ==========================================================

    if cache.get(block_key):
        raise Throttled(
            detail="Too many authentication attempts. Try again later."
        )

    # ==========================================================
    # CONTADOR
    # ==========================================================

    try:
        count = cache.incr(cache_key)

    except ValueError:
        cache.set(
            cache_key,
            1,
            timeout=window,
        )

        count = 1

    # ==========================================================
    # DEFINIR EXPIRAÇÃO DO CONTADOR
    # ==========================================================

    if count == 1:
        cache.expire(
            cache_key,
            window,
        )

    # ==========================================================
    # EXCEDEU O LIMITE
    # ==========================================================

    if count > limit:

        block_seconds = int(
            os.getenv(
                "RATE_LIMIT_BLOCK",
                300,
            )
        )

        cache.set(
            block_key,
            True,
            timeout=block_seconds,
        )

        raise Throttled(
            detail="Too many authentication attempts. Try again later."
        )

    return count