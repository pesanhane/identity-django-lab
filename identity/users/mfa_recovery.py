import secrets

from django.contrib.auth.hashers import (
    check_password,
    make_password,
)

from django.db import transaction
from django.utils import timezone

from .models import MFARecoveryCode


RECOVERY_CODE_COUNT = 10


def generate_recovery_code():
    """
    Gera um recovery code criptograficamente seguro.

    Exemplo:
        8F4A-93BD-27E1
    """

    raw = secrets.token_hex(6).upper()

    return (
        f"{raw[:4]}-"
        f"{raw[4:8]}-"
        f"{raw[8:12]}"
    )


def generate_recovery_codes(
    user,
    count=RECOVERY_CODE_COUNT,
):
    """
    Gera um novo conjunto de recovery codes.

    Todos os códigos antigos são invalidados.

    Retorna os códigos em texto puro apenas uma vez.
    No banco ficam somente hashes.
    """

    codes = [
        generate_recovery_code()
        for _ in range(count)
    ]

    with transaction.atomic():

        MFARecoveryCode.objects.filter(
            user=user
        ).delete()

        MFARecoveryCode.objects.bulk_create(
            [
                MFARecoveryCode(
                    user=user,
                    code_hash=make_password(code),
                )
                for code in codes
            ]
        )

    return codes


def verify_and_consume_recovery_code(
    user,
    code,
):
    """
    Verifica um recovery code e marca-o como utilizado.

    Retorna True se o código for válido.

    Um código usado nunca poderá ser reutilizado.
    """

    if not code:
        return False

    normalized_code = str(code).strip().upper()

    with transaction.atomic():

        recovery_codes = (
            MFARecoveryCode.objects
            .select_for_update()
            .filter(
                user=user,
                used_at__isnull=True,
            )
        )

        for recovery_code in recovery_codes:

            if check_password(
                normalized_code,
                recovery_code.code_hash,
            ):
                recovery_code.used_at = timezone.now()

                recovery_code.save(
                    update_fields=[
                        "used_at"
                    ]
                )

                return True

    return False
