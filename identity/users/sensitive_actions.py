from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from rest_framework.exceptions import (
    PermissionDenied,
)

from .models import UserSession

from .session_management import (
    create_session_audit,
)


def has_recent_step_up(
    session,
):
    """
    Verifica se a sessão realizou step-up
    recentemente.
    """

    if session.step_up_verified_at is None:
        return False

    max_age_seconds = getattr(
        settings,
        "SESSION_STEP_UP_MAX_AGE",
        600,
    )

    threshold = (
        timezone.now()
        - timedelta(
            seconds=max_age_seconds
        )
    )

    return (
        session.step_up_verified_at
        >= threshold
    )


def get_request_session(
    request,
):
    """
    Obtém a UserSession associada
    ao access token atual.
    """

    auth = getattr(
        request,
        "auth",
        None,
    )

    if auth is None:
        return None

    session_id = auth.get(
        "session_id"
    )

    if not session_id:
        return None

    try:

        return UserSession.objects.get(
            id=session_id,
            user=request.user,
        )

    except (
        UserSession.DoesNotExist,
        ValueError,
    ):
        return None



def require_recent_step_up(
    *,
    request,
    action,
):
    """
    Exige step-up MFA recente antes
    de uma operação sensível.

    Retorna a sessão quando a
    autorização é válida.

    Caso contrário:
        - marca requires_step_up=True
        - audita
        - responde HTTP 403
    """

    session = get_request_session(
        request
    )

    if session is None:

        raise PermissionDenied(
            {
                "detail": (
                    "A session-bound token is "
                    "required for this operation."
                ),
                "code": "session_required",
            }
        )

    # --------------------------------------------------------
    # MFA obrigatório
    # --------------------------------------------------------

    if not request.user.mfa_enabled:

        raise PermissionDenied(
            {
                "detail": (
                    "MFA must be enabled before "
                    "performing this sensitive "
                    "operation."
                ),
                "code": "mfa_required",
            }
        )

    # --------------------------------------------------------
    # Step-up recente ainda válido
    # --------------------------------------------------------

    if has_recent_step_up(
        session
    ):

        return session

    # --------------------------------------------------------
    # Persistir exigência de step-up
    # --------------------------------------------------------

    with transaction.atomic():

        session = (
            UserSession.objects
            .select_for_update()
            .get(pk=session.pk)
        )

        # Pode ter sido atualizado por outra request
        # enquanto aguardávamos pelo lock.
        if has_recent_step_up(
            session
        ):
            return session

        if not session.requires_step_up:

            session.requires_step_up = True
            session.step_up_required_at = (
                timezone.now()
            )

            session.save(
                update_fields=[
                    "requires_step_up",
                    "step_up_required_at",
                ]
            )

            create_session_audit(
                request=request,
                user=request.user,
                action=(
                    "SENSITIVE_ACTION_STEP_UP_REQUIRED"
                ),
                description=(
                    "Recent step-up authentication "
                    "is required before sensitive "
                    f"operation: {action}."
                ),
                status_code=403,
                result="WARNING",
            )

    # IMPORTANTE:
    # lançar a exceção DEPOIS da transação terminar.
    raise PermissionDenied(
        {
            "detail": (
                "Recent step-up authentication "
                "is required."
            ),
            "code": "step_up_required",
            "action": action,
        }
    )