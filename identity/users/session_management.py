
from datetime import datetime, timezone as dt_timezone

from .models import UserSession
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import (
    OutstandingToken,
    BlacklistedToken,
)


def get_client_ip(request):
    """
    Obtém o IP do cliente.

    Não confiar cegamente em X-Forwarded-For em produção
    sem configuração correta de trusted proxies.
    """

    x_forwarded_for = request.META.get(
        "HTTP_X_FORWARDED_FOR"
    )

    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()

    return request.META.get("REMOTE_ADDR")


def get_device_name(request):
    """
    Identificação simples do dispositivo baseada
    no User-Agent.

    Não é usada como mecanismo de segurança.
    """

    user_agent = request.META.get(
        "HTTP_USER_AGENT",
        "",
    )

    if not user_agent:
        return "Unknown device"

    return user_agent[:255]


def create_user_session(
    *,
    user,
    refresh_token,
    request,
):
    """
    Cria uma sessão associada ao refresh token.

    Nunca armazena o token JWT em texto simples.
    """

    jti = str(
        refresh_token["jti"]
    )

    exp = int(
        refresh_token["exp"]
    )

    expires_at = datetime.fromtimestamp(
        exp,
        tz=dt_timezone.utc,
    )

    session = UserSession.objects.create(
        user=user,
        jti=jti,
        device_name=get_device_name(request),
        user_agent=request.META.get(
            "HTTP_USER_AGENT",
            "",
        ),
        ip_address=get_client_ip(request),
        expires_at=expires_at,
    )

    return session

def create_session_token_pair(
    *,
    user,
    session,
):
    refresh = RefreshToken.for_user(user)

    refresh["session_id"] = str(session.id)

    access = refresh.access_token
    access["session_id"] = str(session.id)

    return {
        "refresh": str(refresh),
        "access": str(access),
    }


def create_session_tokens(
    *,
    user,
    request,
):
    refresh = RefreshToken.for_user(user)

    session = create_user_session(
        user=user,
        refresh_token=refresh,
        request=request,
    )

    refresh["session_id"] = str(session.id)

    access = refresh.access_token
    access["session_id"] = str(session.id)

    return {
        "refresh": str(refresh),
        "access": str(access),
    }


def attach_session_to_token_data(
    *,
    user,
    request,
    data,
):
    refresh = RefreshToken(
        data["refresh"]
    )

    session = create_user_session(
        user=user,
        refresh_token=refresh,
        request=request,
    )

    refresh["session_id"] = str(session.id)

    access = refresh.access_token

    data["refresh"] = str(refresh)
    data["access"] = str(access)

    return data

def blacklist_user_session(session):

    outstanding_token = (
        OutstandingToken.objects
        .filter(
            jti=session.jti
        )
        .first()
    )

    if outstanding_token is None:
        return False

    BlacklistedToken.objects.get_or_create(
        token=outstanding_token
    )

    return True
