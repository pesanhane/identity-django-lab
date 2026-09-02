
import re
from datetime import datetime, timezone as dt_timezone

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import (
    OutstandingToken,
    BlacklistedToken,
)

from django.db import transaction
from django.utils import timezone

from .models import (
    UserSession,
    AuditLog,
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

    user_agent = request.META.get(
        "HTTP_USER_AGENT",
        "",
    )

    if not user_agent:
        return "Unknown device"

    browser = get_browser_name(
        user_agent
    )

    operating_system = get_operating_system(
        user_agent
    )

    return (
        f"{browser} • {operating_system}"
    )[:255]


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

    create_session_audit(
        request=request,
        user=user,
        action="SESSION_CREATED",
        description=(
            "Nova sessão de utilizador criada."
        ),
        status_code=200,
        result="SUCCESS",
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


def create_session_audit(
    *,
    request,
    user,
    action,
    description,
    status_code=200,
    result="SUCCESS",
):
    """
    Cria auditoria de eventos relacionados
    com sessões.

    Contas sem organização continuam funcionais,
    mas não geram AuditLog porque AuditLog exige
    organization.
    """

    organization = getattr(
        user,
        "organization",
        None,
    )

    if organization is None:
        return None

    return AuditLog.objects.create(
        organization=organization,
        user=user,
        action=action,
        description=description,
        ip_address=get_client_ip(request),
        http_method=request.method,
        endpoint=request.path,
        user_agent=request.META.get(
            "HTTP_USER_AGENT",
            "",
        ),
        status_code=status_code,
        result=result,
    )


@transaction.atomic
def revoke_user_session(
    *,
    session,
):
    """
    Revoga uma UserSession de forma idempotente.

    Faz:
        1. lock da sessão;
        2. blacklist do refresh token;
        3. define revoked_at.

    Retorna True se a sessão foi revogada nesta chamada.
    Retorna False se já estava revogada.
    """

    locked_session = (
        UserSession.objects
        .select_for_update()
        .get(pk=session.pk)
    )

    if locked_session.revoked_at is not None:
        return False

    blacklist_user_session(
        locked_session
    )

    locked_session.revoked_at = (
        timezone.now()
    )

    locked_session.save(
        update_fields=[
            "revoked_at"
        ]
    )

    return True


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


def get_browser_name(user_agent):

    # ============================================================
    # MICROSOFT EDGE
    # ============================================================

    match = re.search(
        r"Edg/([\d.]+)",
        user_agent,
    )

    if match:

        version = match.group(1).split(".")[0]

        return f"Edge {version}"

    # ============================================================
    # GOOGLE CHROME
    # ============================================================

    match = re.search(
        r"Chrome/([\d.]+)",
        user_agent,
    )

    if match:

        version = match.group(1).split(".")[0]

        return f"Chrome {version}"

    # ============================================================
    # FIREFOX
    # ============================================================

    match = re.search(
        r"Firefox/([\d.]+)",
        user_agent,
    )

    if match:

        version = match.group(1).split(".")[0]

        return f"Firefox {version}"

    # ============================================================
    # SAFARI
    # ============================================================

    if (
        "Safari/" in user_agent
        and "Version/" in user_agent
    ):

        match = re.search(
            r"Version/([\d.]+)",
            user_agent,
        )

        if match:

            version = (
                match.group(1)
                .split(".")[0]
            )

            return f"Safari {version}"

        return "Safari"

    return "Unknown browser"



def get_operating_system(user_agent):

    # ============================================================
    # ANDROID
    # ============================================================

    if "Android" in user_agent:

        match = re.search(
            r"Android ([\d.]+)",
            user_agent,
        )

        if match:

            return (
                f"Android "
                f"{match.group(1)}"
            )

        return "Android"

    # ============================================================
    # IPHONE / IPAD
    # ============================================================

    if (
        "iPhone" in user_agent
        or "iPad" in user_agent
    ):

        match = re.search(
            r"OS ([\d_]+)",
            user_agent,
        )

        if match:

            version = (
                match.group(1)
                .replace("_", ".")
            )

            return f"iOS {version}"

        return "iOS"

    # ============================================================
    # WINDOWS
    # ============================================================

    if "Windows NT 10.0" in user_agent:
        return "Windows"

    if "Windows NT 6.3" in user_agent:
        return "Windows 8.1"

    if "Windows NT 6.1" in user_agent:
        return "Windows 7"

    # ============================================================
    # MACOS
    # ============================================================

    if "Mac OS X" in user_agent:

        match = re.search(
            r"Mac OS X ([\d_]+)",
            user_agent,
        )

        if match:

            version = (
                match.group(1)
                .replace("_", ".")
            )

            return f"macOS {version}"

        return "macOS"

    # ============================================================
    # LINUX
    # ============================================================

    if "Ubuntu" in user_agent:
        return "Ubuntu/Linux"

    if "Linux" in user_agent:
        return "Linux"

    return "Unknown OS"
