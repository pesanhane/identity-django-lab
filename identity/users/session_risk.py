from django.core.cache import cache
from dataclasses import dataclass
from .session_management import (
    create_session_audit,
)
from .session_management import (
    get_client_ip,
    get_browser_name,
    get_operating_system,
)


@dataclass(frozen=True)
class SessionRiskResult:
    score: int
    level: str
    ip_changed: bool
    device_changed: bool
    current_ip: str | None
    current_device: str
    reasons: tuple[str, ...]


def get_device_signature(request):

    user_agent = request.META.get(
        "HTTP_USER_AGENT",
        "",
    )

    if not user_agent:
        return "Unknown"

    browser = get_browser_name(
        user_agent
    )

    operating_system = get_operating_system(
        user_agent
    )

    # ------------------------------------------------------------
    # Ignore browser/OS version numbers for anomaly detection.
    #
    # Firefox 153 -> Firefox
    # Chrome 140  -> Chrome
    # Android 14  -> Android
    # iOS 18.6    -> iOS
    # ------------------------------------------------------------

    browser_family = (
        browser.split(" ")[0]
        if browser
        else "Unknown"
    )

    os_family = (
        operating_system.split(" ")[0]
        if operating_system
        else "Unknown"
    )

    return (
        f"{browser_family} • {os_family}"
    )


def get_session_device_signature(session):

    user_agent = session.user_agent or ""

    if not user_agent:
        return "Unknown"

    browser = get_browser_name(
        user_agent
    )

    operating_system = get_operating_system(
        user_agent
    )

    browser_family = (
        browser.split(" ")[0]
        if browser
        else "Unknown"
    )

    os_family = (
        operating_system.split(" ")[0]
        if operating_system
        else "Unknown"
    )

    return (
        f"{browser_family} • {os_family}"
    )


def evaluate_session_risk(
    *,
    session,
    request,
):

    score = 0
    reasons = []

    current_ip = get_client_ip(
        request
    )

    current_device = get_device_signature(
        request
    )

    original_device = (
        get_session_device_signature(
            session
        )
    )

    # ============================================================
    # IP CHANGE
    # ============================================================

    ip_changed = (
        session.ip_address is not None
        and current_ip is not None
        and str(session.ip_address)
        != str(current_ip)
    )

    if ip_changed:

        score += 30

        reasons.append(
            "IP_CHANGED"
        )

    # ============================================================
    # DEVICE CHANGE
    # ============================================================

    device_changed = (
        original_device != "Unknown"
        and current_device != "Unknown"
        and original_device != current_device
    )

    if device_changed:

        score += 60

        reasons.append(
            "DEVICE_CHANGED"
        )

    # ============================================================
    # RISK LEVEL
    # ============================================================

    if score >= 80:

        level = "HIGH"

    elif score >= 50:

        level = "MEDIUM"

    elif score > 0:

        level = "LOW"

    else:

        level = "NONE"

    return SessionRiskResult(
        score=score,
        level=level,
        ip_changed=ip_changed,
        device_changed=device_changed,
        current_ip=current_ip,
        current_device=current_device,
        reasons=tuple(reasons),
    )

def should_audit_session_risk(
    *,
    session,
    risk,
):

    if risk.score == 0:
        return False

    reasons_key = "-".join(
        sorted(risk.reasons)
    )

    cache_key = (
        f"session-risk:"
        f"{session.id}:"
        f"{reasons_key}:"
        f"{risk.current_ip}:"
        f"{risk.current_device}"
    )

    created = cache.add(
        cache_key,
        "1",
        timeout=300,
    )

    return created


def audit_session_risk(
    *,
    session,
    request,
    risk,
):

    if risk.score == 0:
        return None

    if not should_audit_session_risk(
        session=session,
        risk=risk,
    ):
        return None

    reasons = ", ".join(
        risk.reasons
    )

    description = (
        f"Session anomaly detected. "
        f"Risk level={risk.level}; "
        f"score={risk.score}; "
        f"reasons={reasons}."
    )

    return create_session_audit(
        request=request,
        user=session.user,
        action="SESSION_RISK_DETECTED",
        description=description,
        status_code=200,
        result="WARNING",
    )
