import os

from django.db import transaction
from rest_framework.exceptions import Throttled
from rest_framework import serializers

from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
)

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
)

from .mfa import verify_totp_code_with_counter

from .mfa_recovery import (
    verify_and_consume_recovery_code,
)

from .models import (
    User,
    AuditLog,
)

from .rate_limit import check_rate_limit


# ============================================================
# CLIENT IP
# ============================================================

def get_client_ip(request):
    """
    Obtém o IP do cliente.

    Em produção, X-Forwarded-For deve ser aceite
    apenas quando existe proxy confiável.
    """

    forwarded_for = request.META.get(
        "HTTP_X_FORWARDED_FOR"
    )

    if forwarded_for:

        return (
            forwarded_for
            .split(",")[0]
            .strip()
        )

    return request.META.get(
        "REMOTE_ADDR",
        "unknown"
    )


# ============================================================
# RECOVERY LOGIN AUDIT
# ============================================================

def create_recovery_login_audit(
    request,
    user,
    action,
    description,
    result,
    status_code,
):
    """
    Regista eventos de autenticação através
    de MFA Recovery Code.

    A ausência de organização não deve impedir
    a autenticação.
    """

    organization = getattr(
        user,
        "organization",
        None,
    )

    if organization is None:
        return

    AuditLog.objects.create(
        organization=organization,
        user=user,
        action=action,
        description=description,
        ip_address=get_client_ip(request),
        http_method=request.method,
        endpoint=request.path,
        user_agent=request.META.get(
            "HTTP_USER_AGENT"
        ),
        status_code=status_code,
        result=result,
    )


# ============================================================
# NORMAL LOGIN RATE LIMIT
# ============================================================

def apply_login_rate_limit(
    request,
    username,
):
    """
    Rate limit do login normal.

    Proteção por:
        - IP
        - username
    """

    ip = get_client_ip(
        request
    )

    window = int(
        os.getenv(
            "RATE_LIMIT_WINDOW",
            60,
        )
    )

    check_rate_limit(
        key=f"login-ip:{ip}",
        limit=int(
            os.getenv(
                "LOGIN_RATE_LIMIT_IP",
                10,
            )
        ),
        window=window,
    )

    check_rate_limit(
        key=f"login-user:{username}",
        limit=int(
            os.getenv(
                "LOGIN_RATE_LIMIT_USER",
                5,
            )
        ),
        window=window,
    )


# ============================================================
# MFA RATE LIMIT
# ============================================================

def apply_mfa_rate_limit(
    request,
    username,
):
    """
    Rate limit para MFA.

    Proteção por:
        - IP
        - username
    """

    ip = get_client_ip(
        request
    )

    window = int(
        os.getenv(
            "RATE_LIMIT_WINDOW",
            60,
        )
    )

    check_rate_limit(
        key=f"mfa-ip:{ip}",
        limit=int(
            os.getenv(
                "MFA_RATE_LIMIT_IP",
                10,
            )
        ),
        window=window,
    )

    check_rate_limit(
        key=f"mfa-user:{username}",
        limit=int(
            os.getenv(
                "MFA_RATE_LIMIT_USER",
                5,
            )
        ),
        window=window,
    )

def apply_recovery_rate_limit(
    request,
    username,
    user,
):
    """
    Aplica rate limiting ao login por recovery code.

    Quando o limite é efetivamente atingido,
    cria um evento de auditoria específico e
    mantém a resposta HTTP 429 original.
    """

    try:

        apply_mfa_rate_limit(
            request,
            username,
        )

    except Throttled:

        create_recovery_login_audit(
            request=request,
            user=user,
            action="MFA_RECOVERY_RATE_LIMITED",
            description=(
                "Login por recovery code bloqueado "
                "por excesso de tentativas."
            ),
            result="FAILURE",
            status_code=429,
        )

        raise	


# ============================================================
# MFA / TOTP LOGIN
# ============================================================

class MFATokenObtainPairSerializer(
    TokenObtainPairSerializer
):
    """
    Login JWT utilizando MFA/TOTP.

    Utilizadores com MFA ativo devem fornecer:

        username
        password
        code
    """

    code = serializers.CharField(
        required=False,
        allow_blank=True,
        write_only=True,
    )

    def validate(
        self,
        attrs,
    ):

        username = attrs.get(
            "username",
            "",
        )

        request = self.context[
            "request"
        ]

        # ------------------------------------------------------
        # USERNAME + PASSWORD
        # ------------------------------------------------------

        try:

            data = super().validate(
                attrs
            )

        except serializers.ValidationError:

            apply_mfa_rate_limit(
                request,
                username,
            )

            raise

        # ------------------------------------------------------
        # USER WITHOUT MFA
        # ------------------------------------------------------

        if not self.user.mfa_enabled:

            return data

        code = attrs.get(
            "code"
        )

        # ------------------------------------------------------
        # MFA CODE REQUIRED
        # ------------------------------------------------------

        if not code:

            apply_mfa_rate_limit(
                request,
                username,
            )

            raise serializers.ValidationError(
                {
                    "code": (
                        "MFA code is required."
                    )
                }
            )

        # ------------------------------------------------------
        # TOTP VALIDATION + ANTI-REPLAY
        # ------------------------------------------------------

        with transaction.atomic():

            user = (
                User.objects
                .select_for_update()
                .get(
                    pk=self.user.pk
                )
            )

            counter = (
                verify_totp_code_with_counter(
                    user.mfa_secret,
                    code,
                )
            )

            if counter is None:

                apply_mfa_rate_limit(
                    request,
                    username,
                )

                raise serializers.ValidationError(
                    {
                        "code": (
                            "Invalid MFA code."
                        )
                    }
                )

            if (
                user.mfa_last_used_counter
                is not None
                and
                counter
                <=
                user.mfa_last_used_counter
            ):

                apply_mfa_rate_limit(
                    request,
                    username,
                )

                raise serializers.ValidationError(
                    {
                        "code": (
                            "MFA code has already "
                            "been used."
                        )
                    }
                )

            user.mfa_last_used_counter = (
                counter
            )

            user.save(
                update_fields=[
                    "mfa_last_used_counter"
                ]
            )

        return data


class MFATokenObtainPairView(
    TokenObtainPairView
):

    serializer_class = (
        MFATokenObtainPairSerializer
    )


# ============================================================
# NORMAL LOGIN
# ============================================================

class NormalTokenObtainPairSerializer(
    TokenObtainPairSerializer
):
    """
    Login JWT normal.

    Se MFA estiver ativo, o login normal
    é bloqueado.
    """

    def validate(
        self,
        attrs,
    ):

        username = attrs.get(
            "username",
            "",
        )

        request = self.context[
            "request"
        ]

        try:

            data = super().validate(
                attrs
            )

        except serializers.ValidationError:

            apply_login_rate_limit(
                request,
                username,
            )

            raise

        user = self.user

        if user.mfa_enabled:

            apply_login_rate_limit(
                request,
                username,
            )

            raise serializers.ValidationError(
                {
                    "code": (
                        "MFA is enabled for this "
                        "account. Use the MFA "
                        "login endpoint."
                    )
                }
            )

        return data


class NormalTokenObtainPairView(
    TokenObtainPairView
):

    serializer_class = (
        NormalTokenObtainPairSerializer
    )


# ============================================================
# MFA RECOVERY LOGIN
# ============================================================

class MFARecoveryTokenObtainPairSerializer(
    TokenObtainPairSerializer
):
    """
    Login utilizando MFA Recovery Code.

    Requer:

        username
        password
        recovery_code
    """

    recovery_code = serializers.CharField(
        required=True,
        write_only=True,
    )

    def validate(
        self,
        attrs,
    ):

        username = attrs.get(
            "username",
            "",
        )

        request = self.context[
            "request"
        ]

        # ------------------------------------------------------
        # USERNAME + PASSWORD
        # ------------------------------------------------------

        try:

            data = super().validate(
                attrs
            )

        except serializers.ValidationError:

            apply_mfa_rate_limit(
                request,
                username,
            )

            raise

        user = self.user

        # ------------------------------------------------------
        # MFA MUST BE ENABLED
        # ------------------------------------------------------

        if not user.mfa_enabled:

            create_recovery_login_audit(
                request=request,
                user=user,
                action=(
                    "MFA_RECOVERY_LOGIN_FAILED"
                ),
                description=(
                    "Recovery login recusado: "
                    "MFA não está ativado."
                ),
                result="FAILURE",
                status_code=400,
            )

            raise serializers.ValidationError(
                {
                    "recovery_code": (
                        "MFA is not enabled "
                        "for this account."
                    )
                }
            )

        recovery_code = attrs.get(
            "recovery_code"
        )

        # ------------------------------------------------------
        # VERIFY + CONSUME CODE
        # ------------------------------------------------------

        if not verify_and_consume_recovery_code(
            user,
            recovery_code,
        ):

            create_recovery_login_audit(
                request=request,
                user=user,
                action=(
                    "MFA_RECOVERY_LOGIN_FAILED"
                ),
                description=(
                    "Recovery login falhou: "
                    "código inválido ou "
                    "já utilizado."
                ),
                result="FAILURE",
                status_code=400,
            )

            apply_recovery_rate_limit(
                request,
                username,
                user,
            )

            raise serializers.ValidationError(
                {
                    "recovery_code": (
                        "Invalid or already used "
                        "recovery code."
                    )
                }
            )

        # ------------------------------------------------------
        # SUCCESS AUDIT
        # ------------------------------------------------------

        create_recovery_login_audit(
            request=request,
            user=user,
            action=(
                "MFA_RECOVERY_LOGIN_SUCCESS"
            ),
            description=(
                "Login MFA realizado com "
                "recovery code."
            ),
            result="SUCCESS",
            status_code=200,
        )

        return data


class MFARecoveryTokenObtainPairView(
    TokenObtainPairView
):

    serializer_class = (
        MFARecoveryTokenObtainPairSerializer
    )
