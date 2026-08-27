import os
from django.core.cache import cache
from django.db import transaction

from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView

from .mfa import verify_totp_code_with_counter
from .models import User
from .rate_limit import check_rate_limit


def get_client_ip(request):
    """
    Obtém o IP do cliente.

    Em produção, o tratamento de X-Forwarded-For
    deve ser feito somente quando existe um proxy
    confiável configurado.
    """

    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return request.META.get(
        "REMOTE_ADDR",
        "unknown"
    )


def apply_login_rate_limit(request, username):
    """
    Registra uma tentativa de autenticação falhada.

    O limite é aplicado por IP e por username.
    """

    ip = get_client_ip(request)

    window = int(
        os.getenv(
            "RATE_LIMIT_WINDOW",
            60
        )
    )

    check_rate_limit(
        key=f"login-ip:{ip}",
        limit=int(
            os.getenv(
                "LOGIN_RATE_LIMIT_IP",
                10
            )
        ),
        window=window,
    )

    check_rate_limit(
        key=f"login-user:{username}",
        limit=int(
            os.getenv(
                "LOGIN_RATE_LIMIT_USER",
                5
            )
        ),
        window=window,
    )


def apply_mfa_rate_limit(request, username):
    """
    Registra uma tentativa MFA falhada.

    O limite é aplicado por IP e por username.
    """

    ip = get_client_ip(request)

    window = int(
        os.getenv(
            "RATE_LIMIT_WINDOW",
            60
        )
    )

    check_rate_limit(
        key=f"mfa-ip:{ip}",
        limit=int(
            os.getenv(
                "MFA_RATE_LIMIT_IP",
                10
            )
        ),
        window=window,
    )

    check_rate_limit(
        key=f"mfa-user:{username}",
        limit=int(
            os.getenv(
                "MFA_RATE_LIMIT_USER",
                5
            )
        ),
        window=window,
    )


class MFATokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Autenticação JWT com suporte a MFA/TOTP.

    Utilizadores sem MFA continuam a autenticar normalmente.

    Utilizadores com MFA ativado precisam fornecer:

        username
        password
        code
    """

    code = serializers.CharField(
        required=False,
        allow_blank=True,
        write_only=True,
    )

    def validate(self, attrs):

        username = attrs.get("username", "")

        try:
            data = super().validate(attrs)

        except serializers.ValidationError:
            apply_mfa_rate_limit(
                self.context["request"],
                username,
            )
            raise

        code = attrs.get("code")

        if not self.user.mfa_enabled:
            return data

        if not code:
            apply_mfa_rate_limit(
                self.context["request"],
                username,
            )

            raise serializers.ValidationError(
                {"code": "MFA code is required."}
            )

        with transaction.atomic():

            user = (
                User.objects
                .select_for_update()
                .get(pk=self.user.pk)
            )

            counter = verify_totp_code_with_counter(
                user.mfa_secret,
                code,
            )

            if counter is None:

                apply_mfa_rate_limit(
                    self.context["request"],
                    username,
                )

                raise serializers.ValidationError(
                    {"code": "Invalid MFA code."}
                )

            if (
                user.mfa_last_used_counter is not None
                and counter <= user.mfa_last_used_counter
            ):

                apply_mfa_rate_limit(
                    self.context["request"],
                    username,
                )

                raise serializers.ValidationError(
                    {"code": "MFA code has already been used."}
                )

            user.mfa_last_used_counter = counter

            user.save(
                update_fields=[
                    "mfa_last_used_counter"
                ]
            )

        return data


class MFATokenObtainPairView(TokenObtainPairView):
    serializer_class = MFATokenObtainPairSerializer


class NormalTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Login JWT normal.

    Se MFA estiver ativado, o login normal é bloqueado.
    O utilizador deve utilizar /api/token/mfa/.
    """

    def validate(self, attrs):

        username = attrs.get("username", "")

        try:
            data = super().validate(attrs)

        except serializers.ValidationError:
            apply_login_rate_limit(
                self.context["request"],
                username,
            )
            raise

        user = self.user

        if user.mfa_enabled:

            apply_login_rate_limit(
                self.context["request"],
                username,
            )

            raise serializers.ValidationError(
                {
                    "code": (
                        "MFA is enabled for this account. "
                        "Use the MFA login endpoint."
                    )
                }
            )

        return data


class NormalTokenObtainPairView(TokenObtainPairView):
    serializer_class = NormalTokenObtainPairSerializer
