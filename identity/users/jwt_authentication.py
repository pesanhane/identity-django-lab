from django.utils import timezone

from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import (
    JWTAuthentication,
)

from .models import UserSession


class SessionJWTAuthentication(
    JWTAuthentication
):

    def get_user(self, validated_token):

        user = super().get_user(
            validated_token
        )

        session_id = validated_token.get(
            "session_id"
        )

        # Compatibilidade temporária com
        # tokens antigos/manuais.
        if not session_id:
            return user

        try:
            session = UserSession.objects.get(
                id=session_id,
                user=user,
            )

        except (
            UserSession.DoesNotExist,
            ValueError,
        ):
            raise AuthenticationFailed(
                "Session does not exist."
            )

        if session.revoked_at is not None:
            raise AuthenticationFailed(
                "Session has been revoked."
            )

        if session.expires_at <= timezone.now():
            raise AuthenticationFailed(
                "Session has expired."
            )

        return user
