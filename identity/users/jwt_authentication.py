from django.utils import timezone
from datetime import timedelta


from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import (
    JWTAuthentication,
)

from .models import UserSession


class SessionJWTAuthentication(
    JWTAuthentication
):



    ACTIVITY_UPDATE_INTERVAL = timedelta(
        minutes=5
    )

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

        # ============================================================
        # UPDATE LAST ACTIVITY
        # ============================================================
        #
        # Não atualizamos em cada request.
        #
        # Apenas fazemos uma escrita quando passaram
        # pelo menos 5 minutos desde a última atividade
        # registada.
        # ============================================================

        now = timezone.now()

        activity_threshold = (
            now
            - self.ACTIVITY_UPDATE_INTERVAL
        )

        if session.last_activity < activity_threshold:

            UserSession.objects.filter(
                pk=session.pk,
                last_activity__lt=activity_threshold,
                revoked_at__isnull=True,
            ).update(
                last_activity=now
            )

        return user
