from django.db import transaction
from django.utils import timezone

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import UserSession

from .mfa import (
    verify_totp_code_with_counter,
)

from .session_management import (
    create_session_audit,
    get_client_ip,
    get_device_name,
)

class SessionStepUpMFAView(APIView):

    permission_classes = [
        IsAuthenticated
    ]
		
    @transaction.atomic
    @transaction.atomic
    def post(self, request):

        session_id = request.auth.get(
            "session_id"
        )

        if not session_id:

            return Response(
                {
                    "detail": (
                        "Session-bound token "
                        "is required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:

            session = (
                UserSession.objects
                .select_for_update()
                .get(
                    id=session_id,
                    user=request.user,
                )
            )

        except (
            UserSession.DoesNotExist,
            ValueError,
        ):

            return Response(
                {
                    "detail": (
                        "Session does not exist."
                    )
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        if not session.requires_step_up:

            return Response(
                {
                    "detail": (
                        "This session does not "
                        "require step-up authentication."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not request.user.mfa_enabled:

            return Response(
                {
                    "detail": (
                        "MFA is not enabled "
                        "for this account."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not request.user.mfa_secret:

            return Response(
                {
                    "detail": (
                        "MFA configuration is invalid."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        code = request.data.get(
            "code"
        )

        if not code:

            return Response(
                {
                    "detail": (
                        "MFA code is required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ============================================================
        # TOTP VALIDATION + ANTI-REPLAY
        # ============================================================

        verification = verify_totp_code_with_counter(
            request.user.mfa_secret,
            code,
        )

        if verification is None:

            create_session_audit(
                request=request,
                user=request.user,
                action="SESSION_STEP_UP_FAILED",
                description=(
                    "Step-up MFA failed because "
                    "the TOTP code was invalid."
                ),
                status_code=400,
                result="FAILED",
            )

            return Response(
                {
                    "detail": (
                        "Invalid MFA code."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        counter = verification

        # ============================================================
        # ANTI-REPLAY
        # ============================================================

        if (
            request.user.mfa_last_used_counter
            is not None
            and counter
            <= request.user.mfa_last_used_counter
        ):

            create_session_audit(
                request=request,
                user=request.user,
                action="SESSION_STEP_UP_REPLAY_DETECTED",
                description=(
                    "Step-up MFA rejected because "
                    "the TOTP code was already used."
                ),
                status_code=400,
                result="FAILED",
            )

            return Response(
                {
                    "detail": (
                        "MFA code has already been used."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ============================================================
        # SAVE MFA COUNTER
        # ============================================================

        request.user.mfa_last_used_counter = counter

        request.user.save(
            update_fields=[
                "mfa_last_used_counter"
            ]
        )

        # ============================================================
        # TRUST NEW SESSION ENVIRONMENT
        # ============================================================

        session.ip_address = get_client_ip(
            request
        )

        session.device_name = get_device_name(
            request
        )

        session.user_agent = request.META.get(
            "HTTP_USER_AGENT",
            "",
        )

        # ============================================================
        # CLEAR STEP-UP STATE
        # ============================================================

        session.requires_step_up = False

        session.step_up_verified_at = (
            timezone.now()
        )

        session.risk_score = 0
        session.risk_level = "NONE"

        session.save(
            update_fields=[
                "ip_address",
                "device_name",
                "user_agent",
                "requires_step_up",
                "step_up_verified_at",
                "risk_score",
                "risk_level",
            ]
        )

        # ============================================================
        # AUDIT SUCCESS
        # ============================================================

        create_session_audit(
            request=request,
            user=request.user,
            action="SESSION_STEP_UP_SUCCESS",
            description=(
                "Step-up MFA successfully "
                "completed for the session."
            ),
            status_code=200,
            result="SUCCESS",
        )

        return Response(
            {
                "detail": (
                    "Step-up authentication "
                    "completed successfully."
                )
            },
            status=status.HTTP_200_OK,
        )