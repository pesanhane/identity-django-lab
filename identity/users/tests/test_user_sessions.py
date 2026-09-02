from rest_framework.test import APITestCase
from django.test import override_settings

from rest_framework import status


from users.models import (
    User,
    UserSession,
    AuditLog,
    Organization,
)

import pyotp

from django.core.cache import cache
from users.mfa import generate_secret
from users.mfa_recovery import generate_recovery_codes

from datetime import timedelta
from django.utils import timezone

from rest_framework_simplejwt.tokens import (
    AccessToken,
    RefreshToken,
)

from rest_framework_simplejwt.token_blacklist.models import (
    BlacklistedToken,
    OutstandingToken,
)

class UserSessionAuthenticationTest(APITestCase):

    def setUp(self):

        self.password = "StrongPassword123!"

        self.user = User.objects.create_user(
            username="session-user",
            password=self.password,
        )

        self.normal_login_url = "/api/token/"

    def test_normal_login_creates_user_session(self):

        response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        self.assertEqual(
            UserSession.objects.filter(
                user=self.user
            ).count(),
            1,
        )

    def test_failed_login_does_not_create_session(self):

        response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": "WrongPassword123!",
            },
            format="json",
        )

        self.assertNotEqual(
            response.status_code,
            200,
        )

        self.assertFalse(
            UserSession.objects.filter(
                user=self.user
            ).exists()
        )
    def test_session_jti_matches_refresh_token(self):

        response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        refresh_token = RefreshToken(
            response.data["refresh"]
        )

        session = UserSession.objects.get(
            user=self.user
        )

        self.assertEqual(
            session.jti,
            str(refresh_token["jti"]),
        )
    def test_session_stores_request_metadata(self):

        user_agent = (
            "Mozilla/5.0 "
            "(X11; Ubuntu; Linux x86_64; rv:153.0) "
            "Gecko/20100101 Firefox/153.0"
        )

        response = self.client.post(
            "/api/token/",
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
            HTTP_USER_AGENT=user_agent,
            REMOTE_ADDR="192.168.1.100",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        session = (
            UserSession.objects
            .filter(user=self.user)
            .latest("created_at")
        )

        self.assertEqual(
            session.device_name,
            "Firefox 153 • Ubuntu/Linux",
        )

        self.assertEqual(
            session.user_agent,
            user_agent,
        )

        self.assertEqual(
            session.ip_address,
            "192.168.1.100",
        )

    @override_settings(
        TRUSTED_PROXY_IPS=[]
    )
    def test_untrusted_client_cannot_spoof_forwarded_ip(
        self
    ):

        response = self.client.post(
            "/api/token/",
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
            REMOTE_ADDR="203.0.113.10",
            HTTP_X_FORWARDED_FOR="1.2.3.4",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        session = (
            UserSession.objects
            .filter(user=self.user)
            .latest("created_at")
        )

        self.assertEqual(
            session.ip_address,
            "203.0.113.10",
        )

    def test_sessions_endpoint_requires_authentication(self):

        response = self.client.get(
            "/api/users/me/sessions/"
        )

        self.assertEqual(
            response.status_code,
            401,
        )
    def test_user_can_list_own_sessions(self):

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        access = login_response.data["access"]

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {access}"
        )

        response = self.client.get(
            "/api/users/me/sessions/"
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        self.assertEqual(
            len(response.data),
            1,
        )

        self.assertEqual(
            response.data[0]["device_name"],
            UserSession.objects.get(
                user=self.user
            ).device_name,
        )

    def test_sessions_endpoint_does_not_expose_sensitive_data(self):

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        access = login_response.data["access"]
        refresh = login_response.data["refresh"]

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {access}"
        )

        response = self.client.get(
            "/api/users/me/sessions/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        response_text = str(response.data)

        self.assertNotIn(
            "jti",
            response.data[0],
        )

        self.assertNotIn(
            refresh,
            response_text,
        )

        self.assertNotIn(
            access,
            response_text,
        )

    def test_user_cannot_see_other_users_sessions(self):

        other_user = User.objects.create_user(
            username="other-session-user",
            password="OtherPassword123!",
        )

        UserSession.objects.create(
            user=other_user,
            jti="other-user-jti",
            device_name="Other Device",
            user_agent="Other Browser",
            ip_address="10.0.0.10",
            expires_at=timezone.now()
            + timedelta(days=1),
        )

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {login_response.data['access']}"
            )
        )

        response = self.client.get(
            "/api/users/me/sessions/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        returned_ids = {
            item["id"]
            for item in response.data
        }

        other_session = UserSession.objects.get(
            user=other_user
        )

        self.assertNotIn(
            str(other_session.id),
            returned_ids,
        )

    def test_login_tokens_contain_session_id(self):

        response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        refresh = RefreshToken(
            response.data["refresh"]
        )

        access = AccessToken(
            response.data["access"]
        )

        session = UserSession.objects.get(
            user=self.user
        )

        self.assertEqual(
            refresh["session_id"],
            str(session.id),
        )

        self.assertEqual(
            access["session_id"],
            str(session.id),
        )

    def test_session_jti_still_matches_modified_refresh(self):

        response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        refresh = RefreshToken(
            response.data["refresh"]
        )

        session = UserSession.objects.get(
            user=self.user
        )

        self.assertEqual(
            session.jti,
            str(refresh["jti"]),
        )

    def test_refresh_preserves_session_id(self):

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            login_response.status_code,
            200,
            login_response.data,
        )

        old_refresh = RefreshToken(
            login_response.data["refresh"]
        )

        session = UserSession.objects.get(
            user=self.user
        )

        old_session_id = old_refresh["session_id"]

        refresh_response = self.client.post(
            "/api/token/refresh/",
            {
                "refresh": str(old_refresh),
            },
            format="json",
        )

        self.assertEqual(
            refresh_response.status_code,
            200,
            refresh_response.data,
        )

        new_refresh = RefreshToken(
            refresh_response.data["refresh"]
        )

        new_access = AccessToken(
            refresh_response.data["access"]
        )

        self.assertEqual(
            new_refresh["session_id"],
            old_session_id,
        )

        self.assertEqual(
            new_access["session_id"],
            old_session_id,
        )

        self.assertEqual(
            str(session.id),
            old_session_id,
        )

    def test_refresh_updates_session_jti(self):

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            login_response.status_code,
            200,
            login_response.data,
        )

        old_refresh = RefreshToken(
            login_response.data["refresh"]
        )

        old_jti = str(
            old_refresh["jti"]
        )

        refresh_response = self.client.post(
            "/api/token/refresh/",
            {
                "refresh": str(old_refresh),
            },
            format="json",
        )

        self.assertEqual(
            refresh_response.status_code,
            200,
            refresh_response.data,
        )

        new_refresh = RefreshToken(
            refresh_response.data["refresh"]
        )

        new_jti = str(
            new_refresh["jti"]
        )

        self.assertNotEqual(
            old_jti,
            new_jti,
        )

        session = UserSession.objects.get(
            user=self.user
        )

        self.assertEqual(
            session.jti,
            new_jti,
        )

    def test_refresh_does_not_create_new_user_session(self):

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            login_response.status_code,
            200,
        )

        self.assertEqual(
            UserSession.objects.filter(
                user=self.user
            ).count(),
            1,
        )

        refresh_response = self.client.post(
            "/api/token/refresh/",
            {
                "refresh": login_response.data[
                    "refresh"
                ],
            },
            format="json",
        )

        self.assertEqual(
            refresh_response.status_code,
            200,
            refresh_response.data,
        )

        self.assertEqual(
            UserSession.objects.filter(
                user=self.user
            ).count(),
            1,
        )

    def test_revoked_session_cannot_refresh_token(self):

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            login_response.status_code,
            200,
        )

        session = UserSession.objects.get(
            user=self.user
        )

        session.revoked_at = timezone.now()

        session.save(
            update_fields=[
                "revoked_at",
            ]
        )

        response = self.client.post(
            "/api/token/refresh/",
            {
                "refresh": login_response.data[
                    "refresh"
                ],
            },
            format="json",
        )

        self.assertNotEqual(
            response.status_code,
            200,
        )


    def test_session_access_token_can_access_protected_endpoint(self):

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            login_response.status_code,
            200,
            login_response.data,
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer "
                f"{login_response.data['access']}"
            )
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

    def test_revoked_session_cannot_use_access_token(self):

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            login_response.status_code,
            200,
            login_response.data,
        )

        access = login_response.data["access"]

        session = UserSession.objects.get(
            user=self.user
        )

        session.revoked_at = timezone.now()

        session.save(
            update_fields=[
                "revoked_at",
            ]
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {access}"
            )
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            401,
        )


    def test_deleted_session_invalidates_access_token(self):

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            login_response.status_code,
            200,
        )

        access = login_response.data["access"]

        UserSession.objects.filter(
            user=self.user
        ).delete()

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {access}"
            )
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            401,
        )

    def test_legacy_token_without_session_id_remains_valid(self):

        refresh = RefreshToken.for_user(
            self.user
        )

        access = refresh.access_token

        self.assertNotIn(
            "session_id",
            access,
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {str(access)}"
            )
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )


    def test_user_can_revoke_own_session(self):

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            login_response.status_code,
            200,
        )

        access = login_response.data["access"]

        session = UserSession.objects.get(
            user=self.user
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {access}"
            )
        )

        response = self.client.delete(
            f"/api/users/me/sessions/{session.id}/"
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        session.refresh_from_db()

        self.assertIsNotNone(
            session.revoked_at
        )


    def test_revoked_session_access_token_is_rejected(self):

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        access = login_response.data["access"]

        session = UserSession.objects.get(
            user=self.user
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {access}"
            )
        )

        revoke_response = self.client.delete(
            f"/api/users/me/sessions/{session.id}/"
        )

        self.assertEqual(
            revoke_response.status_code,
            200,
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            401,
        )

    def test_user_cannot_revoke_other_users_session(self):

        other_user = User.objects.create_user(
            username="other-revoke-user",
            password="OtherPassword123!",
        )

        other_login = self.client.post(
            self.normal_login_url,
            {
                "username": other_user.username,
                "password": "OtherPassword123!",
            },
            format="json",
        )

        other_session = UserSession.objects.get(
            user=other_user
        )

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {login_response.data['access']}"
            )
        )

        response = self.client.delete(
            f"/api/users/me/sessions/{other_session.id}/"
        )

        self.assertEqual(
            response.status_code,
            404,
        )

        other_session.refresh_from_db()

        self.assertIsNone(
            other_session.revoked_at
        )

    def test_revoke_all_keeps_current_session(self):

        first_login = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            first_login.status_code,
            200,
        )

        current_access = first_login.data[
            "access"
        ]

        current_session_id = AccessToken(
            current_access
        )["session_id"]

        second_login = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            second_login.status_code,
            200,
        )

        self.assertEqual(
            UserSession.objects.filter(
                user=self.user
            ).count(),
            2,
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {current_access}"
            )
        )

        response = self.client.post(
            "/api/users/me/sessions/revoke-all/",
            {
                "keep_current": True,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        current_session = UserSession.objects.get(
            id=current_session_id
        )

        self.assertIsNone(
            current_session.revoked_at
        )

        other_session = (
            UserSession.objects
            .filter(user=self.user)
            .exclude(id=current_session_id)
            .get()
        )

        self.assertIsNotNone(
            other_session.revoked_at
        )

    def test_current_session_still_works_after_revoke_all_others(
        self
    ):

        first_login = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        current_access = first_login.data[
            "access"
        ]

        self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {current_access}"
            )
        )

        revoke_response = self.client.post(
            "/api/users/me/sessions/revoke-all/",
            {
                "keep_current": True,
            },
            format="json",
        )

        self.assertEqual(
            revoke_response.status_code,
            200,
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

    def test_other_session_is_rejected_after_revoke_all(
        self
    ):

        first_login = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        current_access = first_login.data[
            "access"
        ]

        second_login = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        other_access = second_login.data[
            "access"
        ]

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {current_access}"
            )
        )

        revoke_response = self.client.post(
            "/api/users/me/sessions/revoke-all/",
            {
                "keep_current": True,
            },
            format="json",
        )

        self.assertEqual(
            revoke_response.status_code,
            200,
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {other_access}"
            )
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            401,
        )

    def test_revoke_all_can_revoke_current_session(self):

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        access = login_response.data[
            "access"
        ]

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {access}"
            )
        )

        response = self.client.post(
            "/api/users/me/sessions/revoke-all/",
            {
                "keep_current": False,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        session = UserSession.objects.get(
            user=self.user
        )

        self.assertIsNotNone(
            session.revoked_at
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            401,
        )


    def test_revoke_session_blacklists_refresh_token(self):

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        refresh = RefreshToken(
            login_response.data["refresh"]
        )

        session = UserSession.objects.get(
            user=self.user
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {login_response.data['access']}"
            )
        )

        response = self.client.delete(
            f"/api/users/me/sessions/{session.id}/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        outstanding = OutstandingToken.objects.get(
            jti=str(refresh["jti"])
        )

        self.assertTrue(
            BlacklistedToken.objects.filter(
                token=outstanding
            ).exists()
        )

    def test_blacklisted_session_refresh_cannot_be_used(self):

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        refresh = login_response.data[
            "refresh"
        ]

        session = UserSession.objects.get(
            user=self.user
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {login_response.data['access']}"
            )
        )

        revoke_response = self.client.delete(
            f"/api/users/me/sessions/{session.id}/"
        )

        self.assertEqual(
            revoke_response.status_code,
            200,
        )

        self.client.credentials()

        refresh_response = self.client.post(
            "/api/token/refresh/",
            {
                "refresh": refresh,
            },
            format="json",
        )

        self.assertNotEqual(
            refresh_response.status_code,
            200,
        )
    
    def test_revoke_all_blacklists_other_session_refresh(self):

        first_login = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        second_login = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        second_refresh = RefreshToken(
            second_login.data["refresh"]
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {first_login.data['access']}"
            )
        )

        response = self.client.post(
            "/api/users/me/sessions/revoke-all/",
            {
                "keep_current": True,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        outstanding = OutstandingToken.objects.get(
            jti=str(second_refresh["jti"])
        )

        self.assertTrue(
            BlacklistedToken.objects.filter(
                token=outstanding
            ).exists()
        )

    def test_logout_revokes_user_session(self):

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        access = login_response.data["access"]
        refresh = login_response.data["refresh"]

        session = UserSession.objects.get(
            user=self.user
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {access}"
            )
        )

        response = self.client.post(
            "/api/users/logout/",
            {
                "refresh": refresh,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        session.refresh_from_db()

        self.assertIsNotNone(
            session.revoked_at
        )

    def test_logout_invalidates_access_token_session(self):

        login_response = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        access = login_response.data["access"]
        refresh = login_response.data["refresh"]

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {access}"
            )
        )

        logout_response = self.client.post(
            "/api/users/logout/",
            {
                "refresh": refresh,
            },
            format="json",
        )

        self.assertEqual(
            logout_response.status_code,
            200,
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            401,
        )

    def test_logout_does_not_revoke_other_session(self):

        first_login = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        second_login = self.client.post(
            self.normal_login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        first_access = first_login.data["access"]
        first_refresh = first_login.data["refresh"]

        second_access = second_login.data["access"]

        first_session_id = AccessToken(
            first_access
        )["session_id"]

        second_session_id = AccessToken(
            second_access
        )["session_id"]

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {first_access}"
            )
        )

        response = self.client.post(
            "/api/users/logout/",
            {
                "refresh": first_refresh,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        first_session = UserSession.objects.get(
            id=first_session_id
        )

        second_session = UserSession.objects.get(
            id=second_session_id
        )

        self.assertIsNotNone(
            first_session.revoked_at
        )

        self.assertIsNone(
            second_session.revoked_at
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {second_access}"
            )
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

    def test_refresh_rejected_when_jti_does_not_match_session(
        self
    ):

        login_response = self.client.post(
            "/api/token/",
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            login_response.status_code,
            status.HTTP_200_OK,
        )

        refresh = login_response.data[
            "refresh"
        ]

        session = (
            UserSession.objects
            .filter(user=self.user)
            .latest("created_at")
        )

        # Simula inconsistência entre a sessão
        # armazenada e o refresh apresentado.
        session.jti = "different-session-jti"

        session.save(
            update_fields=[
                "jti"
            ]
        )

        response = self.client.post(
            "/api/token/refresh/",
            {
                "refresh": refresh,
            },
            format="json",
        )

        self.assertIn(
            response.status_code,
            [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_401_UNAUTHORIZED,
            ],
        )

        session.refresh_from_db()

        # O refresh rejeitado não pode alterar
        # novamente o JTI da sessão.
        self.assertEqual(
            session.jti,
            "different-session-jti",
        )

    def test_revoked_session_refresh_does_not_modify_session(
        self
    ):

        login_response = self.client.post(
            "/api/token/",
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            login_response.status_code,
            status.HTTP_200_OK,
        )

        refresh = login_response.data[
            "refresh"
        ]

        session = (
            UserSession.objects
            .filter(user=self.user)
            .latest("created_at")
        )

        original_jti = session.jti
        original_expires_at = session.expires_at

        session.revoked_at = timezone.now()

        session.save(
            update_fields=[
                "revoked_at"
            ]
        )

        response = self.client.post(
            "/api/token/refresh/",
            {
                "refresh": refresh,
            },
            format="json",
        )

        self.assertIn(
            response.status_code,
            [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_401_UNAUTHORIZED,
            ],
        )

        session.refresh_from_db()

        self.assertEqual(
            session.jti,
            original_jti,
        )

        self.assertEqual(
            session.expires_at,
            original_expires_at,
        )

        self.assertIsNotNone(
            session.revoked_at
        )
    def test_login_creates_friendly_device_name(
        self
    ):

        response = self.client.post(
            "/api/token/",
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
            HTTP_USER_AGENT=(
                "Mozilla/5.0 "
                "(X11; Ubuntu; Linux x86_64; rv:153.0) "
                "Gecko/20100101 Firefox/153.0"
            ),
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        session = (
            UserSession.objects
            .filter(user=self.user)
            .latest("created_at")
        )

        self.assertEqual(
            session.device_name,
            "Firefox 153 • Ubuntu/Linux",
        )

    def test_chrome_windows_device_is_identified(
        self
    ):

        response = self.client.post(
            "/api/token/",
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
            HTTP_USER_AGENT=(
                "Mozilla/5.0 "
                "(Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/140.0.0.0 Safari/537.36"
            ),
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        session = (
            UserSession.objects
            .filter(user=self.user)
            .latest("created_at")
        )

        self.assertEqual(
            session.device_name,
            "Chrome 140 • Windows",
        )

    def test_authenticated_request_updates_old_last_activity(
        self
    ):

        login_response = self.client.post(
            "/api/token/",
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            login_response.status_code,
            status.HTTP_200_OK,
        )

        access = login_response.data[
            "access"
        ]

        session = (
            UserSession.objects
            .filter(user=self.user)
            .latest("created_at")
        )

        old_activity = (
            timezone.now()
            - timedelta(minutes=10)
        )

        UserSession.objects.filter(
            pk=session.pk
        ).update(
            last_activity=old_activity
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {access}"
            )
        )

        response = self.client.get(
            "/api/users/me/sessions/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        session.refresh_from_db()

        self.assertGreater(
            session.last_activity,
            old_activity,
        )

    def test_recent_last_activity_is_not_updated(
        self
    ):

        login_response = self.client.post(
            "/api/token/",
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        access = login_response.data[
            "access"
        ]

        session = (
            UserSession.objects
            .filter(user=self.user)
            .latest("created_at")
        )

        original_activity = session.last_activity

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {access}"
            )
        )

        self.client.get(
            "/api/users/me/sessions/"
        )

        session.refresh_from_db()

        self.assertEqual(
            session.last_activity,
            original_activity,
        )

    @override_settings(
        TRUSTED_PROXY_IPS=[
            "172.18.0.5"
        ]
    )
    def test_trusted_proxy_uses_forwarded_client_ip(
        self
    ):

        response = self.client.post(
            "/api/token/",
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
            REMOTE_ADDR="172.18.0.5",
            HTTP_X_FORWARDED_FOR="41.77.100.20",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        session = (
            UserSession.objects
            .filter(user=self.user)
            .latest("created_at")
        )

        self.assertEqual(
            session.ip_address,
            "41.77.100.20",
        )


    @override_settings(
        TRUSTED_PROXY_IPS=[
            "172.18.0.0/16"
        ]
    )
    def test_trusted_proxy_network_is_supported(
        self
    ):

        response = self.client.post(
            "/api/token/",
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
            REMOTE_ADDR="172.18.5.20",
            HTTP_X_FORWARDED_FOR="41.77.100.25",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        session = (
            UserSession.objects
            .filter(user=self.user)
            .latest("created_at")
        )

        self.assertEqual(
            session.ip_address,
            "41.77.100.25",
        )

    @override_settings(
        TRUSTED_PROXY_IPS=[
            "172.18.0.0/16"
        ]
    )
    def test_invalid_forwarded_ip_falls_back_to_proxy_ip(
        self
    ):

        response = self.client.post(
            "/api/token/",
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
            REMOTE_ADDR="172.18.0.5",
            HTTP_X_FORWARDED_FOR="invalid-ip",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        session = (
            UserSession.objects
            .filter(user=self.user)
            .latest("created_at")
        )

        self.assertEqual(
            session.ip_address,
            "172.18.0.5",
        )


    @override_settings(
        TRUSTED_PROXY_IPS=[
            "172.18.0.0/16"
        ]
    )
    def test_trusted_proxy_reads_first_forwarded_address(
        self
    ):

        response = self.client.post(
            "/api/token/",
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
            REMOTE_ADDR="172.18.0.5",
            HTTP_X_FORWARDED_FOR=(
                "41.77.100.30, "
                "172.18.0.10"
            ),
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        session = (
            UserSession.objects
            .filter(user=self.user)
            .latest("created_at")
        )

        self.assertEqual(
            session.ip_address,
            "41.77.100.30",
        )
class UserSessionMFAAuthenticationTest(APITestCase):

    def setUp(self):

        cache.clear()

        self.password = "TestPassword123!"

        self.user = User.objects.create_user(
            username="session-mfa-user",
            email="session-mfa@example.com",
            password=self.password,
        )

        self.mfa_token_url = "/api/token/mfa/"
        self.recovery_token_url = (
            "/api/token/mfa/recovery/"
        )

    def tearDown(self):

        cache.clear()

    def enable_mfa(self):

        self.user.mfa_secret = generate_secret()
        self.user.mfa_enabled = True
        self.user.mfa_last_used_counter = None

        self.user.save(
            update_fields=[
                "mfa_secret",
                "mfa_enabled",
                "mfa_last_used_counter",
            ]
        )

    def current_totp_code(self):

        self.user.refresh_from_db()

        return pyotp.TOTP(
            self.user.mfa_secret
        ).now()

    def test_mfa_login_creates_user_session(self):

        self.enable_mfa()

        response = self.client.post(
            self.mfa_token_url,
            {
                "username": self.user.username,
                "password": self.password,
                "code": self.current_totp_code(),
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        self.assertEqual(
            UserSession.objects.filter(
                user=self.user
            ).count(),
            1,
        )

        refresh = RefreshToken(
            response.data["refresh"]
        )

        session = UserSession.objects.get(
            user=self.user
        )

        self.assertEqual(
            session.jti,
            str(refresh["jti"]),
        )

    def test_invalid_mfa_login_does_not_create_session(self):

        self.enable_mfa()

        response = self.client.post(
            self.mfa_token_url,
            {
                "username": self.user.username,
                "password": self.password,
                "code": "000000",
            },
            format="json",
        )

        self.assertNotEqual(
            response.status_code,
            200,
        )

        self.assertFalse(
            UserSession.objects.filter(
                user=self.user
            ).exists()
        )

    def test_recovery_login_creates_user_session(self):

        self.enable_mfa()

        codes = generate_recovery_codes(
            self.user,
            count=10,
        )

        response = self.client.post(
            self.recovery_token_url,
            {
                "username": self.user.username,
                "password": self.password,
                "recovery_code": codes[0],
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        self.assertEqual(
            UserSession.objects.filter(
                user=self.user
            ).count(),
            1,
        )

        refresh = RefreshToken(
            response.data["refresh"]
        )

        session = UserSession.objects.get(
            user=self.user
        )

        self.assertEqual(
            session.jti,
            str(refresh["jti"]),
        )

    def test_invalid_recovery_login_does_not_create_session(self):

        self.enable_mfa()

        generate_recovery_codes(
            self.user,
            count=10,
        )

        response = self.client.post(
            self.recovery_token_url,
            {
                "username": self.user.username,
                "password": self.password,
                "recovery_code": "AAAA-BBBB-CCCC",
            },
            format="json",
        )

        self.assertNotEqual(
            response.status_code,
            200,
        )

        self.assertFalse(
            UserSession.objects.filter(
                user=self.user
            ).exists()
        )


class UserSessionLifecycleAuditTest(APITestCase):

    def setUp(self):

        self.organization = Organization.objects.create(
            name="Audit Organization",
            description="Organization for session audit tests",
        )

        self.user = User.objects.create_user(
            username="sessionaudit",
            email="sessionaudit@example.com",
            password="TestPassword123!",
            organization=self.organization,
        )

        self.password = "TestPassword123!"

        self.login_url = "/api/token/"
        self.sessions_url = "/api/users/me/sessions/"
        self.revoke_all_url = (
            "/api/users/me/sessions/revoke-all/"
        )
        self.logout_url = "/api/users/logout/"

    def login(self):

        response = self.client.post(
            self.login_url,
            {
                "username": self.user.username,
                "password": self.password,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        return response

    def authenticate_with_access(
        self,
        access_token,
    ):

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {access_token}"
            )
        )

    # ============================================================
    # SESSION_CREATED
    # ============================================================

    def test_session_created_is_audited(self):

        self.login()

        self.assertTrue(
            AuditLog.objects.filter(
                user=self.user,
                organization=self.organization,
                action="SESSION_CREATED",
                result="SUCCESS",
            ).exists()
        )

    # ============================================================
    # SESSION_REVOKED
    # ============================================================

    def test_session_revoked_is_audited(self):

        login_response = self.login()

        access = login_response.data[
            "access"
        ]

        self.authenticate_with_access(
            access
        )

        session = (
            UserSession.objects
            .filter(user=self.user)
            .latest("created_at")
        )

        response = self.client.delete(
            f"/api/users/me/sessions/{session.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertTrue(
            AuditLog.objects.filter(
                user=self.user,
                organization=self.organization,
                action="SESSION_REVOKED",
                result="SUCCESS",
            ).exists()
        )

    # ============================================================
    # SESSIONS_REVOKED_ALL
    # ============================================================

    def test_sessions_revoke_all_is_audited(self):

        first_login = self.login()
        second_login = self.login()

        access = second_login.data[
            "access"
        ]

        self.authenticate_with_access(
            access
        )

        response = self.client.post(
            self.revoke_all_url,
            {
                "keep_current": True,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertTrue(
            AuditLog.objects.filter(
                user=self.user,
                organization=self.organization,
                action="SESSIONS_REVOKED_ALL",
                result="SUCCESS",
            ).exists()
        )

    # ============================================================
    # SESSION_LOGOUT
    # ============================================================

    def test_session_logout_is_audited(self):

        login_response = self.login()

        access = login_response.data[
            "access"
        ]

        refresh = login_response.data[
            "refresh"
        ]

        self.authenticate_with_access(
            access
        )

        response = self.client.post(
            self.logout_url,
            {
                "refresh": refresh,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertTrue(
            AuditLog.objects.filter(
                user=self.user,
                organization=self.organization,
                action="SESSION_LOGOUT",
                result="SUCCESS",
            ).exists()
        )

    # ============================================================
    # LEGACY LOGOUT AUDIT
    # ============================================================

    def test_session_logout_preserves_legacy_logout_audit(self):

        login_response = self.login()

        access = login_response.data[
            "access"
        ]

        refresh = login_response.data[
            "refresh"
        ]

        self.authenticate_with_access(
            access
        )

        response = self.client.post(
            self.logout_url,
            {
                "refresh": refresh,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertTrue(
            AuditLog.objects.filter(
                user=self.user,
                organization=self.organization,
                action="LOGOUT",
            ).exists()
        )

    # ============================================================
    # USER WITHOUT ORGANIZATION
    # ============================================================

    def test_session_audit_does_not_break_user_without_organization(
        self
    ):

        user_without_org = User.objects.create_user(
            username="session-no-org",
            email="session-no-org@example.com",
            password="TestPassword123!",
        )

        response = self.client.post(
            self.login_url,
            {
                "username": user_without_org.username,
                "password": "TestPassword123!",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        access = response.data[
            "access"
        ]

        refresh = response.data[
            "refresh"
        ]

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {access}"
            )
        )

        logout_response = self.client.post(
            self.logout_url,
            {
                "refresh": refresh,
            },
            format="json",
        )

        self.assertEqual(
            logout_response.status_code,
            status.HTTP_200_OK,
        )

    