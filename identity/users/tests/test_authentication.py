from django.test import TestCase

from rest_framework.test import APIClient

from users.models import User, Organization


class JWTAuthenticationTest(TestCase):

    def setUp(self):

        self.client = APIClient()

        self.password = "TestPassword123!"

        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Organization for automated tests"
        )

        self.user = User.objects.create_user(
            username="jwtuser",
            email="jwt@example.com",
            password=self.password,
            organization=self.organization
        )

    # ==========================================================
    # LOGIN
    # ==========================================================

    def test_login_returns_access_and_refresh_token(self):

        response = self.client.post(
            "/api/token/",
            {
                "username": "jwtuser",
                "password": self.password
            },
            format="json"
        )

        self.assertEqual(response.status_code, 200)

        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    # ==========================================================
    # LOGIN COM PASSWORD INCORRETA
    # ==========================================================

    def test_login_with_wrong_password_fails(self):

        response = self.client.post(
            "/api/token/",
            {
                "username": "jwtuser",
                "password": "WrongPassword123!"
            },
            format="json"
        )

        self.assertEqual(response.status_code, 401)

    # ==========================================================
    # ACESSO COM ACCESS TOKEN
    # ==========================================================

    def test_authenticated_user_can_access_me(self):

        response = self.client.post(
            "/api/token/",
            {
                "username": "jwtuser",
                "password": self.password
            },
            format="json"
        )

        self.assertEqual(response.status_code, 200)

        access_token = response.data["access"]

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {access_token}"
        )

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(response.status_code, 200)

        self.assertEqual(
            response.data["username"],
            "jwtuser"
        )

    # ==========================================================
    # REQUEST SEM TOKEN
    # ==========================================================

    def test_request_without_token_is_rejected(self):

        response = self.client.get(
            "/api/users/me/"
        )

        self.assertEqual(response.status_code, 401)

    # ==========================================================
    # REFRESH TOKEN
    # ==========================================================

    def test_refresh_token_returns_new_access_token(self):

        response = self.client.post(
            "/api/token/",
            {
                "username": "jwtuser",
                "password": self.password
            },
            format="json"
        )

        self.assertEqual(response.status_code, 200)

        refresh_token = response.data["refresh"]

        response = self.client.post(
            "/api/token/refresh/",
            {
                "refresh": refresh_token
            },
            format="json"
        )

        self.assertEqual(response.status_code, 200)

        self.assertIn(
            "access",
            response.data
        )

    # ==========================================================
    # LOGOUT + BLACKLIST
    # ==========================================================

    def test_logout_blacklists_refresh_token(self):

        # 1. Login
        response = self.client.post(
            "/api/token/",
            {
                "username": "jwtuser",
                "password": self.password
            },
            format="json"
        )

        self.assertEqual(response.status_code, 200)

        access_token = response.data["access"]
        refresh_token = response.data["refresh"]

        # 2. Autenticar
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {access_token}"
        )

        # 3. Logout
        response = self.client.post(
            "/api/users/logout/",
            {
                "refresh": refresh_token
            },
            format="json"
        )

        self.assertEqual(response.status_code, 200)

        self.assertEqual(
            response.data["message"],
            "Logout successful."
        )

        # 4. O refresh token deve estar inutilizável
        response = self.client.post(
            "/api/token/refresh/",
            {
                "refresh": refresh_token
            },
            format="json"
        )

        self.assertEqual(response.status_code, 401)
