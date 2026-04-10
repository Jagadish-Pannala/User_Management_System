"""
tests/integration/Api_Layer/routes/test_auth_routes.py

Integration tests for:  Api_Layer/routes/auth_routes.py
Endpoint tested:        POST /auth/login

Uses real FastAPI app + httpx AsyncClient.
DB session is rolled back after each test for clean state.

Run:  pytest tests/integration/ -v
"""

import pytest
import pytest_asyncio


# ─────────────────────────────────────────────────────────────────────────────
# POST /auth/login
# ─────────────────────────────────────────────────────────────────────────────

class TestLoginRoute:

    # ── Happy path ─────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_login_valid_credentials_returns_200(
        self, client, existing_user, valid_login_payload
    ):
        """
        GIVEN  a registered user with correct credentials
        WHEN   POST /auth/login is called
        THEN   status code must be 200
        """
        # Act
        response = await client.post("/auth/login", json=valid_login_payload)

        # Assert
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_login_response_contains_access_token(
        self, client, existing_user, valid_login_payload
    ):
        """
        GIVEN  valid login credentials
        WHEN   POST /auth/login is called
        THEN   response body must contain 'access_token' as a non-empty string
        """
        # Act
        response = await client.post("/auth/login", json=valid_login_payload)
        body     = response.json()

        # Assert
        assert "access_token" in body
        assert isinstance(body["access_token"], str)
        assert len(body["access_token"]) > 0

    @pytest.mark.asyncio
    async def test_login_response_token_type_is_bearer(
        self, client, existing_user, valid_login_payload
    ):
        """
        GIVEN  valid login credentials
        WHEN   POST /auth/login is called
        THEN   token_type in response must be 'bearer'
        """
        # Act
        response = await client.post("/auth/login", json=valid_login_payload)

        # Assert
        assert response.json()["token_type"] == "bearer"

    @pytest.mark.asyncio
    async def test_login_response_contains_redirect(
        self, client, existing_user, valid_login_payload
    ):
        """
        GIVEN  a returning user (not first login)
        WHEN   POST /auth/login is called
        THEN   redirect field must be '/dashboard'
        """
        # Act
        response = await client.post("/auth/login", json=valid_login_payload)
        body     = response.json()

        # Assert
        assert "redirect" in body
        assert body["redirect"] in ["/dashboard", "/change-password"]

    # ── Failure cases ──────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_login_wrong_password_returns_401(
        self, client, existing_user
    ):
        """
        GIVEN  a registered user but wrong password
        WHEN   POST /auth/login is called
        THEN   status code must be 401
        """
        # Act
        response = await client.post("/auth/login", json={
            "email":    existing_user["mail"],
            "password": "WrongPassword999"
        })

        # Assert
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_login_nonexistent_email_returns_404(self, client):
        """
        GIVEN  an email that is not registered in the system
        WHEN   POST /auth/login is called
        THEN   status code must be 404
        """
        # Act
        response = await client.post("/auth/login", json={
            "email":    "ghost@nobody.com",
            "password": "Secret123"
        })

        # Assert
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_login_invalid_email_format_returns_422(self, client):
        """
        GIVEN  an email in invalid format
        WHEN   POST /auth/login is called
        THEN   status code must be 422 (validation error)
        """
        # Act
        response = await client.post("/auth/login", json={
            "email":    "not-an-email",
            "password": "Secret123"
        })

        # Assert
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_login_missing_email_field_returns_422(self, client):
        """
        GIVEN  request body missing the email field
        WHEN   POST /auth/login is called
        THEN   status code must be 422
        """
        # Act
        response = await client.post("/auth/login", json={
            "password": "Secret123"
            # email intentionally missing
        })

        # Assert
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_login_missing_password_field_returns_422(self, client, existing_user):
        """
        GIVEN  request body missing the password field
        WHEN   POST /auth/login is called
        THEN   status code must be 422
        """
        # Act
        response = await client.post("/auth/login", json={
            "email": existing_user["mail"]
            # password intentionally missing
        })

        # Assert
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_login_empty_body_returns_422(self, client):
        """Empty request body must return 422."""
        response = await client.post("/auth/login", json={})
        assert response.status_code == 422
