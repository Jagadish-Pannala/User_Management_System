"""
tests/unit/Business_Layer/utils/test_jwt_encode.py

Unit tests for:  Business_Layer/utils/jwt_encode.py
Function tested: token_create()

DB and jwt.encode are mocked — we test our logic, not the library.
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException


# ─────────────────────────────────────────────────────────────────────────────
# Shared test data
# ─────────────────────────────────────────────────────────────────────────────

VALID_TOKEN_DATA = {
    "sub":         "1",
    "user_id":     1,
    "name":        "John Doe",
    "email":       "john@example.com",
    "roles":       ["admin"],
    "permissions": ["read", "write"],
}


class TestTokenCreate:

    # ── Happy path ─────────────────────────────────────────────────────────

    def test_token_create_with_issuer_returns_string(self):
        """
        GIVEN  valid token_data and an explicit issuer
        WHEN   token_create() is called
        THEN   a non-empty string (JWT) is returned
        """
        from Backend.Api_Layer.JWT.token_creation.token_create import token_create

        with patch("Backend.Api_Layer.JWT.token_creation.token_create._load_keys"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._private_key", "fake-key"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._algorithm",   "RS256"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._kid",         "kid-001"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create.jwt.encode",
                   return_value="mocked.jwt.token"):

            # Act
            result = token_create(VALID_TOKEN_DATA, issuer="https://myapp.com")

        # Assert
        assert isinstance(result, str)
        assert result == "mocked.jwt.token"

    def test_token_create_with_request_extracts_issuer(self):
        """
        GIVEN  no explicit issuer but a valid Request object
        WHEN   token_create() is called
        THEN   issuer is derived from the request and token is created
        """
        from Backend.Api_Layer.JWT.token_creation.token_create import token_create

        mock_request = MagicMock()

        with patch("Backend.Api_Layer.JWT.token_creation.token_create._load_keys"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._private_key", "fake-key"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._algorithm",   "RS256"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._kid",         "kid-001"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create.get_issuer_from_request",
                   return_value="https://myapp.com"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create.jwt.encode",
                   return_value="request.based.token"):

            # Act
            result = token_create(VALID_TOKEN_DATA, request=mock_request)

        # Assert
        assert result == "request.based.token"

    def test_token_create_payload_contains_required_fields(self):
        """
        GIVEN  valid token_data
        WHEN   token_create() builds the JWT payload
        THEN   payload must contain: user_id, email, name, roles, permissions, iss, exp, jti
        """
        from Backend.Api_Layer.JWT.token_creation.token_create import token_create

        captured_payload = {}

        def capture_encode(payload, *args, **kwargs):
            captured_payload.update(payload)
            return "tok"

        with patch("Backend.Api_Layer.JWT.token_creation.token_create._load_keys"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._private_key", "fake-key"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._algorithm",   "RS256"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._kid",         "kid-001"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create.jwt.encode",
                   side_effect=capture_encode):

            token_create(VALID_TOKEN_DATA, issuer="https://myapp.com")

        # Assert — all required JWT claims must be present
        assert "user_id"     in captured_payload
        assert "email"       in captured_payload
        assert "roles"       in captured_payload
        assert "permissions" in captured_payload
        assert "iss"         in captured_payload
        assert "exp"         in captured_payload
        assert "jti"         in captured_payload

    # ── Failure cases ──────────────────────────────────────────────────────

    def test_token_create_no_issuer_no_request_raises_value_error(self):
        """
        GIVEN  neither 'request' nor 'issuer' is provided
        WHEN   token_create() is called
        THEN   ValueError must be raised — issuer is mandatory for JWT security
        """
        from Backend.Api_Layer.JWT.token_creation.token_create import token_create

        with patch("Backend.Api_Layer.JWT.token_creation.token_create._load_keys"):
            with pytest.raises(ValueError) as exc_info:
                token_create(VALID_TOKEN_DATA)   # no request, no issuer

        assert "issuer" in str(exc_info.value).lower()

    def test_token_create_calls_load_keys(self):
        """
        GIVEN  any valid call to token_create
        WHEN   token is being created
        THEN   _load_keys must be called to ensure keys are loaded from DB
        """
        from Backend.Api_Layer.JWT.token_creation.token_create import token_create

        with patch("Backend.Api_Layer.JWT.token_creation.token_create._load_keys") as mock_load, \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._private_key", "key"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._algorithm",   "RS256"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._kid",         "kid"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create.jwt.encode",
                   return_value="tok"):

            token_create(VALID_TOKEN_DATA, issuer="https://app.com")

        # Assert — keys must always be loaded (they may rotate)
        mock_load.assert_called_once()
