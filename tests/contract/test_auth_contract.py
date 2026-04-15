# """
# tests/contract/test_auth_contract.py

# Contract tests for:  POST /auth/login

# Purpose:
#   Verify the EXACT shape of the login response never changes.
#   If a field is renamed, removed, or changes type — this test breaks immediately.
#   This protects frontend and other microservices that depend on this response.
# """

# import pytest


# class TestLoginResponseContract:

#     @pytest.mark.asyncio
#     async def test_login_response_has_all_required_fields(
#         self, client, existing_user, valid_login_payload
#     ):
#         """
#         GIVEN  valid login credentials
#         WHEN   POST /auth/login is called
#         THEN   response must contain exactly: access_token, token_type, redirect
#                — no required field missing
#         """
#         # Act
#         response = await client.post("/auth/login", json=valid_login_payload)
#         body     = response.json()

#         # Assert — contract: these 3 fields must ALWAYS exist
#         assert "access_token" in body, "Contract broken: 'access_token' missing"
#         assert "token_type"   in body, "Contract broken: 'token_type' missing"
#         assert "redirect"     in body, "Contract broken: 'redirect' missing"

#     @pytest.mark.asyncio
#     async def test_login_access_token_is_string(
#         self, client, existing_user, valid_login_payload
#     ):
#         """access_token must always be a non-empty string (JWT format)."""
#         response = await client.post("/auth/login", json=valid_login_payload)
#         body     = response.json()

#         assert isinstance(body["access_token"], str)
#         assert len(body["access_token"]) > 0

#     @pytest.mark.asyncio
#     async def test_login_token_type_is_always_bearer_string(
#         self, client, existing_user, valid_login_payload
#     ):
#         """token_type must always be the string 'bearer' — never 'Bearer' or 'JWT'."""
#         response = await client.post("/auth/login", json=valid_login_payload)

#         assert response.json()["token_type"] == "bearer"

#     @pytest.mark.asyncio
#     async def test_login_redirect_is_string(
#         self, client, existing_user, valid_login_payload
#     ):
#         """redirect must always be a string path — never None or int."""
#         response = await client.post("/auth/login", json=valid_login_payload)
#         body     = response.json()

#         assert isinstance(body["redirect"], str)
#         assert body["redirect"].startswith("/")

#     @pytest.mark.asyncio
#     async def test_login_redirect_is_one_of_known_values(
#         self, client, existing_user, valid_login_payload
#     ):
#         """
#         redirect must only ever be '/dashboard' or '/change-password'.
#         Any other value means a new redirect was added without updating consumers.
#         """
#         response = await client.post("/auth/login", json=valid_login_payload)
#         body     = response.json()

#         known_redirects = ["/dashboard", "/change-password"]
#         assert body["redirect"] in known_redirects, (
#             f"Contract broken: unexpected redirect value '{body['redirect']}'. "
#             f"Expected one of {known_redirects}"
#         )

#     @pytest.mark.asyncio
#     async def test_login_response_has_no_sensitive_fields(
#         self, client, existing_user, valid_login_payload
#     ):
#         """
#         GIVEN  a successful login
#         WHEN   response body is inspected
#         THEN   it must NOT contain password, hashed_password, or private_key
#                — sensitive data must never leak into the response
#         """
#         response = await client.post("/auth/login", json=valid_login_payload)
#         body     = response.json()

#         forbidden_fields = ["password", "hashed_password", "private_key", "secret"]
#         for field in forbidden_fields:
#             assert field not in body, (
#                 f"Security contract broken: '{field}' found in login response"
#             )
