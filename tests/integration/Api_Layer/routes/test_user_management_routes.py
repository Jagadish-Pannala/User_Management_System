# """
# tests/integration/Api_Layer/routes/test_user_management_routes.py

# Integration tests for:  Api_Layer/routes/user_management_routes.py
# Endpoints tested:
#   - GET    /
#   - GET    /count
#   - GET    /active-count
#   - GET    '', response_model=PaginatedUserResponse
#   - GET    /roles
#   - GET    /id/roles
#   - GET    /{user_id}
#   - GET    /uuid/{user_uuid}
#   - POST   ''
#   - POST   /multiple-users
#   - PUT    /{user_id}
#   - PUT    /uuid/{user_uuid}
#   - DELETE /{user_id}
#   - DELETE /uuid/{user_uuid}
#   - PATCH  /uuid/{user_uuid}/activate
#   - PUT    /{user_id}/role
#   - PUT    /uuid/{user_uuid}/role
#   - GET    /{user_id}/roles
#   - GET    /uuid/{user_uuid}/roles

# Uses real FastAPI app + httpx AsyncClient.
# DB session is rolled back after each test for clean state.

# Run:  pytest tests/integration/ -v
# """

# import pytest
# import pytest_asyncio
# import json


# # ─────────────────────────────────────────────────────────────────────────────
# # HOME & COUNT ENDPOINTS
# # ─────────────────────────────────────────────────────────────────────────────

# class TestUserManagementHome:
#     """Tests for GET / endpoint"""

#     @pytest.mark.asyncio
#     async def test_admin_home_returns_200(self, client, auth_headers):
#         """
#         GIVEN  the user management route home endpoint
#         WHEN   GET /home is called
#         THEN   returns 200 with success message
#         """
#         # Act
#         response = await client.get("/admin/users/home", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200
#         assert "message" in response.json()


# class TestCountEndpoints:
#     """Tests for count endpoints"""

#     @pytest.mark.asyncio
#     async def test_count_users_returns_total_count(self, client, existing_user, auth_headers):
#         """
#         GIVEN  users exist in database
#         WHEN   GET /count is called
#         THEN   returns 200 with user_count field
#         """
#         # Act
#         response = await client.get("/admin/users/count", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200
#         data = response.json()
#         assert "user_count" in data
#         assert isinstance(data["user_count"], int)
#         assert data["user_count"] >= 1

#     @pytest.mark.asyncio
#     async def test_count_active_users_returns_active_count(self, client, existing_user, auth_headers):
#         """
#         GIVEN  active users exist in database
#         WHEN   GET /active-count is called
#         THEN   returns 200 with active_user_count
#         """
#         # Act
#         response = await client.get("/admin/users/active-count", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200
#         data = response.json()
#         assert "active_user_count" in data
#         assert isinstance(data["active_user_count"], int)


# # ─────────────────────────────────────────────────────────────────────────────
# # LIST USERS ENDPOINTS
# # ─────────────────────────────────────────────────────────────────────────────

# class TestListUsers:
#     """Tests for GET /"""

#     @pytest.mark.asyncio
#     async def test_list_users_returns_paginated_result(self, client, existing_user, auth_headers):
#         """
#         GIVEN  users exist in database
#         WHEN   GET / is called
#         THEN   returns 200 with paginated response containing total and users
#         """
#         # Act
#         response = await client.get("/admin/users/?page=1&limit=10", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200
#         data = response.json()
#         assert "total" in data
#         assert "users" in data
#         assert isinstance(data["total"], int)
#         assert isinstance(data["users"], list)

#     @pytest.mark.asyncio
#     async def test_list_users_default_pagination(self, client, existing_user, auth_headers):
#         """
#         GIVEN  no pagination parameters provided
#         WHEN   GET / is called
#         THEN   returns paginated result with default page=1, limit=50
#         """
#         # Act
#         response = await client.get("/admin/users/", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200
#         data = response.json()
#         assert "total" in data
#         assert "users" in data

#     @pytest.mark.asyncio
#     async def test_list_users_with_search_filter(self, client, existing_user, auth_headers):
#         """
#         GIVEN  a search term
#         WHEN   GET / with search parameter is called
#         THEN   returns filtered results
#         """
#         # Act
#         response = await client.get("/admin/users/?page=1&limit=10&search=john", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200
#         data = response.json()
#         assert "users" in data

#     @pytest.mark.asyncio
#     async def test_list_users_pagination_page_parameter(self, client, existing_user, auth_headers):
#         """
#         GIVEN  page parameter
#         WHEN   GET / with page parameter is called
#         THEN   returns correct page offset
#         """
#         # Act
#         response = await client.get("/admin/users/?page=2&limit=5", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200

#     @pytest.mark.asyncio
#     async def test_list_users_respects_limit_parameter(self, client, existing_user, auth_headers):
#         """
#         GIVEN  limit parameter
#         WHEN   GET / with limit parameter is called
#         THEN   respects the limit (max 500)
#         """
#         # Act
#         response = await client.get("/admin/users/?page=1&limit=5", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200
#         data = response.json()
#         assert len(data["users"]) <= 5

#     @pytest.mark.asyncio
#     async def test_list_users_invalid_limit_exceeds_max(self, client, auth_headers):
#         """
#         GIVEN  limit exceeds maximum (500)
#         WHEN   GET / with invalid limit is called
#         THEN   returns 422 validation error
#         """
#         # Act
#         response = await client.get("/admin/users/?page=1&limit=1000", headers=auth_headers)

#         # Assert
#         assert response.status_code == 422

#     @pytest.mark.asyncio
#     async def test_list_users_invalid_page_less_than_one(self, client, auth_headers):
#         """
#         GIVEN  page is less than 1
#         WHEN   GET / with invalid page is called
#         THEN   returns 422 validation error
#         """
#         # Act
#         response = await client.get("/admin/users/?page=0&limit=10", headers=auth_headers)

#         # Assert
#         assert response.status_code == 422


# # ─────────────────────────────────────────────────────────────────────────────
# # USERS WITH ROLES ENDPOINTS
# # ─────────────────────────────────────────────────────────────────────────────

# class TestGetUsersWithRoles:
#     """Tests for GET /roles"""

#     @pytest.mark.asyncio
#     async def test_get_users_with_roles_returns_users_and_role_names(self, client, existing_user, auth_headers):
#         """
#         GIVEN  users with roles exist
#         WHEN   GET /roles is called
#         THEN   returns paginated response with users and aggregated role names
#         """
#         # Act
#         response = await client.get("/admin/users/roles?page=1&limit=10", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200
#         data = response.json()
#         assert "total" in data
#         assert "users" in data
#         if len(data["users"]) > 0:
#             user = data["users"][0]
#             assert "name" in user
#             assert "roles" in user
#             assert isinstance(user["roles"], list)

#     @pytest.mark.asyncio
#     async def test_get_users_with_roles_with_search(self, client, existing_user, auth_headers):
#         """
#         GIVEN  a search term
#         WHEN   GET /roles with search parameter is called
#         THEN   returns filtered users with roles
#         """
#         # Act
#         response = await client.get("/admin/users/roles?page=1&limit=10&search=john", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200


# class TestGetUsersWithRolesId:
#     """Tests for GET /id/roles"""

#     @pytest.mark.asyncio
#     async def test_get_users_with_roles_id_returns_list(self, client, existing_user, auth_headers):
#         """
#         GIVEN  users with role assignments exist
#         WHEN   GET /id/roles is called
#         THEN   returns list of users with user_id and aggregated role names
#         """
#         # Act
#         response = await client.get("/admin/users/id/roles", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200
#         data = response.json()
#         assert isinstance(data, list)
#         if len(data) > 0:
#             user = data[0]
#             assert "user_id" in user
#             assert "name" in user
#             assert "roles" in user
#             assert isinstance(user["roles"], list)


# # ─────────────────────────────────────────────────────────────────────────────
# # GET USER ENDPOINTS
# # ─────────────────────────────────────────────────────────────────────────────

# class TestGetUser:
#     """Tests for GET /{user_id}"""

#     @pytest.mark.asyncio
#     async def test_get_user_by_id_returns_user(self, client, existing_user, auth_headers):
#         """
#         GIVEN  a user_id that exists
#         WHEN   GET /{user_id} is called
#         THEN   returns 200 with user data
#         """
#         # Arrange
#         user_data = existing_user
#         user_id = user_data.get("user_id")

#         # Act
#         response = await client.get(f"/admin/users/{user_id}", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200
#         data = response.json()
#         assert data["first_name"] is not None
#         assert data["mail"] is not None

#     @pytest.mark.asyncio
#     async def test_get_user_by_id_not_found_returns_404(self, client, auth_headers):
#         """
#         GIVEN  a user_id that doesn't exist
#         WHEN   GET /{user_id} is called
#         THEN   returns 404
#         """
#         # Act
#         response = await client.get("/admin/users/999999", headers=auth_headers)

#         # Assert
#         assert response.status_code == 404


# class TestGetUserByUuid:
#     """Tests for GET /uuid/{user_uuid}"""

#     @pytest.mark.asyncio
#     async def test_get_user_by_uuid_returns_user(self, client, existing_user, auth_headers):
#         """
#         GIVEN  a user_uuid that exists
#         WHEN   GET /uuid/{user_uuid} is called
#         THEN   returns 200 with user data
#         """
#         # Arrange
#         user_data = existing_user
#         user_uuid = user_data.get("user_uuid")

#         # Act
#         response = await client.get(f"/admin/users/uuid/{user_uuid}", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200

#     @pytest.mark.asyncio
#     async def test_get_user_by_uuid_not_found_returns_404(self, client, auth_headers):
#         """
#         GIVEN  a user_uuid that doesn't exist
#         WHEN   GET /uuid/{user_uuid} is called
#         THEN   returns 404
#         """
#         # Act
#         response = await client.get("/admin/users/uuid/nonexistent-uuid", headers=auth_headers)

#         # Assert
#         assert response.status_code == 404


# # ─────────────────────────────────────────────────────────────────────────────
# # CREATE USER ENDPOINTS
# # ─────────────────────────────────────────────────────────────────────────────

# class TestCreateUser:
#     """Tests for POST /"""

#     @pytest.mark.asyncio
#     async def test_create_user_successfully(self, client, auth_headers):
#         """
#         GIVEN  valid user creation data
#         WHEN   POST / is called
#         THEN   returns 200 with created user data
#         """
#         # Act
#         response = await client.post("/admin/users/", headers=auth_headers, json={
#             "first_name": "Alice",
#             "last_name": "Wagner",
#             "mail": "alice.wagner@example.com",
#             "contact": "9876543210",
#             "password": "SecurePass123!",
#             "is_active": True
#         })

#         # Assert
#         assert response.status_code == 200
#         data = response.json()
#         assert data["first_name"] == "Alice"
#         assert data["mail"] == "alice.wagner@example.com"

#     @pytest.mark.asyncio
#     async def test_create_user_with_invalid_email_returns_400(self, client, auth_headers):
#         """
#         GIVEN  invalid email format
#         WHEN   POST / is called
#         THEN   returns 400 validation error
#         """
#         # Act
#         response = await client.post("/admin/users/", headers=auth_headers, json={
#             "first_name": "Bob",
#             "last_name": "Smith",
#             "mail": "invalid-email",
#             "contact": "9876543210",
#             "password": "SecurePass123",
#             "is_active": True
#         })

#         # Assert
#         assert response.status_code == 422

#     @pytest.mark.asyncio
#     async def test_create_user_with_existing_email_returns_400(self, client, existing_user, auth_headers):
#         """
#         GIVEN  email that already exists
#         WHEN   POST / is called
#         THEN   returns 400 with error message
#         """
#         # Act
#         response = await client.post("/admin/users/", headers=auth_headers, json={
#             "first_name": "John",
#             "last_name": "Duplicate",
#             "mail": "john.doe@example.com",
#             "contact": "9876543210",
#             "password": "SecurePass123",
#             "is_active": True
#         })

#         # Assert
#         assert response.status_code == 400

#     @pytest.mark.asyncio
#     async def test_create_user_missing_required_field_returns_422(self, client, auth_headers):
#         """
#         GIVEN  missing required field
#         WHEN   POST / is called
#         THEN   returns 422 validation error
#         """
#         # Act
#         response = await client.post("/admin/users/", headers=auth_headers, json={
#             "first_name": "Charlie",
#             "last_name": "Brown",
#             "mail": "charlie@example.com"
#             # Missing contact and password
#         })

#         # Assert
#         assert response.status_code == 422

#     @pytest.mark.asyncio
#     async def test_create_user_with_weak_password_returns_400(self, client, auth_headers):
#         """
#         GIVEN  password that doesn't meet strength requirements
#         WHEN   POST / is called
#         THEN   returns 400 with error message
#         """
#         # Act
#         response = await client.post("/admin/users/", headers=auth_headers, json={
#             "first_name": "David",
#             "last_name": "Lee",
#             "mail": "david@example.com",
#             "contact": "9876543210",
#             "password": "weak",  # Too weak
#             "is_active": True
#         })

#         # Assert
#         assert response.status_code == 400


# # ─────────────────────────────────────────────────────────────────────────────
# # UPDATE USER ENDPOINTS
# # ─────────────────────────────────────────────────────────────────────────────

# class TestUpdateUser:
#     """Tests for PUT /{user_id} and PUT /uuid/{user_uuid}"""

#     @pytest.mark.asyncio
#     async def test_update_user_by_id_successfully(self, client, existing_user, auth_headers):
#         """
#         GIVEN  a user_id that exists and valid update data
#         WHEN   PUT /{user_id} is called
#         THEN   returns 200 with updated user data
#         """
#         # Arrange
#         user_id = existing_user.get("user_id")

#         # Act
#         response = await client.put(f"/admin/users/{user_id}", headers=auth_headers, json={
#             "first_name": "Jonathan",
#             "last_name": "Doe",
#             "mail": existing_user.get("mail"),
#             "contact": "9876543210",
#             "is_active": True
#         })

#         # Assert
#         assert response.status_code == 200
#         data = response.json()
#         assert data["first_name"] == "Jonathan"

#     @pytest.mark.asyncio
#     async def test_update_user_by_id_not_found_returns_404(self, client, auth_headers):
#         """
#         GIVEN  a user_id that doesn't exist
#         WHEN   PUT /{user_id} is called
#         THEN   returns 404
#         """
#         # Act
#         response = await client.put("/admin/users/999999", headers=auth_headers, json={
#             "first_name": "Ghost",
#             "last_name": "User",
#             "mail": "ghost@example.com",
#             "contact": "9876543210",
#             "is_active": True
#         })

#         # Assert
#         assert response.status_code == 404

#     @pytest.mark.asyncio
#     async def test_update_user_with_invalid_email_returns_400(self, client, existing_user, auth_headers):
#         """
#         GIVEN  invalid email format in update data
#         WHEN   PUT /{user_id} is called
#         THEN   returns 400
#         """
#         # Arrange
#         user_id = existing_user.get("user_id")

#         # Act
#         response = await client.put(f"/admin/users/{user_id}", headers=auth_headers, json={
#             "first_name": "John",
#             "last_name": "Doe",
#             "mail": "not-an-email",
#             "contact": "9876543210",
#             "is_active": True
#         })

#         # Assert
#         assert response.status_code == 422


# # ─────────────────────────────────────────────────────────────────────────────
# # DEACTIVATE / ACTIVATE ENDPOINTS
# # ─────────────────────────────────────────────────────────────────────────────

# class TestDeactivateUser:
#     """Tests for DELETE /{user_id} and DELETE /uuid/{user_uuid}"""

#     @pytest.mark.asyncio
#     async def test_deactivate_user_by_id_successfully(self, client, existing_user, auth_headers):
#         """
#         GIVEN  a user_id that exists
#         WHEN   DELETE /{user_id} is called
#         THEN   returns 200 with success message
#         """
#         # Arrange
#         user_id = existing_user.get("user_id")

#         # Act
#         response = await client.delete(f"/admin/users/{user_id}", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200
#         assert "deactivated successfully" in response.json()["message"].lower()

#     @pytest.mark.asyncio
#     async def test_deactivate_user_by_id_not_found_returns_404(self, client, auth_headers):
#         """
#         GIVEN  a user_id that doesn't exist
#         WHEN   DELETE /{user_id} is called
#         THEN   returns 404
#         """
#         # Act
#         response = await client.delete("/admin/users/999999", headers=auth_headers)

#         # Assert
#         assert response.status_code == 404

#     @pytest.mark.asyncio
#     async def test_deactivate_user_by_uuid_successfully(self, client, existing_user, auth_headers):
#         """
#         GIVEN  a user_uuid that exists
#         WHEN   DELETE /uuid/{user_uuid} is called
#         THEN   returns 200 with success message
#         """
#         # Arrange
#         user_uuid = existing_user.get("user_uuid")

#         # Act
#         response = await client.delete(f"/admin/users/uuid/{user_uuid}", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200
#         assert "deactivated successfully" in response.json()["message"].lower()


# class TestActivateUser:
#     """Tests for PATCH /uuid/{user_uuid}/activate"""

#     @pytest.mark.asyncio
#     async def test_activate_user_successfully(self, client, existing_user, auth_headers):
#         """
#         GIVEN  a deactivated user
#         WHEN   PATCH /uuid/{user_uuid}/activate is called
#         THEN   returns 200 with success message
#         """
#         # Arrange
#         user_uuid = existing_user.get("user_uuid")
        
#         # First deactivate
#         await client.delete(f"/admin/users/uuid/{user_uuid}", headers=auth_headers)

#         # Act
#         response = await client.patch(f"/admin/users/uuid/{user_uuid}/activate", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200
#         assert "activated successfully" in response.json()["message"].lower()

#     @pytest.mark.asyncio
#     async def test_activate_user_not_found_returns_404(self, client, auth_headers):
#         """
#         GIVEN  a user_uuid that doesn't exist
#         WHEN   PATCH /uuid/{user_uuid}/activate is called
#         THEN   returns 404
#         """
#         # Act
#         response = await client.patch("/admin/users/uuid/nonexistent-uuid/activate", headers=auth_headers)

#         # Assert
#         assert response.status_code == 404


# # ─────────────────────────────────────────────────────────────────────────────
# # UPDATE ROLES ENDPOINTS
# # ─────────────────────────────────────────────────────────────────────────────

# class TestUpdateUserRoles:
#     """Tests for PUT /{user_id}/role and PUT /uuid/{user_uuid}/role"""

#     @pytest.mark.asyncio
#     async def test_update_user_roles_by_id_successfully(self, client, existing_user, auth_headers):
#         """
#         GIVEN  a valid user_id and list of role_ids
#         WHEN   PUT /{user_id}/role is called
#         THEN   returns 200 with success message
#         """
#         # Arrange
#         user_id = existing_user.get("user_id")

#         # Act
#         response = await client.put(f"/admin/users/{user_id}/role", headers=auth_headers, json={
#             "role_ids": ["2"]  # Assuming role_id 2 exists
#         })

#         # Assert
#         assert response.status_code == 200
#         assert "message" in response.json()

#     @pytest.mark.asyncio
#     async def test_update_user_roles_by_id_not_found_returns_404(self, client, auth_headers):
#         """
#         GIVEN  a user_id that doesn't exist
#         WHEN   PUT /{user_id}/role is called
#         THEN   returns 404
#         """
#         # Act
#         response = await client.put("/admin/users/999999/role", headers=auth_headers, json={
#             "role_ids": ["1"]
#         })

#         # Assert
#         assert response.status_code == 404

#     @pytest.mark.asyncio
#     async def test_update_user_roles_by_uuid_successfully(self, client, existing_user, auth_headers):
#         """
#         GIVEN  a valid user_uuid and list of role_uuids
#         WHEN   PUT /uuid/{user_uuid}/role is called
#         THEN   returns 200 with success message
#         """
#         # Arrange
#         user_uuid = existing_user.get("user_uuid")

#         # Act
#         response = await client.put(f"/admin/users/uuid/{user_uuid}/role", headers=auth_headers, json={
#             "role_ids": ["role-uuid-1"]  # Assuming role UUID exists
#         })

#         # Assert
#         assert response.status_code == 200 or response.status_code in [400, 500]  # Graceful handling


# # ─────────────────────────────────────────────────────────────────────────────
# # GET USER ROLES ENDPOINTS
# # ─────────────────────────────────────────────────────────────────────────────

# class TestGetUserRoles:
#     """Tests for GET /{user_id}/roles and GET /uuid/{user_uuid}/roles"""

#     @pytest.mark.asyncio
#     async def test_get_user_roles_by_id_returns_roles_list(self, client, existing_user, auth_headers):
#         """
#         GIVEN  a user_id that exists
#         WHEN   GET /{user_id}/roles is called
#         THEN   returns 200 with roles list
#         """
#         # Arrange
#         user_id = existing_user.get("user_id")

#         # Act
#         response = await client.get(f"/admin/users/{user_id}/roles", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200
#         data = response.json()
#         assert "roles" in data
#         assert isinstance(data["roles"], list)

#     @pytest.mark.asyncio
#     async def test_get_user_roles_by_id_not_found_returns_404(self, client, auth_headers):
#         """
#         GIVEN  a user_id that doesn't exist
#         WHEN   GET /{user_id}/roles is called
#         THEN   returns 404
#         """
#         # Act
#         response = await client.get("/admin/users/999999/roles", headers=auth_headers)

#         # Assert
#         assert response.status_code == 404

#     @pytest.mark.asyncio
#     async def test_get_user_roles_by_uuid_returns_roles_list(self, client, existing_user, auth_headers):
#         """
#         GIVEN  a user_uuid that exists
#         WHEN   GET /uuid/{user_uuid}/roles is called
#         THEN   returns 200 with roles list
#         """
#         # Arrange
#         user_uuid = existing_user.get("user_uuid")

#         # Act
#         response = await client.get(f"/admin/users/uuid/{user_uuid}/roles", headers=auth_headers)

#         # Assert
#         assert response.status_code == 200
#         data = response.json()
#         assert "roles" in data
#         assert isinstance(data["roles"], list)

#     @pytest.mark.asyncio
#     async def test_get_user_roles_by_uuid_not_found_returns_404(self, client, auth_headers):
#         """
#         GIVEN  a user_uuid that doesn't exist
#         WHEN   GET /uuid/{user_uuid}/roles is called
#         THEN   returns 404
#         """
#         # Act
#         response = await client.get("/admin/users/uuid/nonexistent-uuid/roles", headers=auth_headers)

#         # Assert
#         assert response.status_code == 404
