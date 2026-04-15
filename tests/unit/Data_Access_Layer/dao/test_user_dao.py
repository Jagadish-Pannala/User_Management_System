"""
tests/unit/Data_Access_Layer/dao/test_user_dao.py

Unit tests for:  Data_Access_Layer/dao/user_dao.py
Methods tested:
  - get_user_by_id(), get_user_by_uuid(), get_user_by_email()
  - count_users(), count_active_users()
  - get_paginated_users(), get_users_with_roles()
  - create_user(), create_users_batch()
  - update_user(), deactivate_user(), activate_user()
  - Role mapping operations

DB is fully mocked — no real PostgreSQL connection.
"""

import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime
from sqlalchemy.exc import SQLAlchemyError


# ─────────────────────────────────────────────────────────────────────────────
# Helper — build UserDAO with fake DB session
# ─────────────────────────────────────────────────────────────────────────────

def make_user_dao(mock_db=None):
    """
    Creates UserDAO with a mocked DB session injected.
    Bypasses __init__ so no real DB connection is attempted.
    """
    from Backend.Data_Access_Layer.dao.user_dao import UserDAO
    dao = UserDAO.__new__(UserDAO)
    dao.db = mock_db or MagicMock()
    return dao


def make_mock_user(user_id=1, first_name="John", last_name="Doe",
                   email="john@example.com", is_active=True):
    """Helper to create mock user objects."""
    user = MagicMock()
    user.user_id = user_id
    user.user_uuid = f"uuid-{user_id}"
    user.first_name = first_name
    user.last_name = last_name
    user.mail = email
    user.contact = "9876543210"
    user.password = "$2b$12$hashedpassword"
    user.is_active = is_active
    user.created_at = datetime.utcnow()
    user.updated_at = datetime.utcnow()
    user.gender = None
    return user


# ─────────────────────────────────────────────────────────────────────────────
# GET OPERATIONS — User Reads
# ─────────────────────────────────────────────────────────────────────────────

class TestGetUserByEmail:
    """Tests for get_user_by_email()"""

    def test_returns_user_when_email_exists(self, mock_db):
        """
        GIVEN  a user with email in database
        WHEN   get_user_by_email() is called
        THEN   returns the User object
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_user = make_mock_user(email="john@example.com")
        mock_db.query.return_value.filter_by.return_value.first.return_value = mock_user

        # Act
        result = dao.get_user_by_email("john@example.com")

        # Assert
        assert result == mock_user

    def test_returns_none_when_email_not_found(self, mock_db):
        """
        GIVEN  an email that doesn't exist in database
        WHEN   get_user_by_email() is called
        THEN   returns None
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_db.query.return_value.filter_by.return_value.first.return_value = None

        # Act
        result = dao.get_user_by_email("nonexistent@example.com")

        # Assert
        assert result is None


class TestGetUserById:
    """Tests for get_user_by_id()"""

    def test_returns_user_when_id_exists(self, mock_db):
        """
        GIVEN  a user with user_id in database
        WHEN   get_user_by_id() is called
        THEN   returns the User object
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_user = make_mock_user(user_id=42)
        mock_db.query.return_value.filter_by.return_value.first.return_value = mock_user

        # Act
        result = dao.get_user_by_id(42)

        # Assert
        assert result == mock_user
        assert result.user_id == 42

    def test_returns_none_when_id_not_found(self, mock_db):
        """
        GIVEN  a user_id that doesn't exist
        WHEN   get_user_by_id() is called
        THEN   returns None
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_db.query.return_value.filter_by.return_value.first.return_value = None

        # Act
        result = dao.get_user_by_id(99999)

        # Assert
        assert result is None


class TestGetUserByUuid:
    """Tests for get_user_by_uuid()"""

    def test_returns_user_when_uuid_exists(self, mock_db):
        """
        GIVEN  a user with user_uuid in database
        WHEN   get_user_by_uuid() is called
        THEN   returns the User object
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_user = make_mock_user(user_id=5)
        mock_db.query.return_value.filter_by.return_value.first.return_value = mock_user

        # Act
        result = dao.get_user_by_uuid("uuid-5")

        # Assert
        assert result == mock_user
        assert result.user_uuid == "uuid-5"

    def test_returns_none_when_uuid_not_found(self, mock_db):
        """
        GIVEN  a user_uuid that doesn't exist
        WHEN   get_user_by_uuid() is called
        THEN   returns None
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_db.query.return_value.filter_by.return_value.first.return_value = None

        # Act
        result = dao.get_user_by_uuid("nonexistent-uuid")

        # Assert
        assert result is None


class TestCountUsers:
    """Tests for count_users() and count_active_users()"""

    def test_count_users_returns_total_count(self, mock_db):
        """
        GIVEN  a database with users
        WHEN   count_users() is called
        THEN   returns the total number of users
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_db.query.return_value.count.return_value = 42

        # Act
        result = dao.count_users()

        # Assert
        assert result == 42

    def test_count_active_users_returns_only_active_count(self, mock_db):
        """
        GIVEN  a database with both active and inactive users
        WHEN   count_active_users() is called
        THEN   returns only the count of active users
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_db.query.return_value.filter.return_value.count.return_value = 35

        # Act
        result = dao.count_active_users()

        # Assert
        assert result == 35


class TestGetPaginatedUsers:
    """Tests for get_paginated_users()"""

    def test_returns_paginated_result_with_users(self, mock_db):
        """
        GIVEN  a database with users
        WHEN   get_paginated_users(page=1, limit=10) is called
        THEN   returns dict with 'total' and 'users' list
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_users = [make_mock_user(user_id=i) for i in range(1, 4)]
        
        # Mock the query chain for count and data fetch
        mock_query = MagicMock()
        mock_query.count.return_value = 3
        mock_query.order_by.return_value.offset.return_value.limit.return_value.all.return_value = mock_users
        mock_db.query.return_value = mock_query

        # Act
        result = dao.get_paginated_users(page=1, limit=10)

        # Assert
        assert result["total"] == 3
        assert len(result["users"]) == 3
        assert result["users"] == mock_users

    def test_applies_search_filter_when_search_term_provided(self, mock_db):
        """
        GIVEN  a search term
        WHEN   get_paginated_users() is called with search parameter
        THEN   applies filter to search across first_name, last_name, mail, contact
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_user = make_mock_user(first_name="Alice")
        
        mock_query = MagicMock()
        mock_query.filter.return_value.count.return_value = 1
        mock_query.filter.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = [mock_user]
        mock_db.query.return_value = mock_query

        # Act
        result = dao.get_paginated_users(page=1, limit=10, search="Alice")

        # Assert
        assert result["total"] == 1
        assert len(result["users"]) == 1

    def test_returns_correct_offset_for_pagination(self, mock_db):
        """
        GIVEN  page=3, limit=10
        WHEN   get_paginated_users() is called
        THEN   offset should be (3-1)*10 = 20
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_query = MagicMock()
        mock_query.count.return_value = 100
        mock_query.order_by.return_value.offset.return_value.limit.return_value.all.return_value = []
        mock_db.query.return_value = mock_query

        # Act
        dao.get_paginated_users(page=3, limit=10)

        # Assert
        # Verify offset was called with 20 (page 3, limit 10 → offset = 20)
        mock_query.order_by.return_value.offset.assert_called_once_with(20)

    def test_returns_empty_users_list_when_no_users_exist(self, mock_db):
        """
        GIVEN  a database with no users
        WHEN   get_paginated_users() is called
        THEN   returns total=0 and users=[]
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_query = MagicMock()
        mock_query.count.return_value = 0
        mock_query.order_by.return_value.offset.return_value.limit.return_value.all.return_value = []
        mock_db.query.return_value = mock_query

        # Act
        result = dao.get_paginated_users(page=1, limit=10)

        # Assert
        assert result["total"] == 0
        assert result["users"] == []


class TestGetUsersWithRolesId:
    """Tests for get_users_with_roles_id()"""

    def test_returns_users_with_role_names_aggregated(self, mock_db):
        """
        GIVEN  users with assigned roles
        WHEN   get_users_with_roles_id() is called
        THEN   returns list of dicts with user_id, name, roles, email
        """
        # Arrange
        dao = make_user_dao(mock_db)
        
        # Simulate multi-row result from query
        mock_result = [
            MagicMock(user_id=1, first_name="John", last_name="Doe", mail="john@example.com", role_name="Admin"),
            MagicMock(user_id=1, first_name="John", last_name="Doe", mail="john@example.com", role_name="User"),
            MagicMock(user_id=2, first_name="Jane", last_name="Smith", mail="jane@example.com", role_name="User"),
        ]
        mock_db.query.return_value.join.return_value.join.return_value.order_by.return_value.all.return_value = mock_result

        # Act
        result = dao.get_users_with_roles_id()

        # Assert
        assert len(result) == 2  # 2 users
        assert result[0]["user_id"] == 1
        assert "John Doe" in result[0]["name"]
        assert "Admin" in result[0]["roles"]
        assert "User" in result[0]["roles"]


class TestGetUserRoles:
    """Tests for get_user_roles() and related role operations"""

    def test_returns_role_names_for_user(self, mock_db):
        """
        GIVEN  a user with assigned roles
        WHEN   get_user_roles() is called
        THEN   returns list of role names as strings
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_roles = [
            ("Admin",),
            ("User",),
        ]
        mock_db.query.return_value.join.return_value.filter.return_value.all.return_value = mock_roles

        # Act
        result = dao.get_user_roles(user_id=1)

        # Assert
        assert result == ["Admin", "User"]

    def test_returns_empty_list_when_user_has_no_roles(self, mock_db):
        """
        GIVEN  a user with no assigned roles
        WHEN   get_user_roles() is called
        THEN   returns empty list
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_db.query.return_value.join.return_value.filter.return_value.all.return_value = []

        # Act
        result = dao.get_user_roles(user_id=99)

        # Assert
        assert result == []


# ─────────────────────────────────────────────────────────────────────────────
# CREATE OPERATIONS — User Creation
# ─────────────────────────────────────────────────────────────────────────────

class TestCreateUser:
    """Tests for create_user()"""

    def test_creates_user_successfully(self, mock_db):
        """
        GIVEN  a valid User object
        WHEN   create_user() is called
        THEN   user is added to DB and returned with ID
        """
        # Arrange
        dao = make_user_dao(mock_db)
        new_user = make_mock_user()
        mock_db.refresh = MagicMock()

        # Act
        result = dao.create_user(new_user)

        # Assert
        assert result == new_user
        mock_db.add.assert_called_once_with(new_user)
        mock_db.commit.assert_called_once()

    def test_rollback_on_database_error(self, mock_db):
        """
        GIVEN  a database error occurs during insert
        WHEN   create_user() is called
        THEN   transaction is rolled back and error is re-raised
        """
        # Arrange
        dao = make_user_dao(mock_db)
        new_user = make_mock_user()
        mock_db.add.side_effect = SQLAlchemyError("DB error")

        # Act & Assert
        with pytest.raises(SQLAlchemyError):
            dao.create_user(new_user)
        
        mock_db.rollback.assert_called_once()

    def test_sets_timestamps_on_creation(self, mock_db):
        """
        GIVEN  a new user without timestamps
        WHEN   create_user() is called
        THEN   created_at and updated_at are set to current UTC time
        """
        # Arrange
        dao = make_user_dao(mock_db)
        new_user = make_mock_user()
        new_user.created_at = None
        new_user.updated_at = None

        # Act
        with patch("Backend.Data_Access_Layer.dao.user_dao.datetime") as mock_datetime:
            mock_now = datetime.utcnow()
            mock_datetime.utcnow.return_value = mock_now
            dao.create_user(new_user)

        # Assert — timestamps should be set
        assert new_user.updated_at is not None


class TestCreateUsersBatch:
    """Tests for create_users_batch()"""

    def test_creates_multiple_users_in_single_transaction(self, mock_db):
        """
        GIVEN  a list of User objects
        WHEN   create_users_batch() is called
        THEN   all users are inserted in a single transaction
        """
        # Arrange
        dao = make_user_dao(mock_db)
        users = [make_mock_user(user_id=i) for i in range(1, 4)]
        mock_db.refresh = MagicMock()

        # Act
        result = dao.create_users_batch(users)

        # Assert
        assert result == users
        mock_db.add_all.assert_called_once_with(users)
        mock_db.commit.assert_called_once()

    def test_returns_empty_list_when_empty_input(self, mock_db):
        """
        GIVEN  an empty list of users
        WHEN   create_users_batch() is called
        THEN   returns empty list immediately
        """
        # Arrange
        dao = make_user_dao(mock_db)

        # Act
        result = dao.create_users_batch([])

        # Assert
        assert result == []
        mock_db.add_all.assert_not_called()

    def test_rollback_all_on_batch_error(self, mock_db):
        """
        GIVEN  a batch insert error occurs
        WHEN   create_users_batch() is called
        THEN   entire transaction is rolled back
        """
        # Arrange
        dao = make_user_dao(mock_db)
        users = [make_mock_user(user_id=i) for i in range(1, 4)]
        mock_db.add_all.side_effect = SQLAlchemyError("Batch error")

        # Act & Assert
        with pytest.raises(SQLAlchemyError):
            dao.create_users_batch(users)
        
        mock_db.rollback.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# UPDATE OPERATIONS — User Updates
# ─────────────────────────────────────────────────────────────────────────────

class TestUpdateUser:
    """Tests for update_user()"""

    def test_updates_user_fields_successfully(self, mock_db):
        """
        GIVEN  a user object and update data dict
        WHEN   update_user() is called
        THEN   specified fields are updated and True is returned
        """
        # Arrange
        dao = make_user_dao(mock_db)
        user = make_mock_user(user_id=1)
        update_data = {"first_name": "Jane", "mail": "jane@example.com"}

        # Act
        result = dao.update_user(user, update_data)

        # Assert
        assert result is True
        assert user.first_name == "Jane"
        assert user.mail == "jane@example.com"
        mock_db.commit.assert_called_once()

    def test_returns_false_on_update_error(self, mock_db):
        """
        GIVEN  a database error during update
        WHEN   update_user() is called
        THEN   returns False and transaction is rolled back
        """
        # Arrange
        dao = make_user_dao(mock_db)
        user = make_mock_user()
        update_data = {"first_name": "Jane"}
        mock_db.commit.side_effect = SQLAlchemyError("Update error")

        # Act
        result = dao.update_user(user, update_data)

        # Assert
        assert result is False
        mock_db.rollback.assert_called_once()

    def test_updates_updated_at_timestamp(self, mock_db):
        """
        GIVEN  a user update
        WHEN   update_user() is called
        THEN   updated_at timestamp is set to current UTC time
        """
        # Arrange
        dao = make_user_dao(mock_db)
        user = make_mock_user()
        user.updated_at = None
        update_data = {"first_name": "Jane"}

        # Act
        with patch("Backend.Data_Access_Layer.dao.user_dao.datetime") as mock_datetime:
            mock_now = datetime.utcnow()
            mock_datetime.utcnow.return_value = mock_now
            dao.update_user(user, update_data)

        # Assert
        assert user.updated_at is not None


class TestDeactivateUser:
    """Tests for deactivate_user() and activate_user()"""

    def test_deactivates_user_successfully(self, mock_db):
        """
        GIVEN  an active user
        WHEN   deactivate_user() is called
        THEN   is_active is set to False
        """
        # Arrange
        dao = make_user_dao(mock_db)
        user = make_mock_user(is_active=True)

        # Act
        dao.deactivate_user(user)

        # Assert
        assert user.is_active is False
        mock_db.commit.assert_called_once()

    def test_activates_user_successfully(self, mock_db):
        """
        GIVEN  an inactive user
        WHEN   activate_user() is called
        THEN   is_active is set to True
        """
        # Arrange
        dao = make_user_dao(mock_db)
        user = make_mock_user(is_active=False)

        # Act
        dao.activate_user(user)

        # Assert
        assert user.is_active is True
        mock_db.commit.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# ROLE MAPPING OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

class TestMapUserRole:
    """Tests for map_user_role() and role assignment"""

    def test_maps_single_user_to_role(self, mock_db):
        """
        GIVEN  a user_id, role_id, and assigned_by user_id
        WHEN   map_user_role() is called
        THEN   inserts the mapping via execute()
        """
        # Arrange
        dao = make_user_dao(mock_db)

        # Act
        dao.map_user_role(user_id=1, role_id=2, created_by_user_id=5)

        # Assert
        mock_db.execute.assert_called_once()
        mock_db.commit.assert_called_once()

    def test_handles_role_mapping_error(self, mock_db):
        """
        GIVEN  a database error during role mapping
        WHEN   map_user_role() is called
        THEN   transaction is rolled back
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_db.execute.side_effect = SQLAlchemyError("Mapping error")

        # Act & Assert
        with pytest.raises(SQLAlchemyError):
            dao.map_user_role(user_id=1, role_id=2, created_by_user_id=5)

        mock_db.rollback.assert_called_once()


class TestMapUserRolesBatch:
    """Tests for map_user_roles_batch()"""

    def test_creates_multiple_role_mappings_in_transaction(self, mock_db):
        """
        GIVEN  a list of (user_id, role_id, assigned_by_id) tuples
        WHEN   map_user_roles_batch() is called
        THEN   all mappings are created in a single transaction
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mappings = [(1, 2, 5), (2, 3, 5), (3, 2, 5)]

        # Act
        dao.map_user_roles_batch(mappings)

        # Assert
        mock_db.execute.assert_called_once()
        mock_db.commit.assert_called_once()

    def test_returns_early_for_empty_mappings_list(self, mock_db):
        """
        GIVEN  an empty list of mappings
        WHEN   map_user_roles_batch() is called
        THEN   no database operations are performed
        """
        # Arrange
        dao = make_user_dao(mock_db)

        # Act
        dao.map_user_roles_batch([])

        # Assert
        mock_db.add_all.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# HELPER OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

class TestGetRoleByName:
    """Tests for get_role_by_name()"""

    def test_returns_role_when_name_exists(self, mock_db):
        """
        GIVEN  a role name that exists
        WHEN   get_role_by_name() is called
        THEN   returns the Role object
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_role = MagicMock()
        mock_role.role_id = 1
        mock_role.role_name = "Admin"
        mock_db.query.return_value.filter.return_value.first.return_value = mock_role

        # Act
        result = dao.get_role_by_name("Admin")

        # Assert
        assert result == mock_role

    def test_returns_none_when_role_name_not_found(self, mock_db):
        """
        GIVEN  a role name that doesn't exist
        WHEN   get_role_by_name() is called
        THEN   returns None
        """
        # Arrange
        dao = make_user_dao(mock_db)
        mock_db.query.return_value.filter.return_value.first.return_value = None

        # Act
        result = dao.get_role_by_name("NonexistentRole")

        # Assert
        assert result is None


class TestGetUsersByEmails:
    """Tests for get_users_by_emails()"""

    def test_returns_existing_emails_from_database(self, mock_db):
        """
        GIVEN  a list of email addresses
        WHEN   get_users_by_emails() is called
        THEN   returns only the emails that exist in database
        """
        # Arrange
        dao = make_user_dao(mock_db)
        existing = [("john@example.com",), ("jane@example.com",)]
        mock_db.query.return_value.filter.return_value.all.return_value = existing

        # Act
        result = dao.get_users_by_emails(["john@example.com", "jane@example.com", "ghost@example.com"])

        # Assert
        assert result == ["john@example.com", "jane@example.com"]

    def test_returns_empty_list_for_empty_input(self, mock_db):
        """
        GIVEN  an empty list of emails
        WHEN   get_users_by_emails() is called
        THEN   returns empty list immediately
        """
        # Arrange
        dao = make_user_dao(mock_db)

        # Act
        result = dao.get_users_by_emails([])

        # Assert
        assert result == []
        mock_db.query.assert_not_called()
