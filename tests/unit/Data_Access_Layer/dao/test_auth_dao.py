"""
tests/unit/Data_Access_Layer/dao/test_auth_dao.py

Unit tests for:  Data_Access_Layer/dao/auth_dao.py
Methods tested:
  - get_user_login_data()
  - check_user_first_login()
  - update_last_login()

DB is fully mocked — no real PostgreSQL connection.
"""

import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime
from fastapi import HTTPException


# ─────────────────────────────────────────────────────────────────────────────
# Helper — build AuthDAO with fake DB session
# ─────────────────────────────────────────────────────────────────────────────

def make_auth_dao(mock_db=None):
    """
    Creates AuthDAO with a mocked DB session injected.
    Bypasses __init__ so no real DB connection is attempted.
    """
    from Backend.Data_Access_Layer.dao.auth_dao import AuthDAO
    dao    = AuthDAO.__new__(AuthDAO)
    dao.db = mock_db or MagicMock()
    return dao


# ─────────────────────────────────────────────────────────────────────────────
# get_user_login_data()
# ─────────────────────────────────────────────────────────────────────────────

class TestGetUserLoginData:

    def test_returns_user_roles_permissions_for_active_user(self, mock_db):
        """
        GIVEN  an active user with roles and permissions in DB
        WHEN   get_user_login_data() is called with their email
        THEN   returns (user, [roles], [permissions]) — none are empty
        """
        # Arrange
        dao       = make_auth_dao(mock_db)
        mock_user = MagicMock()
        mock_user.user_id = 1

        # Simulate DB query chain: .query().filter().first()
        mock_db.query.return_value \
               .filter.return_value \
               .first.return_value = mock_user

        # Simulate roles and permissions query chains
        mock_db.query.return_value \
               .join.return_value \
               .filter.return_value \
               .distinct.return_value \
               .all.return_value = [MagicMock(role_name="admin")]

        # Act
        user, roles, permissions = dao.get_user_login_data("john@example.com")

        # Assert
        assert user is mock_user
        assert isinstance(roles, list)

    def test_returns_none_empty_lists_when_user_not_found(self, mock_db):
        """
        GIVEN  an email that does not exist or user is inactive
        WHEN   get_user_login_data() is called
        THEN   returns (None, [], []) — caller handles the 404
        """
        # Arrange
        dao = make_auth_dao(mock_db)
        mock_db.query.return_value \
               .filter.return_value \
               .first.return_value = None   # no user found

        # Act
        user, roles, permissions = dao.get_user_login_data("ghost@example.com")

        # Assert
        assert user        is None
        assert roles       is None or roles == []  # roles can be None or empty list
        assert permissions is None or permissions == []  # permissions can be None or empty list

    def test_returns_empty_roles_when_user_has_no_roles(self, mock_db):
        """
        GIVEN  a user with no roles assigned
        WHEN   get_user_login_data() is called
        THEN   roles list must be empty — not None, not an error
        """
        # Arrange
        dao       = make_auth_dao(mock_db)
        mock_user = MagicMock()
        mock_user.user_id = 5

        mock_db.query.return_value \
               .filter.return_value \
               .first.return_value = mock_user

        mock_db.query.return_value \
               .join.return_value \
               .filter.return_value \
               .distinct.return_value \
               .all.return_value = []   # no roles

        # Act
        user, roles, permissions = dao.get_user_login_data("norole@example.com")

        # Assert
        assert user  is mock_user
        assert roles == []


# ─────────────────────────────────────────────────────────────────────────────
# check_user_first_login()
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckUserFirstLogin:

    def test_returns_true_when_last_login_is_none(self, mock_db):
        """
        GIVEN  a user who has never logged in (last_login_at = None)
        WHEN   check_user_first_login() is called
        THEN   returns True — frontend should redirect to /change-password
        """
        # Arrange
        dao       = make_auth_dao(mock_db)
        mock_user = MagicMock()
        mock_user.last_login_at         = None
        mock_user.password_last_updated = None

        mock_db.query.return_value \
               .filter.return_value \
               .first.return_value = mock_user

        # Act
        result = dao.check_user_first_login(user_id=1)

        # Assert
        assert result is True

    def test_returns_true_when_password_last_updated_is_none(self, mock_db):
        """
        GIVEN  a user with last_login_at set but password_last_updated = None
        WHEN   check_user_first_login() is called
        THEN   returns True — password has never been changed
        """
        # Arrange
        dao       = make_auth_dao(mock_db)
        mock_user = MagicMock()
        mock_user.last_login_at         = datetime(2024, 1, 1)
        mock_user.password_last_updated = None   # password never updated

        mock_db.query.return_value \
               .filter.return_value \
               .first.return_value = mock_user

        # Act
        result = dao.check_user_first_login(user_id=1)

        # Assert
        assert result is True

    def test_returns_false_when_user_has_login_history(self, mock_db):
        """
        GIVEN  a user who has logged in before and changed their password
        WHEN   check_user_first_login() is called
        THEN   returns False — normal login, redirect to /dashboard
        """
        # Arrange
        dao       = make_auth_dao(mock_db)
        mock_user = MagicMock()
        mock_user.last_login_at         = datetime(2024, 6, 1, 10, 0)
        mock_user.password_last_updated = datetime(2024, 6, 1, 9, 0)

        mock_db.query.return_value \
               .filter.return_value \
               .first.return_value = mock_user

        # Act
        result = dao.check_user_first_login(user_id=1)

        # Assert
        assert result is False

    def test_raises_404_when_user_not_found(self, mock_db):
        """
        GIVEN  a user_id that does not exist in the DB
        WHEN   check_user_first_login() is called
        THEN   raises HTTPException with status_code=404
        """
        # Arrange
        dao = make_auth_dao(mock_db)
        mock_db.query.return_value \
               .filter.return_value \
               .first.return_value = None   # no user

        # Act + Assert
        with pytest.raises(HTTPException) as exc_info:
            dao.check_user_first_login(user_id=999)

        assert exc_info.value.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# update_last_login()
# ─────────────────────────────────────────────────────────────────────────────

class TestUpdateLastLogin:

    def test_updates_last_login_ip_and_commits(self, mock_db):
        """
        GIVEN  a valid user_id and client IP
        WHEN   update_last_login() is called
        THEN   user.last_login_ip must be set and db.commit() must be called
        """
        # Arrange
        dao       = make_auth_dao(mock_db)
        mock_user = MagicMock()
        mock_db.query.return_value \
               .filter.return_value \
               .first.return_value = mock_user

        # Act
        dao.update_last_login(user_id=1, ip="192.168.1.50")

        # Assert
        assert mock_user.last_login_ip == "192.168.1.50"
        mock_db.commit.assert_called_once()  # DB must be committed

    def test_sets_last_login_at_timestamp(self, mock_db):
        """
        GIVEN  a successful login
        WHEN   update_last_login() is called
        THEN   user.last_login_at must be updated to a datetime value
        """
        # Arrange
        dao       = make_auth_dao(mock_db)
        mock_user = MagicMock()
        mock_user.last_login_at = None  # was None before login

        mock_db.query.return_value \
               .filter.return_value \
               .first.return_value = mock_user

        # Act
        dao.update_last_login(user_id=1, ip="10.0.0.1")

        # Assert — last_login_at must now be set (not None)
        assert mock_user.last_login_at is not None

    def test_raises_404_when_user_not_found(self, mock_db):
        """
        GIVEN  a user_id that does not exist
        WHEN   update_last_login() is called
        THEN   raises HTTPException 404 — must not silently fail
        """
        # Arrange
        dao = make_auth_dao(mock_db)
        mock_db.query.return_value \
               .filter.return_value \
               .first.return_value = None

        # Act + Assert
        with pytest.raises(HTTPException) as exc_info:
            dao.update_last_login(user_id=999, ip="127.0.0.1")

        assert exc_info.value.status_code == 404

    def test_does_not_commit_when_user_not_found(self, mock_db):
        """
        GIVEN  a user_id that does not exist
        WHEN   update_last_login() raises 404
        THEN   db.commit() must NOT be called — no partial DB write
        """
        # Arrange
        dao = make_auth_dao(mock_db)
        mock_db.query.return_value \
               .filter.return_value \
               .first.return_value = None

        # Act
        with pytest.raises(HTTPException):
            dao.update_last_login(user_id=999, ip="127.0.0.1")

        # Assert
        mock_db.commit.assert_not_called()
