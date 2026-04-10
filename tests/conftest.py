# tests/conftest.py
"""
Root conftest.py
Shared fixtures available to ALL tests (unit + integration + contract)
"""

import pytest


# ── Sample raw credential payloads ────────────────────────────────────────────

@pytest.fixture
def valid_login_payload(existing_user):
    return {
        "email": existing_user["mail"],
        "password": existing_user["password"]
    }


@pytest.fixture
def invalid_email_payload():
    return {
        "email": "not-an-email",
        "password": "Secret123"
    }


@pytest.fixture
def wrong_password_payload(existing_user):
    return {
        "email": existing_user["mail"],
        "password": "WrongPassword"
    }


# ── Sample user object (mimics SQLAlchemy model row) ──────────────────────────

@pytest.fixture
def mock_user_row():
    """A fake User ORM object returned by the DB."""
    from unittest.mock import MagicMock
    from datetime import datetime

    user = MagicMock()
    user.user_id     = 1
    user.first_name  = "John"
    user.last_name   = "Doe"
    user.mail        = "john.doe@example.com"
    user.password    = "$2b$12$hashedpassword"   # bcrypt hash placeholder
    user.is_active   = True
    user.last_login_at         = datetime(2024, 1, 1, 10, 0, 0)
    user.password_last_updated = datetime(2024, 1, 1, 9, 0, 0)
    user.last_login_ip = "127.0.0.1"
    return user


@pytest.fixture
def mock_first_login_user_row():
    """A fake User that has never logged in before."""
    from unittest.mock import MagicMock

    user = MagicMock()
    user.user_id     = 2
    user.first_name  = "Jane"
    user.last_name   = "Smith"
    user.mail        = "jane.smith@example.com"
    user.password    = "$2b$12$hashedpassword"
    user.is_active   = True
    user.last_login_at         = None   # never logged in
    user.password_last_updated = None
    return user
