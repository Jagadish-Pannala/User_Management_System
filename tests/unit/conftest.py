"""
tests/unit/conftest.py
Fixtures shared across ALL unit tests.
Everything is mocked — no real DB, no real HTTP.
"""

import pytest
from unittest.mock import MagicMock, patch


# ── Fake DAO with mocked DB session ───────────────────────────────────────────

@pytest.fixture
def mock_db():
    """A fully mocked SQLAlchemy session."""
    return MagicMock()


@pytest.fixture
def mock_auth_dao(mock_db):
    """
    AuthDAO instance with a fake DB session.
    Use this in unit tests for DAO methods so no real DB is touched.
    """
    from unittest.mock import MagicMock
    dao = MagicMock()
    dao.db = mock_db
    return dao


# ── Fake FastAPI Request ───────────────────────────────────────────────────────

@pytest.fixture
def mock_request():
    """Fake FastAPI Request object."""
    request = MagicMock()
    request.client.host = "127.0.0.1"
    request.headers     = {"host": "localhost"}
    request.url.scheme  = "http"
    return request


# ── Fake LoginUser schema ─────────────────────────────────────────────────────

@pytest.fixture
def login_credentials():
    """Fake LoginUser pydantic object."""
    creds = MagicMock()
    creds.email    = "john.doe@example.com"
    creds.password = "Secret123"
    return creds


@pytest.fixture
def login_credentials_wrong_password():
    creds = MagicMock()
    creds.email    = "john.doe@example.com"
    creds.password = "WrongPassword"
    return creds


@pytest.fixture
def login_credentials_bad_email():
    creds = MagicMock()
    creds.email    = "not-an-email"
    creds.password = "Secret123"
    return creds
