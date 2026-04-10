"""
tests/unit/Business_Layer/utils/test_input_validators.py

Unit tests for:  Business_Layer/utils/input_validators.py
Function tested: validate_email_format()

No mocking needed — pure logic function.
"""

import pytest
from fastapi import HTTPException


# ─────────────────────────────────────────────────────────────────────────────
# Import the function under test
# ─────────────────────────────────────────────────────────────────────────────

from Backend.Business_Layer.utils.input_validators import validate_email_format


class TestValidateEmailFormat:

    # ── Happy path ─────────────────────────────────────────────────────────

    def test_valid_email_does_not_raise(self):
        """
        GIVEN  a properly formatted email
        WHEN   validate_email_format() is called
        THEN   no exception is raised
        """
        validate_email_format("user@example.com")   # must not raise

    def test_valid_email_with_subdomain_does_not_raise(self):
        """Subdomains like user@mail.example.com must be valid."""
        validate_email_format("user@mail.example.com")

    def test_valid_email_with_plus_tag_does_not_raise(self):
        """Plus-tagged emails like user+tag@example.com must be valid."""
        validate_email_format("user+tag@example.com")

    # ── Failure cases ──────────────────────────────────────────────────────

    def test_missing_at_symbol_raises_422(self):
        """
        GIVEN  an email missing the @ symbol
        WHEN   validate_email_format() is called
        THEN   HTTPException 422 must be raised
        """
        with pytest.raises(HTTPException) as exc_info:
            validate_email_format("userexample.com")
        assert exc_info.value.status_code == 422

    def test_missing_domain_raises_422(self):
        """Email with no domain part (user@) must fail."""
        with pytest.raises(HTTPException) as exc_info:
            validate_email_format("user@")
        assert exc_info.value.status_code == 422

    def test_missing_local_part_raises_422(self):
        """Email with no local part (@example.com) must fail."""
        with pytest.raises(HTTPException) as exc_info:
            validate_email_format("@example.com")
        assert exc_info.value.status_code == 422

    def test_empty_string_raises_422(self):
        """Empty string must not pass email validation."""
        with pytest.raises(HTTPException) as exc_info:
            validate_email_format("")
        assert exc_info.value.status_code == 422

    def test_whitespace_only_raises_422(self):
        """Whitespace-only string must fail."""
        with pytest.raises(HTTPException):
            validate_email_format("   ")

    def test_none_raises_exception(self):
        """None must raise an exception (TypeError or HTTPException)."""
        with pytest.raises((HTTPException, TypeError, AttributeError)):
            validate_email_format(None)

    def test_plain_text_no_at_raises_422(self):
        """Plain text without any email structure must fail."""
        with pytest.raises(HTTPException) as exc_info:
            validate_email_format("notanemail")
        assert exc_info.value.status_code == 422
