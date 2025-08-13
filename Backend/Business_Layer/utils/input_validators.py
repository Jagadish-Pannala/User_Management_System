import re
from fastapi import HTTPException, status
from sqlalchemy.orm import Session


def validate_email_format(email: str):
    """Validate the format of the email using regex."""
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w{2,}$'  # more flexible TLD length
    if not re.match(email_regex, email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email format"
        )


def validate_password_strength(password: str):
    """
    Validate password strength:
    - At least 8 characters
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least one special character
    """
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long"
        )

    if not re.search(r'[A-Z]', password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one uppercase letter"
        )

    if not re.search(r'[a-z]', password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one lowercase letter"
        )

    if not re.search(r'\d', password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one digit"
        )

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one special character"
        )


def validate_contact_number(contact: str):
    """
    Validate contact number:
    - Allows optional '+' prefix
    - 7 to 15 digits
    """
    contact_regex = r'^\+?\d{7,15}$'
    if not re.match(contact_regex, contact):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid contact number format"
        )


def validate_name(name: str):
    """
    Validate name:
    - Allows letters, spaces, hyphens, apostrophes
    - No digits or special symbols
    """
    name_regex = r"^[A-Za-zÀ-ÖØ-öø-ÿ' -]+$"
    if not re.match(name_regex, name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid name format. Only letters, spaces, hyphens, and apostrophes are allowed."
        )
