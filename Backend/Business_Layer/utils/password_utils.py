from passlib.hash import bcrypt
from fastapi import HTTPException, status

def hash_password(password: str) -> str:
    """
    Hash a plaintext password using bcrypt.
    """
    return bcrypt.hash(password)


def verify_password(plain_password: str, hashed_password: str):
    if not bcrypt.verify(plain_password, hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


def check_password_or_raise(plain_password: str, hashed_password: str):
    """
    Verify password and raise HTTPException if invalid.
    Useful during login or password update validation.
    """
    if not verify_password(plain_password, hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password"
        )
