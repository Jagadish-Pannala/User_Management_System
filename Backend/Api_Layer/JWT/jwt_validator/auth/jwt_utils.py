# auth/jwt_utils.py
from .jwt_validator import validate_jwt_token

def decode_access_token(token: str) -> dict:
    return validate_jwt_token(token)
