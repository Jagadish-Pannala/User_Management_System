# auth/jwt_utils.py

def decode_access_token(token: str) -> dict:
    from .jwt_validator import validate_jwt_token
    return validate_jwt_token(token)
