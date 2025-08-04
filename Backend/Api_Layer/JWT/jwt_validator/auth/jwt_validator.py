# jwt_validator/auth/jwt_validator.py

import jwt
from fastapi import HTTPException
from .oidc_config import get_oidc_validator

def validate_jwt_token(token: str):
    try:
        validator = get_oidc_validator()
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")

        if kid not in validator.jwks_dict:
            raise HTTPException(status_code=401, detail="Invalid key ID")

        key = validator.jwks_dict[kid]

        decoded = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=None,  # Or set if you need strict audience
            issuer=validator.issuer
        )
        return decoded
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"JWT validation failed: {str(e)}")
