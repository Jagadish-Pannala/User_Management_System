# jwt_validator/auth/jwt_validator.py

import jwt
from fastapi import HTTPException
from .....Business_Layer.utils.token_blacklist import is_token_blacklisted
from .oidc_config import get_oidc_validator

def validate_jwt_token(token: str):
    """
    Validates JWT using OIDC (public keys).
    Use this for Microsoft / OIDC tokens.
    """
    try:
        print("Starting JWT validation via OIDC...")
        validator = get_oidc_validator()
        print("OIDC Validator fetched successfully.")

        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if kid not in validator.jwks_dict:
            raise HTTPException(status_code=401, detail="Invalid key ID")

        key = validator.jwks_dict[kid]

        decoded = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=None,  # Set if needed
            issuer=validator.issuer
        )

        # Check if token is blacklisted
        jti = decoded.get("jti")
        if jti and is_token_blacklisted(jti):
            print(f"🚫 Token blacklisted (jti={jti})")
            raise HTTPException(status_code=401, detail="Token has been revoked")

        return decoded
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"JWT validation failed: {str(e)}")
