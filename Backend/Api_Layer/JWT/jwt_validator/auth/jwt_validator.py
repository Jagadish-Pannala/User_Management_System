# jwt_validator/auth/jwt_validator.py

import jwt
from fastapi import HTTPException, status
from .....Business_Layer.utils.token_blacklist import is_token_blacklisted
from .oidc_config import get_oidc_validator

_oidc_validator = None

def get_cached_oidc_validator():
    """
    Returns a cached OIDC validator instance to prevent redundant network fetches.
    """
    global _oidc_validator
    if _oidc_validator is None:
        _oidc_validator = get_oidc_validator()
    return _oidc_validator

def validate_jwt_token(token: str):
    """
    Validate a JWT token using OIDC public keys.
    - Caches OIDC keys for performance.
    - Checks blacklist to revoke tokens.
    - Raises clear HTTP errors for frontend.
    """
    try:

        validator = get_cached_oidc_validator()

        # Extract header safely (without verifying)
        try:
            header = jwt.get_unverified_header(token)
        except jwt.DecodeError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token header")

        kid = header.get("kid")
        if not kid:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing key ID in token header")

        key = validator.jwks_dict.get(kid)
        if not key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid key ID")

        # Decode the JWT using the correct key
        decoded = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=None,  # Set if required by your OIDC provider
            issuer=validator.issuer,
        )

        # Blacklist check
        jti = decoded.get("jti")
        if jti and is_token_blacklisted(jti):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")

        return decoded

    except HTTPException:
        # Already formatted, just bubble up
        raise

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")

    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {str(e)}")

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="JWT validation failed")