# jwt_validator/auth/jwt_validator.py

import jwt
from fastapi import HTTPException
from .....Business_Layer.utils.token_blacklist import is_token_blacklisted
from .oidc_config import get_oidc_validator


def validate_jwt_token(token: str):
    """
    Validates JWT using OIDC (public keys).
    Use this for Microsoft / OIDC tokens.
    Auto-reloads JWKS if key rotation detected.
    """
    try:
        print("Starting JWT validation via OIDC...")
        validator = get_oidc_validator()
        print("OIDC Validator fetched successfully.")

        # Get KID from token header
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        print(f"Token header 'kid': {kid}")
        print(
            "Issuer form OIDC",
            validator.issuer,
            "Issuer from token",
            jwt.decode(token, options={"verify_signature": False}).get("iss"),
        )

        # ✅ FIXED: Use get_signing_key() instead of direct cache access
        # This method automatically reloads JWKS if KID not found
        try:
            key = validator.get_signing_key(kid)
        except ValueError as e:
            # Only raised if key truly doesn't exist after reload attempt
            raise HTTPException(status_code=401, detail=str(e))
        except RuntimeError as e:
            # Configuration not loaded
            raise HTTPException(status_code=500, detail=str(e))

        # Decode and validate the token
        decoded = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=None,  # Set if needed
            issuer=validator.issuer,
        )

        # Check if token is blacklisted
        jti = decoded.get("jti")
        try:
            if jti and is_token_blacklisted(jti):
                print(f"🚫 Token blacklisted (jti={jti})")
                raise HTTPException(status_code=401, detail="Token has been revoked")
        except HTTPException:
            raise  # re-raise the revoked token exception
        except Exception as e:
            print(
                f"⚠️ Blacklist check error (ignored): {e}"
            )  # Redis down, allow request
        return decoded

    except jwt.ExpiredSignatureError:
        print("⏰ Token expired")
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        print(f"❌ Invalid token: {e}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        print(f"💥 Unexpected validation error: {e}")
        raise HTTPException(status_code=401, detail=f"JWT validation failed: {str(e)}")
