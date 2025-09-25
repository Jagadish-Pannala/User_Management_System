import jwt
from jwt import PyJWKClient
from fastapi import HTTPException
from .oidc_config import get_oidc_validator

def validate_jwt_token(token: str):
    print("[validate_jwt_token] Validating token:", token)
    try:
        print("Starting JWT validation...")
        validator = get_oidc_validator()
        print("OIDC Validator fetched successfully.")
        header = jwt.get_unverified_header(token)
        print("[validate_jwt_token] JWT header:", header)

        kid = header.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="JWT header missing 'kid'")
        print("[validate_jwt_token] kid:", kid)

        # Use PyJWKClient to fetch key (handles PEM formatting)
        jwks_client = PyJWKClient(validator.jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(token).key
        print("[validate_jwt_token] Obtained signing key via PyJWKClient")

        # Decode JWT
        decoded = jwt.decode(
            token,
            key=signing_key,
            algorithms=["RS256"],
            audience=None,  # set if needed
            issuer=validator.issuer
        )

        print("[validate_jwt_token] JWT successfully decoded")
        return decoded

    except jwt.PyJWKClientError as e:
        raise HTTPException(status_code=401, detail=f"Failed to fetch JWKS key: {e}")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="JWT has expired")
    except jwt.InvalidIssuerError:
        raise HTTPException(status_code=401, detail="Invalid issuer")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"JWT validation failed: {str(e)}")
