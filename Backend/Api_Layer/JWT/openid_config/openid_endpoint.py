# Backend/Api_Layer/JWT/openid_config/openid_endpoint.py
from fastapi import APIRouter
from fastapi.responses import JSONResponse
import json
from pathlib import Path
from Backend.config.env_loader import get_env_var
from ..jwt_validator.middleware.permission_utils import check_permission
from fastapi import Request
from ..jwt_validator.auth.jwt_validator import validate_jwt_token
router = APIRouter()

# Static path to JWKS file
JWKS_PATH = Path(__file__).resolve().parent.parent / "token_creation" / "jwks.json"

# Replace with your actual domain name or environment variable
ISSUER = get_env_var("ISSUER")

@router.get("/.well-known/jwks.json")
def serve_jwks():
    with open(JWKS_PATH, "r") as f:
        jwks = json.load(f)
    return JSONResponse(content=jwks)

@router.get("/.well-known/openid-configuration")
def openid_config():
    config = {
        "issuer": ISSUER,
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "response_types_supported": ["token"],
        "subject_types_supported": ["public"]
    }
    return JSONResponse(content=config)
@router.get("/auth/check-permission")
async def check_permission_endpoint(request: Request):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"detail": "Missing or invalid token"})

        token = auth_header.split(" ")[1]
        try:

            decoded_token = validate_jwt_token(token)

            if not decoded_token:
                return JSONResponse(status_code=401, content={"detail": "Invalid token"})

            request.state.user = decoded_token
            print(f"JWT Middleware - User set: {decoded_token.get('name')}")
            path = request.url.path
            method = request.method
            user = request.state.user
            result = check_permission(path, method, user)
            if isinstance(result, JSONResponse):
                return result  # permission denied
            return JSONResponse(content={"detail": "Permission granted"})
        except Exception as e:
            return JSONResponse(status_code=401, content={"detail": str(e)}) 

