# Backend/Api_Layer/JWT/openid_config/openid_endpoint.py
from fastapi import APIRouter
from fastapi.responses import JSONResponse
import json
from pathlib import Path
from Backend.config.env_loader import get_env_var
from ..jwt_validator.middleware.permission_utils import check_permission
from Backend.Api_Layer.interfaces.auth import PermissionCheck
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
@router.post("/middleware/check-permission")
async def permission_check_endpoint(request: Request, data: PermissionCheck):
    print(f"📥 Permission check request: path={data.path}, method={data.method}")
    
    token_data = request.state.user
    print(f"👤 User data: {token_data}")
    
    response = check_permission(data.path, data.method, token_data)
    if isinstance(response, JSONResponse):
        print(f"❌ Permission denied")
        return response
    
    print(f"✅ Permission granted")
    return {"allowed": True}


