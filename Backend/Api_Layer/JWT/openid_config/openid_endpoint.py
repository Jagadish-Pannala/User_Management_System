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
    try:
        print(f"✅ POST ENDPOINT HIT!")
        print(f"📍 Method: {request.method}")
        print(f"📍 Path: {request.url.path}")
        print(f"📍 Client IP: {request.client.host if request.client else 'Unknown'}")
        print(f"📥 Data: path={data.path}, method={data.method}")
        
        # Check if user data exists
        if not hasattr(request.state, "user") or request.state.user is None:
            print("❌ No user data in request.state")
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized - no user data"}
            )
        
        token_data = request.state.user
        print(f"👤 User data: {token_data}")
        
        # Get DB session if available
        db = getattr(request.state, "db", None)
        print(f"💾 DB session: {'Available' if db else 'Not available'}")
        
        response = check_permission(data.path, data.method, token_data, db_session=db)
        
        if isinstance(response, JSONResponse):
            print(f"❌ Permission denied")
            return response
        
        print(f"✅ Permission granted")
        return {"allowed": True}
        
    except Exception as e:
        print(f"💥 ERROR in permission_check_endpoint: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"detail": f"Internal error: {str(e)}"}
        )

@router.get("/middleware/check-permission")
async def permission_check_get_handler(request: Request):
    print(f"❌ GET REQUEST RECEIVED - This endpoint only accepts POST")
    print(f"📍 Client: {request.client}")
    print(f"📍 Headers: {dict(request.headers)}")
    return JSONResponse(
        status_code=405,
        content={"error": "Method Not Allowed. Use POST instead of GET"}
    )
