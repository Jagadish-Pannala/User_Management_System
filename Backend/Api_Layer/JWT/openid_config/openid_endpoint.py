from fastapi import APIRouter
from fastapi.responses import JSONResponse
import json
from pathlib import Path

router = APIRouter()

# Static path to JWKS file
JWKS_PATH = Path(__file__).resolve().parent.parent / "token_creation" / "jwks.json"

# Replace with your actual domain name or environment variable
ISSUER = "http://localhost:8000"

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