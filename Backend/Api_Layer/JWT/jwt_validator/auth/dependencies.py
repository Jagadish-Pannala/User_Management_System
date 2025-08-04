# auth/dependencies.py
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from .jwt_utils import decode_access_token

bearer_scheme = HTTPBearer()

def get_current_user(token: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    try:
        payload = decode_access_token(token.credentials)
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def admin_required(current_user: dict = Depends(get_current_user)):
    roles = current_user.get("roles", [])
    if "Admin" not in roles and "Super Admin" not in roles:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user
