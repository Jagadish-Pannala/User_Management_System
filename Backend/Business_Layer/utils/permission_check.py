from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
import jwt

from ...config.env_loader import get_env_var
from ...Data_Access_Layer.utils.dependency import get_db
from ...Data_Access_Layer.models.models import AccessPoint, AccessPointPermission

# Environment-based configuration
SECRET_KEY = get_env_var("SECRET_KEY")
ALGORITHM = get_env_var("ALGORITHM")

# HTTP Bearer for token extraction
security = HTTPBearer()

async def permission_required(
    request: Request,
    db: Session = Depends(get_db),
    token=Depends(security)
):
    path = str(request.url.path).rstrip("/") or "/"
    method = request.method.upper()

    # --- Step 1: Decode JWT ---
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        user_roles = [role.lower() for role in payload.get("roles", [])]
        user_permissions = set(payload.get("permissions", []))

        if not user_id:
            raise ValueError("Token missing user_id")

    except (jwt.InvalidTokenError, jwt.ExpiredSignatureError, ValueError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {str(e)}"
        )

    # --- Step 2: Lookup Access Point ---
    access_point = db.query(AccessPoint).filter_by(
        endpoint_path=path,
        method=method
    ).first()

    if not access_point:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Access point not registered: {path} [{method}]"
        )

    # --- Step 3: Allow if Public ---
    if access_point.is_public:
        return  # ✅ Public access granted

    # --- Step 4: Admin Bypass ---
    if "admin" in user_roles or "superadmin" in user_roles:
        return  # ✅ Admin role granted

    # --- Step 5: Fetch Required Permissions ---
    permission_entries = db.query(AccessPointPermission.permission_code).filter_by(
        access_id=access_point.access_id
    ).all()

    required_codes = {entry.permission_code for entry in permission_entries}

    if not required_codes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"No permissions mapped to endpoint {path} [{method}] (access_id={access_point.access_id})"
        )

    # --- Step 6: Check if User Has Required Permissions ---
    if not user_permissions.intersection(required_codes):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied for {path} [{method}] — requires one of: {required_codes}"
        )

    # ✅ Permission granted
    return
