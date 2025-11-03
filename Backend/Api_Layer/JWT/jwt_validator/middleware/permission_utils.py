# jwt_validator/middleware/permission_utils.py
from .....Data_Access_Layer.dao.access_point_dao import AccessPointDAO
from .....Data_Access_Layer.dao.group_dao import PermissionGroupDAO
from .....Data_Access_Layer.utils.database import get_db_session
from .....Business_Layer.utils.redis_cache import get_access_point_from_cache, set_access_point_cache

from fastapi.responses import JSONResponse


def check_permission(path: str, method: str, user: dict, db_session=None):
    """
    Core permission logic extracted from middleware.
    Returns JSONResponse (403/401) if unauthorized, else None.
    """
    if not method:
        return JSONResponse(status_code=400, content={"detail": "HTTP method is required"})
    method = method.upper()
    cache_key = f"{method}:{path}"
    print(f"🔍 Checking permission for {cache_key}")

    # 1️⃣ Try cache first
    cached_data = get_access_point_from_cache(method, path)
    if cached_data:
        print(f"✅ Cache hit for {cache_key}")
        access_point_info = cached_data.get("access_point")
        required_permissions = cached_data.get("required_permissions", [])
    else:
        print(f"❌ Cache miss for {cache_key} → querying DB")
        db = db_session or get_db_session()
        access_point_dao = AccessPointDAO(db)
        group_dao = PermissionGroupDAO(db)

        access_point = access_point_dao.get_access_point_by_path_and_method(path, method)
        if not access_point:
            return JSONResponse(status_code=403, content={"detail": "Access point not found"})

        required_permissions = access_point_dao.get_permissions_for_access_point(access_point.access_id)
        if (not required_permissions) and not access_point.is_public and 'Super Admin' not in user.get('roles', []):
            return JSONResponse(
                status_code=403,
                content={"detail": "ACCESS DENIED: No permissions mapped for this access point"}
            )

        access_point_info = {"is_public": access_point.is_public, "access_id": access_point.access_id}
        set_access_point_cache(method, path, {
            "access_point": access_point_info,
            "required_permissions": required_permissions
        })

    # 2️⃣ Public or Super Admin bypass
    if access_point_info.get("is_public"):
        print(f"🔓 Access point is public so skipping permission check")
        return None  # allowed

    # 3️⃣ Actual permission check
    user_permissions = set(user.get("permissions", []))
    user_groups = set(user.get("groups", []))
    required_group = group_dao.get_group_by_permission_code(required_permissions[0]) if required_permissions else None
    print(f"Required permissions for access: {required_permissions}")
    print(f"Groups required for permission: {required_group}")
    print(f"User's groups: {user_groups}")
    required_permissions_set = set(required_permissions or [])
    required_groups_set = set(required_group or [])

    if required_groups_set and not required_groups_set.intersection(user_groups):
        return JSONResponse(status_code=403, content={"detail": "You don't have permission to access this resource"})
    
    print(f"Allowed: User groups match required groups, {required_groups_set.intersection(user_groups)}")

    # if required_permissions_set and not required_permissions_set.intersection(user_permissions):
    #     return JSONResponse(status_code=403, content={"detail": "You don't have permission to access this resource"})

    return None  # allowed
