# jwt_validator/middleware/optimized_permission_middleware.py

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from .....Data_Access_Layer.dao.access_point_dao import AccessPointDAO
from .....Data_Access_Layer.utils.database import get_db_session
from .....Business_Layer.utils.redis_cache import (
    get_access_point_from_cache, set_access_point_cache
)
import logging

logger = logging.getLogger(__name__)

class OptimizedPermissionMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        print("Entering Permission Middleware")

        public_paths = ["/docs", "/redoc", "/openapi.json", "/auth", "/.well-known"]

        if request.method == "OPTIONS" or any(request.url.path.startswith(p) for p in public_paths):
            return await call_next(request)

        if not hasattr(request.state, "user"):
            return await call_next(request)

        user = request.state.user
        endpoint_path = request.url.path
        method = request.method.upper()
        cache_key = f"{method}:{endpoint_path}"
        print(f"Checking access for: {cache_key}")

        # Step 1: Try cache
        cached_data = await get_access_point_from_cache(method, endpoint_path)
        if cached_data:
            print(f"✅ Cache hit for {cache_key}")
            access_point_info = cached_data.get("access_point")
            required_permissions = cached_data.get("required_permissions", [])
        else:
            print(f"❌ Cache miss for {cache_key} → querying DB")
            db = getattr(request.state, "db", get_db_session())
            access_point_dao = AccessPointDAO(db)

            access_point = access_point_dao.get_access_point_by_path_and_method(
                endpoint_path=endpoint_path,
                method=method,
            )
            if not access_point:
                return JSONResponse(status_code=403, content={"detail": "Access point not found"})

            required_permissions = access_point_dao.get_permissions_for_access_point(access_point.access_id)

            # Normalize to dict before caching
            access_point_info = {
                "is_public": access_point.is_public,
                "access_id": access_point.access_id,
            }

            await set_access_point_cache(method, endpoint_path, {
                "access_point": access_point_info,
                "required_permissions": required_permissions,
            })

        # Step 2: Permission check logic
        if access_point_info["is_public"]:
            return await call_next(request)

        user_roles = user.get("roles", [])
        if "Super Admin" in user_roles:
            return await call_next(request)

        user_permissions = set(user.get("permissions", []))
        required_permissions_set = set(required_permissions or [])

        if not required_permissions_set or required_permissions_set.intersection(user_permissions):
            return await call_next(request)

        return JSONResponse(
            status_code=403,
            content={"detail": "You don't have permission to access this resource"},
        )
