# jwt_validator/middleware/optimized_permission_middleware.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import JSONResponse
from .....Data_Access_Layer.dao.access_point_dao import AccessPointDAO
from .....Data_Access_Layer.utils.database import get_db_session
from .....Business_Layer.utils.redis_cache import get_access_point_from_cache, set_access_point_cache

class OptimizedPermissionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        print("Permission Middleware - ENTERING")

        public_paths = ["/docs", "/redoc", "/openapi.json", "/auth", "/.well-known"]
        if request.method == "OPTIONS" or any(request.url.path.startswith(p) for p in public_paths):
            return await call_next(request)

        # Reject if user not set by JWT middleware
        if not hasattr(request.state, "user") or request.state.user is None:
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

        user = request.state.user
        method = request.method.upper()
        path = request.url.path
        cache_key = f"{method}:{path}"
        print(f"Permission Middleware - Checking access for {cache_key}")

        # Step 1: Try cache
        try:
            cached_data = await get_access_point_from_cache(method, path)
        except Exception as e:
            print(f"Permission Middleware - Redis fetch failed: {e}")
            cached_data = None

        if cached_data:
            print(f"✅ Cache hit for {cache_key}")
            access_point_info = cached_data.get("access_point")
            required_permissions = cached_data.get("required_permissions", [])
        else:
            print(f"❌ Cache miss for {cache_key} → querying DB")
            db = getattr(request.state, "db", get_db_session())
            access_point_dao = AccessPointDAO(db)

            access_point = access_point_dao.get_access_point_by_path_and_method(path, method)
            if not access_point:
                return JSONResponse(status_code=403, content={"detail": "Access point not found"})

            required_permissions = access_point_dao.get_permissions_for_access_point(access_point.access_id)
            if (required_permissions is None or required_permissions == []) and access_point.is_public is False and 'Super Admin' not in user.get('roles', []):
                print(f"ACCESS DENIED: No permissions mapped for this access point")
                return JSONResponse(
                    status_code=403,
                    content={"detail": "ACESS DENIED : No permissions is mapped for this access point"}
                )
            access_point_info = {"is_public": access_point.is_public, "access_id": access_point.access_id}

            try:
                await set_access_point_cache(method, path, {
                    "access_point": access_point_info,
                    "required_permissions": required_permissions
                })
            except Exception as e:
                print(f"Permission Middleware - Redis cache set failed: {e}")

        # Step 2: Permission check
        if access_point_info.get("is_public"):
            return await call_next(request)

        if "Super Admin" in user.get("roles", []):
            return await call_next(request)

        user_permissions = set(user.get("permissions", []))
        required_permissions_set = set(required_permissions or [])

        if required_permissions_set and not required_permissions_set.intersection(user_permissions):
            return JSONResponse(status_code=403, content={"detail": "You don't have permission to access this resource"})

        return await call_next(request)
