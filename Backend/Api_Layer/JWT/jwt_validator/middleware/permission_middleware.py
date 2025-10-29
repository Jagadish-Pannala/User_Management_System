# jwt_validator/middleware/optimized_permission_middleware.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import JSONResponse
from .permission_utils import check_permission

class OptimizedPermissionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        print("Permission Middleware - ENTERING")

        public_paths = ["/docs", "/redoc", "/openapi.json", "/auth", "/.well-known"]
        if request.method == "OPTIONS" or any(request.url.path.startswith(p) for p in public_paths):
            return await call_next(request)

        # JWT middleware must set request.state.user
        if not hasattr(request.state, "user") or request.state.user is None:
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

        user = request.state.user
        path = request.url.path
        method = request.method
        db = getattr(request.state, "db", None)

        # Use the shared check_permission() logic
        result = check_permission(path, method, user, db_session=db)
        if isinstance(result, JSONResponse):
            return result  # permission denied

        # Continue request
        return await call_next(request)
