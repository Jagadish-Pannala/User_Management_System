# jwt_validator/middleware/optimized_permission_middleware.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import JSONResponse
from .permission_utils import check_permission
import time

class OptimizedPermissionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        t_start = time.time()  # Start timing
        print("Permission Middleware - ENTERING")

        public_paths = ["/docs", "/redoc", "/openapi.json", "/auth", "/.well-known", "/middleware/check-permission"]
        if request.method == "OPTIONS" or any(request.url.path.startswith(p) for p in public_paths):
            response = await call_next(request)
        else:
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
                t_end = time.time()
                elapsed = (t_end - t_start) * 1000
                print(f"⏱ Permission Middleware: {elapsed:.2f}ms (permission denied)")
                return result  # permission denied

            # Continue request
            response = await call_next(request)

        t_end = time.time()
        elapsed = (t_end - t_start) * 1000
        print(f"⏱ Permission Middleware: {elapsed:.2f}ms")  # Log timing
        return response
