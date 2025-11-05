from fastapi.responses import JSONResponse
from starlette.requests import Request
from ..auth.jwt_validator import validate_jwt_token
from Backend.Business_Layer.utils.redis_cache import get_access_point_from_cache
from .permission_utils import check_permission
import inspect
import traceback
 
class JWTMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET").upper()
        print(f"\n🚀 JWT Middleware ENTERING → {method} {path}")

        public_paths = ["/docs", "/redoc", "/openapi.json", "/auth", "/.well-known"]
        if method == "OPTIONS" or any(path.startswith(p) for p in public_paths):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        auth_header = headers.get(b"authorization")
        if not auth_header:
            res = JSONResponse({"detail": "Missing or invalid token"}, status_code=401)
            await res(scope, receive, send)
            return

        try:
            auth_header_decoded = auth_header.decode()
            if not auth_header_decoded.startswith("Bearer "):
                res = JSONResponse({"detail": "Invalid token format"}, status_code=401)
                await res(scope, receive, send)
                return

            token = auth_header_decoded.split(" ")[1]
            decoded_token = (
                await validate_jwt_token(token)
                if inspect.iscoroutinefunction(validate_jwt_token)
                else validate_jwt_token(token)
            )

            if not decoded_token:
                res = JSONResponse({"detail": "Invalid token"}, status_code=401)
                await res(scope, receive, send)
                return

            # ⭐ Create request object so request.state is available
            request = Request(scope, receive=receive)

            # ⭐ STORE user data for permission check endpoint
            request.state.user = decoded_token

            db = getattr(request.state, "db", None)

            permission_result = check_permission(path, method, decoded_token, db_session=db)
            if isinstance(permission_result, JSONResponse):
                await permission_result(scope, receive, send)
                return

            access_point_cache = get_access_point_from_cache(method, path)
            if access_point_cache:
                request.state.access_point_cache = access_point_cache

            await self.app(scope, receive, send)

        except Exception as e:
            print(f"💥 JWT Middleware Error: {e}")
            traceback.print_exc()
            res = JSONResponse({"detail": str(e)}, status_code=401)
            await res(scope, receive, send)