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
        # Only handle HTTP requests
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
 
        path = scope.get("path", "")
        method = scope.get("method", "GET").upper()
        print(f"\n🚀 JWT Middleware ENTERING → {method} {path}")
 
        # ✅ Public paths (no token/permission check)
        public_paths = ["/docs", "/redoc", "/openapi.json", "/auth", "/.well-known"]
        if method == "OPTIONS" or any(path.startswith(p) for p in public_paths):
            print(f"🟢 Public path detected → Skipping JWT: {path}")
            await self.app(scope, receive, send)
            return
 
        # ✅ Extract Authorization header
        headers = dict(scope.get("headers") or [])
        auth_header = headers.get(b"authorization")
        if not auth_header:
            print("❌ Missing Authorization header")
            res = JSONResponse({"detail": "Missing or invalid token"}, status_code=401)
            await res(scope, receive, send)
            return
 
        try:
            auth_header_decoded = auth_header.decode()
            if not auth_header_decoded.startswith("Bearer "):
                print("❌ Invalid Authorization header format")
                res = JSONResponse({"detail": "Invalid token format"}, status_code=401)
                await res(scope, receive, send)
                return
 
            token = auth_header_decoded.split(" ")[1]
            print(f"🎫 Token extracted: {token[:20]}...")
 
            # ✅ Validate token (sync or async)
            decoded_token = (
                await validate_jwt_token(token)
                if inspect.iscoroutinefunction(validate_jwt_token)
                else validate_jwt_token(token)
            )
 
            if not decoded_token:
                print("❌ Token validation failed")
                res = JSONResponse({"detail": "Invalid token"}, status_code=401)
                await res(scope, receive, send)
                return
 
            print(f"✅ Token validated for user: {decoded_token.get('email', decoded_token.get('sub', 'unknown'))}")
 
            # ✅ Create request object for DB access
            request = Request(scope, receive=receive)
            db = getattr(request.state, "db", None)
 
            # ✅ Permission check from DB
            print(f"🔍 Checking permission for {method}:{path}")
            permission_result = check_permission(path, method, decoded_token, db_session=db)
 
            if isinstance(permission_result, JSONResponse):
                print("🚫 Permission denied")
                await permission_result(scope, receive, send)
                return
 
            # ✅ Optional: Cache lookup for access point (if exists)
            access_point_cache = get_access_point_from_cache(method, path)
            if access_point_cache:
                request.state.access_point_cache = access_point_cache
                print("⚡ Access point cache hit")
 
            # ✅ Continue to actual endpoint
            await self.app(scope, receive, send)
            print(f"🏁 JWT Middleware EXITING → {method} {path}")
 
        except Exception as e:
            print(f"💥 JWT Middleware Error: {e}")
            traceback.print_exc()
            res = JSONResponse({"detail": str(e)}, status_code=401)
            await res(scope, receive, send)