from fastapi.responses import JSONResponse
from starlette.requests import Request
import inspect
import traceback

from ..auth.jwt_validator import validate_jwt_token
from Backend.Business_Layer.utils.redis_cache import get_access_point_from_cache
from .permission_utils import check_permission


class JWTMiddleware:
    def __init__(self, app):
        self.app = app
        self.public_paths = [
            "/docs", "/redoc", "/openapi.json", "/auth", "/.well-known"
        ]

    async def __call__(self, scope, receive, send):
        # ✅ Create Request object (so we can use request.method, headers, state)
        request = Request(scope, receive=receive)

        method = request.method
        path = request.url.path
        print(f"\n🚀 [JWT Middleware] ENTER → {method} {path}")

        # ✅ Skip for public paths / OPTIONS
        if self._is_public_path(request):
            print(f"🟢 Public path → Skipping JWT/Permission: {path}")
            await self.app(scope, receive, send)
            return

        # ✅ STEP 1: AUTHENTICATE USER (Decode JWT)
        token_data = await self._validate_token(request)
        if isinstance(token_data, JSONResponse):
            await token_data(scope, receive, send)
            return

        # Store authenticated user in request.state
        request.state.user = token_data
        print(f"👤 Authenticated User: {token_data.get('email') or token_data.get('sub')}")

        # ✅ STEP 2: PERMISSION CHECK
        permission_result = self._check_permission(request, token_data)
        if isinstance(permission_result, JSONResponse):
            print(f"🚫 Permission Denied → {method}:{path}")
            await permission_result(scope, receive, send)
            return

        print(f"✅ Permission Granted → {method}:{path}")

        # ✅ STEP 3: Optional Cache Lookup for Access Point
        access_point_cache = get_access_point_from_cache(method, path)
        if access_point_cache:
            request.state.access_point_cache = access_point_cache
            print(f"⚡ Cache HIT → Access Point Data Loaded")

        # ✅ Continue to endpoint
        await self.app(scope, receive, send)
        print(f"🏁 [JWT Middleware] EXIT → {method} {path}")

    # --------------------------------------------------------------------
    # 🔹 Helper: Public Path Check
    def _is_public_path(self, request: Request):
        if request.method == "OPTIONS":
            return True
        return any(request.url.path.startswith(p) for p in self.public_paths)

    # --------------------------------------------------------------------
    # 🔹 Helper: JWT Validation
    async def _validate_token(self, request: Request):
        auth_header = request.headers.get("authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            print("❌ Missing or Invalid Authorization Header")
            return JSONResponse({"detail": "Missing or invalid token"}, status_code=401)

        token = auth_header.split(" ")[1]
        print(f"🎫 Received Token: {token[:15]}...")

        try:
            decoded = (
                await validate_jwt_token(token)
                if inspect.iscoroutinefunction(validate_jwt_token)
                else validate_jwt_token(token)
            )
            if not decoded:
                print("❌ Token validation failed")
                return JSONResponse({"detail": "Invalid token"}, status_code=401)

            print("✅ Token Validated Successfully")
            return decoded

        except Exception as e:
            print(f"💥 JWT Validation Error: {e}")
            traceback.print_exc()
            return JSONResponse({"detail": str(e)}, status_code=401)

    # --------------------------------------------------------------------
    # 🔹 Helper: Permission Check
    def _check_permission(self, request: Request, token_data):
        db = getattr(request.state, "db", None)
        print(f"🔍 Checking Permission → {request.method}:{request.url.path}")
        print(f"💾 DB Session: {'Available' if db else 'Not Available'}")

        return check_permission(request.url.path, request.method, token_data, db_session=db)
