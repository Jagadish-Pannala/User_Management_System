# jwt_validator/middleware/jwt_middleware.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import JSONResponse
from ..auth.jwt_validator import validate_jwt_token
from Backend.Business_Layer.utils.redis_cache import get_access_point_from_cache
import inspect
import traceback

class JWTMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        print("JWT Middleware - ENTERING")

        public_paths = ["/docs", "/redoc", "/openapi.json", "/auth", "/.well-known"]
        if request.method == "OPTIONS" or any(request.url.path.startswith(p) for p in public_paths):
            print(f"JWT Middleware - Skipping: {request.url.path}")
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        print(f"🔑 Authorization header: {auth_header[:50] if auth_header else 'None'}...")
        
        if not auth_header or not auth_header.startswith("Bearer "):
            print("❌ JWT Middleware - Missing or invalid Authorization header")
            return JSONResponse(status_code=401, content={"detail": "Missing or invalid token"})

        token = auth_header.split(" ")[1]
        print(f"🎫 Token extracted: {token[:20]}...")
        
        try:
            # Support async or sync JWT validator
            if inspect.iscoroutinefunction(validate_jwt_token):
                decoded_token = await validate_jwt_token(token)
            else:
                decoded_token = validate_jwt_token(token)

            print(f"🔓 Decoded token: {decoded_token}")
            
            if not decoded_token:
                print("❌ JWT Middleware - validate_jwt_token returned None/False")
                return JSONResponse(status_code=401, content={"detail": "Invalid token"})

            request.state.user = decoded_token
            print(f"✅ JWT Middleware - User set: {decoded_token.get('name', decoded_token.get('email', 'Unknown'))}")
            print(f"✅ request.state.user = {request.state.user}")

            # Optional: fetch access point cache (SYNCHRONOUS - no await!)
            access_point_cache = get_access_point_from_cache(request.method, request.url.path)
            if access_point_cache:
                request.state.access_point_cache = access_point_cache
                print("JWT Middleware - Access point cache found")

            response = await call_next(request)
            print("JWT Middleware - EXITING")
            return response

        except Exception as e:
            print(f"💥 JWT Middleware Error: {e}")
            import traceback
            traceback.print_exc()
            return JSONResponse(status_code=401, content={"detail": str(e)})