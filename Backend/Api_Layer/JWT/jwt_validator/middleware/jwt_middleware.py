# jwt_validator/middleware/jwt_middleware.py

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import JSONResponse
from ..auth.jwt_validator import validate_jwt_token

class JWTMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        print("2. JWT Middleware - ENTERING")
        
        public_paths = ["/docs", "/redoc", "/openapi.json", "/auth", "/.well-known"]
        if request.method == "OPTIONS" or any(request.url.path.startswith(path) for path in public_paths):
            print("2. JWT Middleware - SKIPPING (public path)")
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            print("2. JWT Middleware - NO AUTH HEADER")
            return JSONResponse(status_code=401, content={"detail": "Missing or invalid token"})

        token = auth_header.split(" ")[1]
        print("2. JWT Middleware - Token received")

        try:
            decoded_token = validate_jwt_token(token)
            request.state.user = decoded_token
            print("2. JWT Middleware - User set in request.state")
            print(f"2. JWT Middleware - User: {decoded_token.get('name')}")
            
            response = await call_next(request)
            print("2. JWT Middleware - EXITING")
            return response
        except Exception as e:
            print(f"2. JWT Middleware - TOKEN VALIDATION FAILED: {e}")
            return JSONResponse(status_code=401, content={"detail": str(e)})

