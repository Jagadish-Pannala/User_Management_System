# jwt_validator/middleware/jwt_middleware.py

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import JSONResponse
from ..auth.jwt_validator import validate_jwt_token

class JWTMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        public_paths = ["/", "/docs", "/redoc", "/openapi.json", "/auth"]

        if any(request.url.path.startswith(path) for path in public_paths):
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"detail": "Missing or invalid token"})

        token = auth_header.split(" ")[1]

        try:
            decoded_token = validate_jwt_token(token)
            request.state.user = decoded_token
            return await call_next(request)
        except Exception as e:
            return JSONResponse(status_code=401, content={"detail": str(e)})
