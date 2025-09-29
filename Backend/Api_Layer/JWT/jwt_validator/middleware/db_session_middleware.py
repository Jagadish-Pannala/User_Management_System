from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from fastapi.responses import JSONResponse

from .....Data_Access_Layer.utils.database import set_db_session, remove_db_session


class DBSessionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        print("🔵 1. DB Middleware - ENTERING")
        try:
            db = set_db_session()
            request.state.db = db
            print("🔵 1. DB Middleware - DB session set")
            response = await call_next(request)
            print("🔵 1. DB Middleware - EXITING")
            return response
        finally:
            remove_db_session()