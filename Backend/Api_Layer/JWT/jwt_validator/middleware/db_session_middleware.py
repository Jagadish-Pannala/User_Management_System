from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from fastapi.responses import JSONResponse

from .....Data_Access_Layer.utils.database import set_db_session, remove_db_session


class DBSessionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            set_db_session()
            response = await call_next(request)
            return response
        finally:
            remove_db_session()
