from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from .....Data_Access_Layer.utils.database import set_db_session, remove_db_session


class DBSessionMiddleware(BaseHTTPMiddleware):
    """
    Middleware to manage database session lifecycle per request.
    Ensures session creation before processing and cleanup after.
    """

    async def dispatch(self, request: Request, call_next):
        print("🟢 DB Middleware - ENTERING")

        db = None
        try:
            # Create and attach DB session to request state
            db = set_db_session()
            request.state.db = db
            print("🟢 DB Middleware - DB session initialized")

            # Proceed to next middleware/endpoint
            response = await call_next(request)
            return response

        except SQLAlchemyError as e:
            # Handle DB-specific errors gracefully
            print(f"🔴 DB Middleware - SQLAlchemyError: {e}")
            if db:
                db.rollback()
            return JSONResponse(
                {"detail": "A database error occurred."}, status_code=500
            )

        except Exception as e:
            # Catch unexpected errors to avoid crashing the app
            print(f"🔴 DB Middleware - Unexpected Error: {e}")
            return JSONResponse(
                {"detail": "Internal server error."}, status_code=500
            )

        finally:
            # Always remove DB session after request completes
            remove_db_session()
            print("🟢 DB Middleware - Session removed and EXITING")
