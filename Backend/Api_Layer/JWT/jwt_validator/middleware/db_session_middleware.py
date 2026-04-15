from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from .....Data_Access_Layer.utils.database import set_db_session, remove_db_session
import time


class DBSessionMiddleware(BaseHTTPMiddleware):
    # Routes that don't need a DB session
    SKIP_PATHS = [
        "/.well-known/jwks.json",
        "/.well-known/openid-configuration",
    ]

    async def dispatch(self, request: Request, call_next):

        # ✅ Skip DB session for routes that don't need it
        if any(request.url.path.startswith(p) for p in self.SKIP_PATHS):
            return await call_next(request)

        t_start = time.time()  # Start timing
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
            return JSONResponse({"detail": "Internal server error."}, status_code=500)

        finally:
            # Always remove DB session after request completes
            remove_db_session()
            t_end = time.time()  # End timing
            elapsed = (t_end - t_start) * 1000
            print(f"⏱ DB Middleware: {elapsed:.2f}ms")
            print("🟢 DB Middleware - Session removed and EXITING")
