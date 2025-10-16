# jwt_validator/middleware/optimized_permission_middleware.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from .....Data_Access_Layer.dao.access_point_dao import AccessPointDAO
from .....Data_Access_Layer.utils.database import get_db_session
import logging
from typing import Dict, Set

logger = logging.getLogger(__name__)

class OptimizedPermissionMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, cache_size: int = 1000):
        super().__init__(app)    
    async def dispatch(self, request: Request, call_next):
        print("Entering Permission Middleware")
        
        # Skip permission check for public paths (FIXED - exact matches and specific patterns)

        public_paths = ["/docs", "/redoc", "/openapi.json", "/auth", "/.well-known"]

        if request.method == "OPTIONS" or any(request.url.path.startswith(path) for path in public_paths):
            return await call_next(request)

        

       
        # Skip if user is not authenticated (handled by JWTMiddleware)
        if not hasattr(request.state, 'user'):
            print("User not found ")
            return await call_next(request)
        print("3. Permission Middleware - ✅ USER FOUND!")
        user = request.state.user
        print(f"3. Permission Middleware - User: {user.get('name')}")
        
        try:
            # Get database session - try multiple ways
            db = None
            
            # Method 1: From request.state (set by DBSessionMiddleware)
            if hasattr(request.state, 'db'):
                db = request.state.db
                print(f"Got DB from request.state")
            
            # Method 2: From context (your existing method)
            if not db:
                try:
                    db = get_db_session()
                    print(f"Got DB from context")
                except Exception as e:
                    print(f"Could not get DB from context: {e}")
            
            if not db:
                print(f"ERROR: No database session available")
                return JSONResponse(
                    status_code=500, 
                    content={"detail": "Database session not available"}
                )
            
            access_point_dao = AccessPointDAO(db)
            
            # Get current endpoint and method
            endpoint_path = request.url.path
            method = request.method.upper()
            cache_key = f"{method}:{endpoint_path}"
            
            print(f"Checking access for: {cache_key}")
            
            
                
            #query database
            access_point = access_point_dao.get_access_point_by_path_and_method(
                endpoint_path=endpoint_path, 
                method=method
            )
            if not access_point:
                print(f"ACCESS DENIED: Access point not registered in DB")
                return JSONResponse(
                    status_code=403,
                    content={"detail": "ACESS DENIED : Access Point is not registered in the system db"}
                )



                
            # Get required permissions and cache them
            required_permissions = access_point_dao.get_permissions_for_access_point(
                access_point.access_id
            )
            print(f"Required permissions for this endpoint: {required_permissions}")
            if (required_permissions is None or required_permissions == []) and access_point.is_public is False and 'Super Admin' not in user.get('roles', []):
                print(f"ACCESS DENIED: No permissions mapped for this access point")
                return JSONResponse(
                    status_code=403,
                    content={"detail": "ACESS DENIED : No permissions is mapped for this access point"}
                )
            
            # Check if endpoint is public (from database)
            if access_point.is_public:
                print(f"ACCESS GRANTED: Endpoint is public")
                return await call_next(request)
            
            # Get user permissions from token
            user_permissions = set(user.get('permissions', []))
            user_roles = user.get('roles', [])
            print(user_roles)
            
            # Admin bypass
            if 'Super Admin' in user_roles:
                print(f"ACCESS GRANTED: User is Super Admin")
                return await call_next(request)
            
            # Check if user has required permissions
            required_permissions_set = set(required_permissions)
            
            if not required_permissions_set:
                print(f"WARNING: No specific permissions required for this endpoint")
                print(f"ACCESS GRANTED: No permissions configured")
                return await call_next(request)
            
            # Check for permission intersection
            matching_permissions = required_permissions_set.intersection(user_permissions)
            
            if not matching_permissions:
                print(f"ACCESS DENIED: User lacks required permissions")
                print(f"Required: {list(required_permissions_set)}")
                print(f"User has: {list(user_permissions)}")
                
                return JSONResponse(
                    status_code=403, 
                    content={
                        "detail": "You don't have permission to access this resource",
                        "required_permissions": list(required_permissions_set),
                        "user_permissions": list(user_permissions)
                    }
                )
            
            # Permission granted, proceed to endpoint
            print(f"ACCESS GRANTED: User has required permissions")
            print(f"Matching permissions: {list(matching_permissions)}")
            return await call_next(request)
            
        except Exception as e:
            print(f"ERROR in permission middleware: {str(e)}")
            logger.error(f"Permission middleware error: {str(e)}", exc_info=True)
            return JSONResponse(
                status_code=500, 
                content={"detail": f"Internal server error during permission check: {str(e)}"}
            )
    






