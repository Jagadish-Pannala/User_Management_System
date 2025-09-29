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
        self._permission_cache: Dict[str, Set[str]] = {}
        self.cache_size = cache_size
    
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
        print("🔴 3. Permission Middleware - ✅ USER FOUND!")
        user = request.state.user
        print(f"🔴 3. Permission Middleware - User: {user.get('name')}")
        
        try:
            # Get database session - try multiple ways
            db = None
            
            # Method 1: From request.state (set by DBSessionMiddleware)
            if hasattr(request.state, 'db'):
                db = request.state.db
                print(f"   ✅ Got DB from request.state")
            
            # Method 2: From context (your existing method)
            if not db:
                try:
                    db = get_db_session()
                    print(f"   ✅ Got DB from context")
                except Exception as e:
                    print(f"   ❌ Could not get DB from context: {e}")
            
            if not db:
                print(f"   ❌ ERROR: No database session available")
                return JSONResponse(
                    status_code=500, 
                    content={"detail": "Database session not available"}
                )
            
            access_point_dao = AccessPointDAO(db)
            
            # Get current endpoint and method
            endpoint_path = request.url.path
            method = request.method.upper()
            cache_key = f"{method}:{endpoint_path}"
            
            print(f"   🎯 Checking access for: {cache_key}")
            
            # Check cache first
            required_permissions = self._get_cached_permissions(cache_key)
            access_point = None
            
            if required_permissions is None:
                print(f"   📊 Cache miss - querying database")
                
                # Not in cache, query database
                access_point = access_point_dao.get_access_point_by_path_and_method(
                    endpoint_path=endpoint_path, 
                    method=method
                )
                
                if not access_point:
                    print(f"   ❌ ACCESS DENIED: Access point not registered in database")
                    return JSONResponse(
                        status_code=403, 
                        content={"detail": "Access point not registered"}
                    )
                
                print(f"   ✅ Access point found: ID={access_point.access_id}, Public={access_point.is_public}")
                
                # Get required permissions and cache them
                required_permissions = access_point_dao.get_permissions_for_access_point(
                    access_point.access_id
                )
                
                print(f"   🔒 Required permissions from DB: {required_permissions}")
                self._cache_permissions(cache_key, required_permissions, access_point.is_public)
            else:
                print(f"   📊 Cache hit - using cached permissions: {required_permissions}")
            
            # Check if endpoint is public (from cache or database)
            if self._is_endpoint_public(cache_key, access_point):
                print(f"   🟢 ACCESS GRANTED: Endpoint is public")
                return await call_next(request)
            
            # Get user permissions from token
            user_permissions = set(user.get('permissions', []))
            user_roles = user.get('roles', [])
            print(user_roles)
            
            # Admin bypass
            if 'Super Admin' in user_roles:
                print(f"   🟢 ACCESS GRANTED: User is Super Admin")
                return await call_next(request)
            
            # Check if user has required permissions
            required_permissions_set = set(required_permissions)
            
            if not required_permissions_set:
                print(f"   ⚠️  WARNING: No specific permissions required for this endpoint")
                print(f"   🟢 ACCESS GRANTED: No permissions configured")
                return await call_next(request)
            
            # Check for permission intersection
            matching_permissions = required_permissions_set.intersection(user_permissions)
            
            if not matching_permissions:
                print(f"   ❌ ACCESS DENIED: User lacks required permissions")
                print(f"       Required: {list(required_permissions_set)}")
                print(f"       User has: {list(user_permissions)}")
                
                return JSONResponse(
                    status_code=403, 
                    content={
                        "detail": "You don't have permission to access this resource",
                        "required_permissions": list(required_permissions_set),
                        "user_permissions": list(user_permissions)
                    }
                )
            
            # Permission granted, proceed to endpoint
            print(f"   🟢 ACCESS GRANTED: User has required permissions")
            print(f"       Matching permissions: {list(matching_permissions)}")
            return await call_next(request)
            
        except Exception as e:
            print(f"   ❌ ERROR in permission middleware: {str(e)}")
            logger.error(f"Permission middleware error: {str(e)}", exc_info=True)
            return JSONResponse(
                status_code=500, 
                content={"detail": f"Internal server error during permission check: {str(e)}"}
            )
    
    def _get_cached_permissions(self, cache_key: str):
        """Get permissions from cache."""
        cache_entry = self._permission_cache.get(cache_key)
        if cache_entry:
            return cache_entry.get('permissions')
        return None
    
    def _cache_permissions(self, cache_key: str, permissions: list, is_public: bool):
        """Cache permissions for an endpoint."""
        # Simple cache size management
        if len(self._permission_cache) >= self.cache_size:
            # Remove oldest entry (simple FIFO)
            oldest_key = next(iter(self._permission_cache))
            del self._permission_cache[oldest_key]
        
        self._permission_cache[cache_key] = {
            'permissions': permissions,
            'is_public': is_public
        }
    
    def _is_endpoint_public(self, cache_key: str, access_point=None):
        """Check if endpoint is public from cache or access_point object."""
        cache_entry = self._permission_cache.get(cache_key)
        if cache_entry:
            is_public = cache_entry.get('is_public', False)
            return is_public in (True, 1)
        
        if access_point:
            return access_point.is_public in (True, 1)
        
        return False
    
    def clear_cache(self):
        """Clear the permission cache. Useful for testing or when permissions change."""
        self._permission_cache.clear()
        logger.info("Permission cache cleared")


# Simple version without caching for easier debugging
class SimplePermissionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        print(f"\n🔐 SIMPLE PERMISSION CHECK - Processing: {request.method} {request.url.path}")
        
        # Skip permission check for public paths
        public_paths = ["/", "/docs", "/redoc", "/openapi.json", "/auth"]
        
        if any(request.url.path.startswith(path) for path in public_paths):
            print(f"   🟢 SKIPPING: Public path")
            return await call_next(request)
        
        # Skip if user is not authenticated
        if not hasattr(request.state, 'user'):
            print(f"   ⚠️  No user in request.state")
            return await call_next(request)
        
        user = request.state.user
        print(f"   👤 User: {user.get('name')} (Roles: {user.get('roles', [])})")
        
        try:
            # Get database session
            db = None
            if hasattr(request.state, 'db'):
                db = request.state.db
            else:
                db = get_db_session()
            
            access_point_dao = AccessPointDAO(db)
            
            endpoint_path = request.url.path
            method = request.method.upper()
            
            # Get access point
            access_point = access_point_dao.get_access_point_by_path_and_method(
                endpoint_path=endpoint_path, 
                method=method
            )
            
            if not access_point:
                print(f"   ❌ ACCESS DENIED: Access point not registered")
                return JSONResponse(
                    status_code=403, 
                    content={"detail": "Access point not registered"}
                )
            
            print(f"   ✅ Access point found: ID={access_point.access_id}")
            
            # If endpoint is public, allow access (handle 1/0 and True/False)
            is_public = access_point.is_public in (True, 1)
            if is_public:
                print(f"   🟢 ACCESS GRANTED: Public endpoint (is_public={access_point.is_public})")
                return await call_next(request)
            
            # Get user data
            user_permissions = set(user.get('permissions', []))
            user_roles = user.get('roles', [])
            
            # Admin bypass
            if 'Admin' in user_roles:
                print(f"   🟢 ACCESS GRANTED: Admin user")
                return await call_next(request)
            
            # Get required permissions
            required_permissions = access_point_dao.get_permissions_for_access_point(
                access_point.access_id
            )
            
            print(f"   🔒 Required: {required_permissions}")
            print(f"   🔑 User has: {list(user_permissions)}")
            
            # Check permissions
            if required_permissions and not set(required_permissions).intersection(user_permissions):
                print(f"   ❌ ACCESS DENIED: Insufficient permissions")
                return JSONResponse(
                    status_code=403, 
                    content={
                        "detail": "You don't have permission to access this resource",
                        "required_permissions": required_permissions,
                        "user_permissions": list(user_permissions)
                    }
                )
            
            print(f"   🟢 ACCESS GRANTED: Permission check passed")
            return await call_next(request)
            
        except Exception as e:
            print(f"   ❌ ERROR: {str(e)}")
            logger.error(f"Permission middleware error: {str(e)}")
            return JSONResponse(
                status_code=500, 
                content={"detail": "Internal server error during permission check"}
            )