# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from .Api_Layer.JWT.jwt_validator.middleware.jwt_middleware import JWTMiddleware
from .Data_Access_Layer.utils.database import engine
from .Data_Access_Layer.models import models
from .Api_Layer.routes import auth_routes, profile_routes, permission_group_route, role_management_routes, permission_routes, user_management_routes, access_point_routes, otp_routes
from .Api_Layer.JWT.openid_config import openid_endpoint
from .Api_Layer.JWT.jwt_validator.middleware.db_session_middleware import DBSessionMiddleware

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="User Management System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(JWTMiddleware)
app.add_middleware(DBSessionMiddleware)

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="User Management System",
        version="0.1.0",
        description="Secure API with JWT & RBAC",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            if method in ["get", "post", "put", "delete"]:
                openapi_schema["paths"][path][method]["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Route imports
app.include_router(openid_endpoint.router, prefix="", tags=["Login Management"])
app.include_router(auth_routes.router, prefix="/auth", tags=["Login Management"])
app.include_router(otp_routes.router, prefix="/auth", tags=["OTP Management"])
app.include_router(profile_routes.router, prefix="/general_user", tags=["General User Management"])
app.include_router(user_management_routes.router, prefix="/admin/users", tags=["Admin - User Management"])
app.include_router(role_management_routes.router, prefix="/admin/roles", tags=["Admin - Role Management"])
app.include_router(permission_routes.router, prefix="/admin/permissions", tags=["Admin - Permission Management"])
app.include_router(permission_group_route.router, prefix="/admin/groups", tags=["Admin - Permission Group Management"])
app.include_router(access_point_routes.router, prefix="/admin/access-points", tags=["Admin - Access Point Management"])

@app.get("/")
def read_root():
    return {"status": "User Management System API is running"}
