from pydantic import BaseModel
from typing import Optional, List
from enum import Enum

class PermissionBase(BaseModel):
    permission_code: str
    description: str

class PermissionOut(PermissionBase):
    permission_id: int
    class Config:
        from_attributes = True

class PermissionCreate(PermissionBase):
    group_id: int

class PermissionCreateU(PermissionBase):
    pass

class PermissionGroupUpdate(BaseModel):
    group_id: int

class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"

class AccessPointBase(BaseModel):
    endpoint_path: str
    method: HTTPMethod
    module: str
    is_public: bool = False

class AccessPointPermissionMappingIn(BaseModel):
    access_id: int
    permission_code: str


class PermissionResponse(BaseModel):
    permission_id: int
    permission_code: str
    description: str
    
    class Config:
        from_attributes = True
