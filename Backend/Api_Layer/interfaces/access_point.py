from pydantic import BaseModel, Field, validator
from typing import Optional, Literal

class AccessPointCreate(BaseModel):
    endpoint_path: str
    method: Literal["GET", "POST", "PUT", "DELETE"]
    module: str
    is_public: Optional[bool] = False

class AccessPointOut(BaseModel):
    access_id: int
    endpoint_path: str
    method: Literal["GET", "POST", "PUT", "DELETE"]
    module: str
    is_public: Optional[bool] = False
    permission_code: Optional[str] = None  # flattening from relationship
    permission_id: Optional[int]

    class Config:
        from_attributes = True

class AccessPointUpdate(BaseModel):
    endpoint_path: Optional[str] = None
    method: Optional[Literal["GET", "POST", "PUT", "DELETE"]] = None
    module: Optional[str] = None
    is_public: Optional[bool] = None
    permission_code: Optional[str] = None

class CreateAPResponse(BaseModel):
    access_id: int
    message: str

class PermissionMappingIn(BaseModel):
    permission_id: int
