from pydantic import BaseModel, Field, validator
from typing import Optional, Literal, List
from uuid import UUID
from datetime import datetime


# Define all supported HTTP methods
HttpMethod = Literal[
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
    "TRACE",
    "CONNECT"
]


class AccessPointCreate(BaseModel):
    endpoint_path: str
    method: HttpMethod
    module: str
    is_public: Optional[bool] = False


class AccessPointOut(BaseModel):
    access_uuid: UUID
    endpoint_path: str
    method: HttpMethod
    module: str
    is_public: Optional[bool] = False
    permission_code: Optional[str] = None
    permission_uuid: Optional[UUID] = None

    class Config:
        from_attributes = True


class AccessPointUpdate(BaseModel):
    endpoint_path: Optional[str] = None
    method: Optional[HttpMethod] = None
    module: Optional[str] = None
    is_public: Optional[bool] = None
    permission_code: Optional[str] = None


class CreateAPResponse(BaseModel):
    access_uuid: str
    message: str

class BulkCreateAPResponse(BaseModel):
    summary: dict
    created_access_points: List[CreateAPResponse]
    errors: List[dict]

class PermissionMappingIn(BaseModel):
    permission_uuid: str
