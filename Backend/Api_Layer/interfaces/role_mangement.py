from pydantic import BaseModel
from typing import List
from datetime import datetime
from uuid import UUID

class RoleBase(BaseModel):
    role_name: str

class RoleOut(RoleBase):
    role_uuid: str
    class Config:
        from_attributes = True

class RolePermissionGroupUpdate(BaseModel):
    group_ids: list[int]

class RoleGroupRequest(BaseModel):
    group_ids: List[int]

class Group(BaseModel):
    group_uuid: UUID
    group_name: str
    created_at: datetime
    created_by: int
    updated_at: datetime