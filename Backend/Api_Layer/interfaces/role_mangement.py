from pydantic import BaseModel
from typing import List

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