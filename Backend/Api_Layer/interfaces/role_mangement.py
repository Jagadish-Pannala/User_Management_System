from pydantic import BaseModel
from typing import List

class RoleBase(BaseModel):
    role_name: str

class RoleOut(RoleBase):
    role_id: int
    class Config:
        from_attributes = True

class RolePermissionGroupUpdate(BaseModel):
    group_ids: list[int]

class RoleGroupRequest(BaseModel):
    group_ids: List[int]