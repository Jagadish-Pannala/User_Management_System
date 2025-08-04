from pydantic import BaseModel

# Schemas
class GroupBase(BaseModel):
    group_name: str

class GroupOut(GroupBase):
    group_id: int
    class Config:
        from_attributes = True

class PermissionInGroup(BaseModel):
    code: str
    description: str

class PermissionInGroupwithId(BaseModel):
    permission_id: int
    code: str
    description: str
