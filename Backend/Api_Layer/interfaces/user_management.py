from pydantic import BaseModel
from typing import List

class UserBase(BaseModel):
    first_name: str
    last_name: str
    mail: str
    contact: str
    password: str
    is_active: bool = True

class UserOut(UserBase):
    user_id: int
    class Config:
       from_attributes = True

class UserRoleUpdate(BaseModel):
    role_ids: list[int]


class UserWithRoleNames(BaseModel):
    user_id: int
    name: str  # e.g., "John Doe"
    roles: List[str]  # Only role names

    class Config:
        from_attributes = True