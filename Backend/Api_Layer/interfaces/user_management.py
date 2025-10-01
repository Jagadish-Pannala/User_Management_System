from pydantic import BaseModel
from typing import List,Optional
from datetime import datetime

class UserBase(BaseModel):
    user_uuid: Optional[str] = None 
    first_name: str
    last_name: str
    mail: str
    contact: str
    password: Optional[str] = None
    is_active: bool = True
    last_login_ip: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    password_last_updated: Optional[datetime] = None 
    last_login_at: Optional[datetime] = None 

class UserBaseIn(BaseModel):
    user_uuid: Optional[str] = None 
    first_name: str
    last_name: str
    mail: str
    contact: str
    password: Optional[str] = None
    is_active: bool = True

class UserOut(UserBase):
    user_id: int
    class Config:
       from_attributes = True

class UserOut_uuid(UserBase):
    class Config:
       from_attributes = True
class UserRoleUpdate(BaseModel):
    role_ids: list[str]


class UserWithRoleNames(BaseModel):
    user_id: int
    name: str  # e.g., "John Doe"
    roles: List[str]  # Only role names
    mail: str

    class Config:
        from_attributes = True