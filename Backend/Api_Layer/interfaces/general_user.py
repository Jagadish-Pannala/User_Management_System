from pydantic import BaseModel
from typing import Optional

class EditProfile(BaseModel):
    first_name: str
    last_name: str
    contact: str
    password: Optional[str] = None

class EditProfileHr(BaseModel):
    first_name: str
    last_name: str
    contact: str
    is_active: bool