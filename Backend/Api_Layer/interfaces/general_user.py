from pydantic import BaseModel

class EditProfile(BaseModel):
    first_name: str
    last_name: str
    contact: str
    password: str

class EditProfileHr(BaseModel):
    first_name: str
    last_name: str
    contact: str
    is_active: bool