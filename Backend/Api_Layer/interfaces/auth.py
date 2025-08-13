from pydantic import BaseModel, EmailStr, Field

class RegisterUser(BaseModel):
    first_name: str = Field(..., min_length=2, max_length=50)
    last_name: str = Field(..., min_length=2, max_length=50)
    mail: EmailStr = Field(..., description="User's email address")
    contact: str = Field(
        ..., 
        pattern=r'^\d{10}$',  # ✅ use pattern instead of regex
        description="10-digit contact number"
    )
    password: str = Field(
        ..., 
        min_length=8, 
        description="Password must be at least 6 characters long"
    )

class LoginUser(BaseModel):
    email: str
    password: str

class ForgotPassword(BaseModel):
    email: str
    otp: str
    new_password: str

