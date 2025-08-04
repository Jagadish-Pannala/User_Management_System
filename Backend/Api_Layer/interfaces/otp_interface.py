from pydantic import BaseModel, EmailStr

class OTPRequest(BaseModel):
    email: EmailStr
 
class OTPValidateRequest(BaseModel):
    email: EmailStr
    otp: str