from fastapi import APIRouter, HTTPException
from ..interfaces.otp_interface import OTPRequest, OTPValidateRequest
from ...Business_Layer.services.otp_service import send_otp_service, validate_otp_service

router = APIRouter()

@router.post("/send-otp")
def send_otp(request: OTPRequest):
    try:
        return send_otp_service(request.email)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/validate-otp")
def validate_otp(request: OTPValidateRequest):
    return validate_otp_service(request.email, request.otp)
