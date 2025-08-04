from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from ...Data_Access_Layer.utils.dependency import SessionLocal
from ...Data_Access_Layer.models.otp import OTP
from ..utils.email_utils import generate_otp, send_otp_email

def send_otp_service(email: str):
    db: Session = SessionLocal()

    # Remove existing OTPs
    db.query(OTP).filter(OTP.email == email).delete()

    otp = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=5)

    db_otp = OTP(email=email, otp=otp, expires_at=expires_at)
    db.add(db_otp)
    db.commit()

    send_otp_email(email, otp)
    return {"message": "OTP sent successfully"}

def validate_otp_service(email: str, otp: str):
    db: Session = SessionLocal()

    db_otp = db.query(OTP).filter(OTP.email == email, OTP.otp == otp).first()
    if db_otp and db_otp.expires_at > datetime.utcnow():
        db.delete(db_otp)
        db.commit()
        return {"message": "OTP validated successfully"}
    else:
        raise Exception("Invalid or expired OTP")
