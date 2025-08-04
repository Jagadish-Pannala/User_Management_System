from sqlalchemy import Column, String, DateTime, Integer
from datetime import datetime, timedelta
from ..utils.database import Base
 
class OTP(Base):
    __tablename__ = "OTP"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(150), index=True)  # Specify length
    otp = Column(String(10))                 # Specify length
    expires_at = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(minutes=5))