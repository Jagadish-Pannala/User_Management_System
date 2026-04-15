from sqlalchemy import Column, String, DateTime, Integer, Boolean, Text
from datetime import datetime, timedelta
from ..utils.database import Base


class JWTKeys(Base):
    __tablename__ = "jwt_keys"

    id = Column(Integer, primary_key=True, index=True)
    kid = Column(String(255), unique=True, nullable=False)
    private_key = Column(Text, nullable=False)  # You can use Text if the key is long
    public_key = Column(Text, nullable=False)
    algorithm = Column(String(20), default="RS256")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(days=3))
