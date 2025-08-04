from sqlalchemy.orm import Session
from ...Data_Access_Layer.utils.dependency import SessionLocal

class BaseService:
    def __init__(self):
        self.db: Session = SessionLocal()
    
    def __del__(self):
        self.db.close()
