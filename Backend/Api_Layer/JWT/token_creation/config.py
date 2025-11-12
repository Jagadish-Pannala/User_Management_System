# Backend/Api_Layer/JWT/token_creation/config.py

from Backend.Business_Layer.utils.jwt_key_update import rotate_jwt_keys
from Backend.Data_Access_Layer.utils.database import get_db_session, set_db_session
from Backend.Data_Access_Layer.models.jwt import JWTKeys
from sqlalchemy.orm import Session
import json


def get_jwt_keys():
    """
    Fetch the latest active JWT key from DB. 
    If none found, trigger rotation and fetch again.
    """
    db: Session = set_db_session()

    key_record = (
        db.query(JWTKeys)
        .filter(JWTKeys.is_active == True)
        .order_by(JWTKeys.created_at.desc())
        .first()
    )

    # If no key found, auto-rotate once
    if not key_record:
        print("⚠️ No active JWT key found — rotating...")
        rotate_jwt_keys()
        db.commit()

        key_record = (
            db.query(JWTKeys)
            .filter(JWTKeys.is_active == True)
            .order_by(JWTKeys.created_at.desc())
            .first()
        )

        if not key_record:
            raise Exception("Key rotation failed — no JWT keys in DB")

    private_pem = key_record.private_key
    public_pem = key_record.public_key
    kid = key_record.kid
    algorithm = key_record.algorithm

    return private_pem, public_pem, algorithm, kid