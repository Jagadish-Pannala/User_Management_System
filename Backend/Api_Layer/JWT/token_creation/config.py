# Backend/Api_Layer/JWT/token_creation/config.py

from Backend.Business_Layer.utils.jwt_key_update import rotate_jwt_keys
from Backend.Data_Access_Layer.utils.database import get_db_session, set_db_session
from Backend.Data_Access_Layer.models.jwt import JWTKeys
from sqlalchemy.orm import Session
import json
from sqlalchemy import and_
from sqlalchemy.sql import func


def get_jwt_keys():
    """
    Fetch the latest active JWT key from DB. 
    If none found, trigger rotation and update JWKS file.
    """
    db: Session = set_db_session()

    now = func.now()  # ✅ use SQLAlchemy's server-side NOW()

    key_record = (
        db.query(JWTKeys)
        .filter(
            and_(
                JWTKeys.is_active == True,
                JWTKeys.expires_at > now
            )
        )
        .order_by(JWTKeys.created_at.desc())
        .first()
    )

    # If no key found, auto-rotate once
    if not key_record:
        print("⚠️ No active JWT key found — rotating...")
        rotate_jwt_keys()
        db.commit()
        
        # ✅ UPDATED: Import here to avoid circular dependency
        from Backend.Api_Layer.JWT.token_creation.jwks_generator import generate_jwks
        
        # ✅ UPDATED: Regenerate JWKS after rotation
        try:
            generate_jwks()
            print("✅ JWKS file updated after auto-rotation in get_jwt_keys()")
        except Exception as jwks_error:
            print(f"⚠️ Failed to update JWKS file: {jwks_error}")

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