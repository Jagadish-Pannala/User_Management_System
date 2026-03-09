# Backend/Api_Layer/JWT/token_creation/config.py

from Backend.Data_Access_Layer.utils.database import get_db_session
from Backend.Data_Access_Layer.models.jwt import JWTKeys
from sqlalchemy import and_
from sqlalchemy.sql import func
import time

# ---- Module-level cache ----
_cached_keys = None
_cache_expiry = 0
CACHE_TTL_SECONDS = 300  # re-fetch from DB every 5 minutes

def get_jwt_keys(db=None):
    """
    Returns active JWT keys. Uses in-memory cache to avoid
    DB hit on every login. Cache refreshes every 5 minutes.
    """
    global _cached_keys, _cache_expiry

    # ✅ Return cached keys if still valid
    if _cached_keys and time.time() < _cache_expiry:
        return _cached_keys

    # ✅ Use provided session or get from context (never create new one)
    if db is None:
        db = get_db_session()

    now = func.now()
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

    if not key_record:
        print("⚠️ No active JWT key found — rotating...")
        from Backend.Business_Layer.utils.jwt_key_update import rotate_jwt_keys
        rotate_jwt_keys()
        db.commit()

        from Backend.Api_Layer.JWT.token_creation.jwks_generator import generate_jwks
        try:
            generate_jwks()
        except Exception as e:
            print(f"⚠️ Failed to update JWKS: {e}")

        key_record = (
            db.query(JWTKeys)
            .filter(JWTKeys.is_active == True)
            .order_by(JWTKeys.created_at.desc())
            .first()
        )
        if not key_record:
            raise Exception("Key rotation failed — no JWT keys in DB")

    # ✅ Cache the result
    _cached_keys = (
        key_record.private_key,
        key_record.public_key,
        key_record.algorithm,
        key_record.kid
    )
    _cache_expiry = time.time() + CACHE_TTL_SECONDS
    print("✅ JWT keys cached for 5 minutes")

    return _cached_keys