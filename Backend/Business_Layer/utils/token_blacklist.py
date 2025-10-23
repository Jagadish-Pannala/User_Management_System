import time
import jwt
from datetime import datetime
from .redis_client import get_redis_client
from ...Api_Layer.JWT.jwt_validator.auth.jwt_utils import decode_access_token

# Redis key prefix
BLACKLIST_PREFIX = "blacklist:"

def blacklist_token(token: str):
    """
    Adds the token's jti (unique id) to Redis with TTL = remaining token lifetime.
    If Redis is unavailable, silently skip (fallback mode).
    """
    redis_client = get_redis_client()
    if not redis_client:
        print("⚠️ Redis unavailable - cannot blacklist token")
        return False
    
    try:
        # Decode without verifying expiration
        payload = decode_access_token(token)
        jti = payload.get("jti")
        exp = float(payload.get("exp", 0))
        ttl = int(exp - time.time())

        if ttl > 0 and jti:
            redis_client.setex(f"{BLACKLIST_PREFIX}{jti}", ttl, "1")
            print(f"🗑️ Token blacklisted (jti={jti}, ttl={ttl}s)")
            return True
    except Exception as e:
        print(f"⚠️ Blacklist failed: {e}")
    
    return False


def is_token_blacklisted(jti: str) -> bool:
    """
    Checks if a given token jti is blacklisted in Redis.
    Returns False if Redis is down (fails open).
    """
    redis_client = get_redis_client()
    if not redis_client:
        return False  # Redis down, allow temporarily

    return redis_client.exists(f"{BLACKLIST_PREFIX}{jti}") == 1
