# Backend/Business_Layer/utils/redis_client.py
import redis
from ...config.env_loader import get_env_var

REDIS_URL = get_env_var("REDIS_URL")

_redis_client = None
_redis_available = True

def get_redis_client():
    """
    Returns a connected synchronous Redis client.
    Uses singleton pattern to avoid multiple connections.
    Returns None if Redis is unavailable (no delays).
    """
    global _redis_client, _redis_available
    
    # If we already know Redis is unavailable, return immediately
    if not _redis_available:
        return None
    
    if _redis_client is None:
        try:
            # Parse Redis URL or use defaults
            _redis_client = redis.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=1,  # Quick timeout
                socket_timeout=1,
                retry_on_timeout=False
            )
            # Test connection
            _redis_client.ping()
            print("✅ Redis connected successfully")
        except Exception as e:
            print(f"⚠️ Redis unavailable, running without cache: {e}")
            _redis_available = False
            _redis_client = None
            return None
    
    return _redis_client

def close_redis_client():
    """Close Redis connection"""
    global _redis_client
    if _redis_client:
        _redis_client.close()
        _redis_client = None