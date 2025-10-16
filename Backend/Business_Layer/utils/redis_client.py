# Backend/Business_Layer/utils/redis_client.py
import aioredis
from ...config.env_loader import get_env_var

REDIS_URL = get_env_var("REDIS_URL")

redis_client = None

async def get_redis_client():
    """
    Returns a connected async Redis client.
    Uses singleton pattern to avoid multiple connections.
    """
    global redis_client
    if not redis_client:
        redis_client = await aioredis.from_url(REDIS_URL, decode_responses=True)
    return redis_client
