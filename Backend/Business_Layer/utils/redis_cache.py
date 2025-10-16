# redis_cache.py
from .redis_client import get_redis_client
import json

ACCESS_POINT_CACHE_PREFIX = "access_point_cache"

def make_cache_key(method: str, path: str) -> str:
    return f"{ACCESS_POINT_CACHE_PREFIX}:{method}:{path}"

async def get_access_point_from_cache(method: str, path: str):
    try:
        r = await get_redis_client()
        if not r:
            return None
        key = f"access_point_cache:{method}:{path}"
        data = await r.get(key)
        if data:
            import json
            return json.loads(data)
        return None
    except Exception as e:
        print(f"Redis get failed: {e}")
        return None


async def set_access_point_cache(method: str, path: str, value: dict):
    r = await get_redis_client()
    if r is None:
        return
    key = make_cache_key(method, path)
    await r.set(key, json.dumps(value))

async def delete_access_point_cache(method: str, path: str):
    r = await get_redis_client()
    if r is None:
        return  # <-- prevent NoneType error
    key = make_cache_key(method, path)
    await r.delete(key)

async def clear_all_access_point_cache():
    r = await get_redis_client()
    if r is None:
        return
    async for key in r.scan_iter(f"{ACCESS_POINT_CACHE_PREFIX}:*"):
        await r.delete(key)
