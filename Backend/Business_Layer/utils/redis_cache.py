# Backend/Business_Layer/utils/redis_cache.py
from .redis_client import get_redis_client
import json

ACCESS_POINT_CACHE_PREFIX = "access_point_cache"

def make_cache_key(method: str, path: str) -> str:
    return f"{ACCESS_POINT_CACHE_PREFIX}:{method}:{path}"

def get_access_point_from_cache(method: str, path: str):
    """Synchronous - returns None if Redis unavailable"""
    try:
        r = get_redis_client()
        if not r:
            return None
        key = make_cache_key(method, path)
        data = r.get(key)
        if data:
            return json.loads(data)
        return None
    except Exception:
        return None

def set_access_point_cache(method: str, path: str, value: dict):
    """Synchronous - silent fail if Redis unavailable"""
    try:
        r = get_redis_client()
        if r is None:
            return
        key = make_cache_key(method, path)
        r.set(key, json.dumps(value))
    except Exception:
        pass

def delete_access_point_cache(method: str, path: str):
    """Synchronous - silent fail if Redis unavailable"""
    try:
        r = get_redis_client()
        if r is None:
            return
        key = make_cache_key(method, path)
        r.delete(key)
    except Exception:
        pass

def delete_access_point_cache_by_path(path: str):
    """
    Delete cache for a specific path across ALL methods.
    Use this when you update/delete an access point.
    """
    try:
        r = get_redis_client()
        if r is None:
            return
        
        # Find all keys for this path with any method
        pattern = f"{ACCESS_POINT_CACHE_PREFIX}:*:{path}"
        keys = r.keys(pattern)
        
        if keys:
            r.delete(*keys)
            print(f"🗑️ Deleted {len(keys)} cache entries for path: {path}")
    except Exception as e:
        print(f"Cache deletion failed: {e}")

def clear_all_access_point_cache():
    """Synchronous - silent fail if Redis unavailable"""
    try:
        r = get_redis_client()
        if r is None:
            return
        keys = r.keys(f"{ACCESS_POINT_CACHE_PREFIX}:*")
        if keys:
            r.delete(*keys)
            print(f"🗑️ Cleared {len(keys)} cache entries")
    except Exception:
        pass