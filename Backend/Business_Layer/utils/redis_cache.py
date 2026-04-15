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


def delete_access_point_cache_by_id(access_id: int):
    print(f"Deleting cache entries for access_id: {access_id}")
    try:
        r = get_redis_client()
        if r is None:
            print("❌ Redis client not available")
            return

        pattern = f"{ACCESS_POINT_CACHE_PREFIX}:*"
        deleted_keys = 0

        for key in r.scan_iter(pattern):
            try:
                value = r.get(key)
                if not value:
                    continue

                data = json.loads(value)

                # Check if access_id matches
                if data.get("access_point", {}).get("access_id") == access_id:
                    r.delete(key)
                    deleted_keys += 1
                    print(f"🗑️ Deleted cache key: {key}")

            except Exception as e:
                print(f"⚠️ Error processing {key}: {e}")
                continue

        if deleted_keys == 0:
            print(f"ℹ️ No cache entries found for access_id {access_id}")
        else:
            print(f"✅ Deleted {deleted_keys} cache entries for access_id {access_id}")

    except Exception as e:
        print(f"❌ Redis deletion failed: {e}")


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
