import json
import redis
from typing import Any, Optional
from .redis_client import redis_client as r

# Initialize Redis connection

# Cache keys prefix
ACCESS_POINT_CACHE_PREFIX = "access_point_cache"

def make_cache_key(method: str, path: str) -> str:
    return f"{ACCESS_POINT_CACHE_PREFIX}:{method}:{path}"

def get_access_point_from_cache(method: str, path: str) -> Optional[dict]:
    key = make_cache_key(method, path)
    data = r.get(key)
    return json.loads(data) if data else None

def set_access_point_cache(method: str, path: str, value: dict):
    key = make_cache_key(method, path)
    r.set(key, json.dumps(value))

def delete_access_point_cache(method: str, path: str):
    key = make_cache_key(method, path)
    r.delete(key)

def clear_all_access_point_cache():
    for key in r.scan_iter(f"{ACCESS_POINT_CACHE_PREFIX}:*"):
        r.delete(key)
