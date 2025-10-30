from datetime import datetime, timedelta, timezone
import jwt
from typing import Optional

from .config import (
    PRIVATE_KEY_PATH,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    KID
)

from ....Business_Layer.utils.generate_uuid7 import generate_uuid7

def get_issuer_from_request(request) -> str:
    """
    Automatically determine the issuer from the request.
    
    Args:
        request: FastAPI/Starlette Request object
        
    Returns:
        str: The issuer URL (e.g., "http://localhost:8000" or "https://api.example.com")
    """
    # Get the base URL from the request
    scheme = request.url.scheme  # http or https
    host = request.headers.get("host")  # e.g., localhost:8000 or api.example.com
    
    # Construct the issuer
    issuer = f"{scheme}://{host}"
    print("Determined Issuer from request:", issuer)
    
    return issuer

def token_create(token_data: dict, request=None, issuer: Optional[str] = None) -> str:
    """
    Create a JWT token with automatic issuer detection.
    
    Args:
        token_data: Dictionary containing user information
        request: Optional FastAPI/Starlette Request object for automatic issuer detection
        issuer: Optional manual issuer override
        
    Returns:
        str: JWT token
    """
    # Load the private key
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = key_file.read()

    # Set expiration
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    jti = generate_uuid7()
    
    # Automatically determine issuer
    if issuer is None and request is not None:
        issuer = get_issuer_from_request(request)
    elif issuer is None:
        # Fallback to a default or raise an error
        raise ValueError("Either 'request' or 'issuer' must be provided")
    
    # Create payload
    payload = {
        "jti": jti,
        "user_id": token_data["user_id"],
        "email": token_data["email"],
        "name": token_data["name"],
        "roles": token_data["roles"],
        "permissions": token_data["permissions"],
        "iss": issuer,
        "exp": expire
    }
    print("Token Payload:", payload)

    # Include 'kid' in JWT header
    headers = {
        "kid": KID
    }

    # Create token
    token = jwt.encode(
        payload,
        private_key,
        algorithm=ALGORITHM,
        headers=headers
    )

    return token