from datetime import datetime, timedelta, timezone
import jwt

from .config import (
    PRIVATE_KEY_PATH,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    ISSUER,
    KID
)

def token_create(token_data: dict) -> str:
    # Load the private key
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = key_file.read()

    # Set expiration
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    # Create payload
    payload = {
        "user_id": token_data["user_id"],
        "email": token_data["email"],
        "name": token_data["name"],
        "roles": token_data["roles"],
        "permissions": token_data["permissions"],
        "iss": ISSUER,
        "exp": expire
    }

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
