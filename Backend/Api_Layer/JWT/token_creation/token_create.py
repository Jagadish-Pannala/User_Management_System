# Backend/Api_Layer/JWT/token_creation/token_create.py
from datetime import datetime, timedelta, timezone
import jwt
from typing import Optional
from .config import get_jwt_keys
from Backend.Business_Layer.utils.jwt_encode import decrypt_key  # ✅ Add this import
from Backend.config.env_loader import get_env_var
from ....Business_Layer.utils.generate_uuid7 import generate_uuid7

ACCESS_TOKEN_EXPIRE_MINUTES = int(get_env_var("ACCESS_TOKEN_EXPIRE_MINUTES"))

def get_issuer_from_request(request) -> str:
    scheme = request.url.scheme
    host = request.headers.get("host")
    issuer = f"{scheme}://{host}"
    print("Determined Issuer from request:", issuer)
    return issuer


def token_create(token_data: dict, request=None, issuer: Optional[str] = None) -> str:
    private_key_enc, public_key_enc, ALGORITHM, KID = get_jwt_keys()

    # 🔓 Decrypt both keys (especially private key)
    private_key = decrypt_key(private_key_enc)
    public_key = decrypt_key(public_key_enc)

    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    jti = generate_uuid7()

    # Automatically determine issuer
    if issuer is None and request is not None:
        issuer = get_issuer_from_request(request)
    elif issuer is None:
        raise ValueError("Either 'request' or 'issuer' must be provided")

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

    headers = {"kid": KID}

    # ✅ Use decrypted private key to sign the token
    token = jwt.encode(payload, private_key, algorithm=ALGORITHM, headers=headers)

    return token
