
from pathlib import Path

# Token settings
ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 6000000
ISSUER = "http://localhost:8000"
KID = "auth-key-001"  # Must match JWKS key later

# Path to private key
BASE_DIR = Path(__file__).resolve().parent
print("hello",BASE_DIR)
PRIVATE_KEY_PATH = BASE_DIR / "keys" / "private.pem"
print("hello",PRIVATE_KEY_PATH)