
from pathlib import Path
from Backend.config.env_loader import get_env_var


# Token settings
ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1  # 10 minutes
ISSUER = get_env_var("ISSUER")  # Load from environment variable
KID = "auth-key-001"  # Must match JWKS key later

# Path to private key
BASE_DIR = Path(__file__).resolve().parent
print("hello",BASE_DIR)
PRIVATE_KEY_PATH = BASE_DIR / "keys" / "private.pem"
print("hello",PRIVATE_KEY_PATH)