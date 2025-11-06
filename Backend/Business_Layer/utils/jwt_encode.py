from cryptography.fernet import Fernet
from Backend.config.env_loader import get_env_var

# Get encryption key from environment (.env)
FERNET_KEY = get_env_var("FERNET_SECRET_KEY")  # Must be a base64-encoded 32-byte key
fernet = Fernet(FERNET_KEY)

# Encrypt PEM before storing
def encrypt_key(pem_data: str) -> str:
    return fernet.encrypt(pem_data.encode()).decode()

# Decrypt PEM after retrieving
def decrypt_key(encrypted_pem: str) -> str:
    return fernet.decrypt(encrypted_pem.encode()).decode()
