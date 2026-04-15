"""
Run once manually (or via cron/deployment) to generate a JWKS (JSON Web Key Set)
from the active RSA public key stored in the database.
"""

import json
import logging
from jwcrypto import jwk
from pathlib import Path
from Backend.Api_Layer.JWT.token_creation.config import get_jwt_keys
from Backend.Business_Layer.utils.jwt_encode import (
    decrypt_key,
)  # ✅ Use existing decrypt function


def generate_jwks():
    """
    Converts the active public key (PEM) from DB into JWKS format
    and saves it as jwks.json
    """
    private_pem, public_pem, ALGORITHM, KID = get_jwt_keys()
    JWKS_OUTPUT_PATH = Path(__file__).parent / "jwks.json"

    try:
        # 🔓 Decrypt the Fernet-encrypted public key from DB
        decrypted_public_pem = decrypt_key(public_pem)

        # ✅ Convert the PEM public key into a JWK object
        key = jwk.JWK.from_pem(decrypted_public_pem.encode("utf-8"))

        # ✅ Add required metadata
        key_dict = json.loads(key.export_public())
        key_dict["use"] = "sig"  # used for signature verification
        key_dict["alg"] = ALGORITHM
        key_dict["kid"] = KID

        # ✅ Create JWKS container
        jwks = {"keys": [key_dict]}

        # ✅ Write the JWKS file
        with open(JWKS_OUTPUT_PATH, "w", encoding="utf-8") as f:
            json.dump(jwks, f, indent=2)

        logging.info(f"✅ JWKS successfully written to {JWKS_OUTPUT_PATH}")

    except Exception as e:
        logging.error(f"❌ Failed to generate JWKS: {e}")
        raise


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logging.info("Generating JWKS from database keys...")
    generate_jwks()
    logging.info("JWKS generation completed ✅")
