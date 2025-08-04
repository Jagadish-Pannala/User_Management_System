'''
Run once manually (or through a deployment script)

Convert public.pem to a proper JWKS JSON format

Save that result for use by your authentication system (public key distribution)
'''

import json
from jwcrypto import jwk
from pathlib import Path
import logging

# Constants
PUBLIC_KEY_PATH = Path(__file__).parent / "keys" / "public.pem"
print("Public Key Path:", PUBLIC_KEY_PATH)
JWKS_OUTPUT_PATH = Path(__file__).parent / "jwks.json"
KID = "auth-key-001"   # Must match JWT 'kid' in token header
ALGORITHM = "RS256"

def generate_jwks():
    try:
        # Load the public key from PEM
        with open(PUBLIC_KEY_PATH, "rb") as pub_file:
            public_pem = pub_file.read()
        logging.info(f"Loaded public key from {PUBLIC_KEY_PATH}")
    except Exception as e:
        logging.error(f"Failed to load public key: {e}")
        raise

    try:
        # Create a JWK object from the PEM
        key = jwk.JWK.from_pem(public_pem)
        # Add required metadata
        key_dict = json.loads(key.export_public())
        key_dict["use"] = "sig"
        key_dict["alg"] = ALGORITHM
        key_dict["kid"] = KID
        # Create the final JWKS
        jwks = {
            "keys": [key_dict]
        }
        # Write to jwks.json
        with open(JWKS_OUTPUT_PATH, "w") as f:
            json.dump(jwks, f, indent=2)
        logging.info(f"JWKS written to {JWKS_OUTPUT_PATH}")
    except Exception as e:
        logging.error(f"Failed to generate or write JWKS: {e}")
        raise

# Run only if this is called directly
if __name__ == "__main__":
    generate_jwks()
