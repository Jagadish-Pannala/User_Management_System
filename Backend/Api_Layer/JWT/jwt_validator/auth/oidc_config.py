import json
from jwt import algorithms
from Backend.config.env_loader import get_env_var
from cryptography.hazmat.primitives import serialization
import httpx

ISSUER = get_env_var("ISSUER")


class OIDCValidator:
    def __init__(self, config_url: str):
        self.config_url = config_url
        self.issuer = None
        self.jwks_uri = None
        self.jwks_dict = {}  # kid -> PEM key
        self._config_loaded = False

    async def _load_config(self):
        if self._config_loaded:
            return

        print(f"[OIDCValidator] Fetching OIDC config from {self.config_url}")

        async with httpx.AsyncClient() as client:
            # Fetch OIDC configuration
            response = await client.get(self.config_url, timeout=10)
            response.raise_for_status()
            config = response.json()
            self.issuer = config["issuer"]
            self.jwks_uri = config["jwks_uri"]

            # Fetch JWKS
            jwks_response = await client.get(self.jwks_uri, timeout=10)
            jwks_response.raise_for_status()
            keys = jwks_response.json().get("keys", [])
            

            if not keys:
                print("[OIDCValidator] Warning: No keys found in JWKS endpoint")

            for key in keys:
                kid = key.get("kid")
                if not kid:
                    continue
                # Convert JWK to RSA key object
                rsa_key = algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                # Convert RSA key object to PEM bytes
                pem_bytes = rsa_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                # Convert bytes to string (PEM format)
                pem_str = pem_bytes.decode("utf-8")
                self.jwks_dict[kid] = pem_str
                print(f"[OIDCValidator] Loaded key for kid={kid}")

        self._config_loaded = True

    async def get_key(self, kid: str):
        if not self._config_loaded:
            await self._load_config()
        return self.jwks_dict.get(kid)


# Singleton / lazy loader
_oidc_validator = None


def get_oidc_validator() -> OIDCValidator:
    """
    Returns a single global OIDCValidator instance.
    Does not fetch config until first key lookup.
    """
    global _oidc_validator
    if _oidc_validator is None:
        print(f"[get_oidc_validator] Creating OIDCValidator for {ISSUER}")
        _oidc_validator = OIDCValidator(f"{ISSUER}/.well-known/openid-configuration")
    return _oidc_validator
