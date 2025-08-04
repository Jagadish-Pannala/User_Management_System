# jwt_validator/auth/oidc_config.py

import requests
from jwt import algorithms

class OIDCValidator:
    def __init__(self, config_url: str):
        self.config_url = config_url
        self.issuer = None
        self.jwks_uri = None
        self.jwks_dict = {}
        self._load_config()

    def _load_config(self):
        response = requests.get(self.config_url)
        response.raise_for_status()
        config = response.json()
        self.issuer = config['issuer']
        self.jwks_uri = config['jwks_uri']

        jwks_response = requests.get(self.jwks_uri)
        jwks_response.raise_for_status()
        keys = jwks_response.json().get('keys', [])

        for key in keys:
            kid = key['kid']
            self.jwks_dict[kid] = algorithms.RSAAlgorithm.from_jwk(key)

# Lazy loader pattern
_oidc_validator = None

def get_oidc_validator():
    global _oidc_validator
    if _oidc_validator is None:
        _oidc_validator = OIDCValidator("http://localhost:8000/.well-known/openid-configuration")
    return _oidc_validator
