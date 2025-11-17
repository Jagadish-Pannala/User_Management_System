# jwt_validator/auth/oidc_config.py

import json
import threading
from jwt import algorithms
from Backend.config.env_loader import get_env_var
from pathlib import Path
from typing import Optional
import os
import logging
import traceback

# Import JWKS generator
from Backend.Api_Layer.JWT.token_creation.jwks_generator import generate_jwks

ISSUER = get_env_var("ISSUER")

class OIDCValidator:
    def __init__(self):
        self.issuer = ISSUER
        self.jwks_dict = {}
        self._config_loaded = False
        self._config_lock = threading.Lock()
        self.jwks_path = None
        
        # Find or create JWKS file
        self._find_or_create_jwks_file()

    def _find_or_create_jwks_file(self):
        """Find the JWKS file, or auto-generate if missing"""
        print("🔍 Searching for JWKS file...")

        try:
            # Step 1: Compute expected JWKS path
            current_file = Path(__file__).resolve()
            backend_root = current_file.parent
            while backend_root.name != "Backend" and backend_root.parent != backend_root:
                backend_root = backend_root.parent
            
            jwks_path = backend_root / "Api_Layer" / "JWT" / "token_creation" / "jwks.json"
            print(f"Expected JWKS path: {jwks_path}")

            # Step 2: If missing, generate it
            if not jwks_path.exists():
                print("⚠️ JWKS file not found. Generating a new one...")
                try:
                    generate_jwks()
                    print(f"✅ JWKS successfully generated at: {jwks_path}")
                except Exception as gen_err:
                    print(f"❌ JWKS auto-generation failed: {gen_err}")
                    raise

            self.jwks_path = jwks_path
            print(f"✅ JWKS file ready at: {self.jwks_path}")

        except Exception as e:
            print(f"❌ JWKS file detection/generation failed: {e}")
            traceback.print_exc()
            raise FileNotFoundError("Could not find or create JWKS file.") from e

    def _load_config_from_file(self, force_reload=False):
        """Load JWKS configuration directly from file - no HTTP requests
        
        Args:
            force_reload: If True, reload even if already loaded (clears cache)
        """
        with self._config_lock:
            # ✅ UPDATED: Allow forcing a reload even if already loaded
            if self._config_loaded and not force_reload:
                return
            
            try:
                # ✅ UPDATED: Log reload status
                if force_reload:
                    print("🔄 Force reloading OIDC configuration from JWKS file...")
                else:
                    print("📂 Loading OIDC configuration from JWKS file...")
                
                if not self.jwks_path or not self.jwks_path.exists():
                    print("⚠️ JWKS file missing during load. Regenerating...")
                    generate_jwks()

                with open(self.jwks_path, 'r', encoding='utf-8') as f:
                    jwks_data = json.load(f)

                if "keys" not in jwks_data or not jwks_data["keys"]:
                    print("⚠️ Empty or invalid JWKS file. Regenerating...")
                    generate_jwks()
                    with open(self.jwks_path, 'r', encoding='utf-8') as f:
                        jwks_data = json.load(f)

                keys = jwks_data.get("keys", [])
                print(f"Found {len(keys)} keys in JWKS file.")

                # ✅ UPDATED: Clear existing keys when force reloading
                if force_reload:
                    old_kids = list(self.jwks_dict.keys())
                    self.jwks_dict.clear()
                    print(f"🗑️ Cleared {len(old_kids)} cached keys: {old_kids}")

                for i, key in enumerate(keys):
                    try:
                        kid = key.get("kid")
                        if not kid:
                            print(f"⚠️ Key #{i+1} missing 'kid', skipping.")
                            continue
                        rsa_key = algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                        self.jwks_dict[kid] = rsa_key
                        print(f"✅ Loaded key: {kid}")
                    except Exception as key_error:
                        print(f"❌ Failed to process key #{i+1}: {key_error}")
                        continue

                if not self.jwks_dict:
                    raise ValueError("No valid keys could be processed from JWKS file.")

                self._config_loaded = True
                print(f"✅ OIDC configuration successfully loaded.")
                print(f"Available KIDs: {list(self.jwks_dict.keys())}")

            except Exception as e:
                print(f"❌ Failed to load JWKS configuration: {e}")
                traceback.print_exc()
                raise

    def is_ready(self):
        """Check if configuration is loaded"""
        return self._config_loaded

    def get_signing_key(self, kid: str):
        """Get signing key by KID, auto-reload if not found
        
        Args:
            kid: The Key ID from the JWT header
            
        Returns:
            RSA public key for signature verification
            
        Raises:
            ValueError: If KID not found even after reload
        """
        if not self.is_ready():
            raise RuntimeError("OIDC configuration not loaded.")
        
        # ✅ UPDATED: Auto-reload if KID not found in cache
        if kid not in self.jwks_dict:
            available = list(self.jwks_dict.keys())
            print(f"⚠️ Key ID '{kid}' not found in cache.")
            print(f"   Current cached KIDs: {available}")
            print(f"   Attempting to reload JWKS from file...")
            
            # Force reload from file
            self._load_config_from_file(force_reload=True)
            
            # ✅ UPDATED: Check again after reload
            if kid not in self.jwks_dict:
                available = list(self.jwks_dict.keys())
                raise ValueError(
                    f"Key ID '{kid}' not found even after reloading JWKS. "
                    f"Available keys: {available}"
                )
            
            print(f"✅ Key '{kid}' successfully loaded after reload")
        
        return self.jwks_dict[kid]

# --- Global helpers ---

_oidc_validator: Optional[OIDCValidator] = None
_oidc_lock = threading.Lock()

def get_oidc_validator():
    """Returns the singleton OIDC validator instance (lazy-loaded)."""
    global _oidc_validator

    if _oidc_validator is not None and _oidc_validator.is_ready():
        return _oidc_validator

    with _oidc_lock:
        if _oidc_validator is None:
            print("🔐 Initializing OIDC validator...")
            _oidc_validator = OIDCValidator()

        if not _oidc_validator.is_ready():
            _oidc_validator._load_config_from_file()

        return _oidc_validator

def reset_oidc_validator():
    """Reset the validator for refresh/debug purposes."""
    global _oidc_validator
    with _oidc_lock:
        _oidc_validator = None
        print("🔄 OIDC validator reset.")

def check_oidc_health():
    """Perform a quick health check on JWKS file availability."""
    try:
        validator = get_oidc_validator()
        return validator.is_ready()
    except Exception as e:
        print(f"❌ OIDC health check failed: {e}")
        return False