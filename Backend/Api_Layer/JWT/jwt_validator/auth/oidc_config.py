# jwt_validator/auth/oidc_config.py

import json
import threading
from jwt import algorithms
from Backend.config.env_loader import get_env_var
from pathlib import Path
from typing import Optional
import os

ISSUER = get_env_var("ISSUER")

class OIDCValidator:
    def __init__(self):
        self.issuer = ISSUER
        self.jwks_dict = {}
        self._config_loaded = False
        self._config_lock = threading.Lock()
        self.jwks_path = None
        
        # Find the JWKS file
        self._find_jwks_file()

    def _find_jwks_file(self):
        """Find the JWKS file using multiple strategies"""
        print("🔍 Searching for JWKS file...")
        
        # Strategy 1: Use the same logic as openid_endpoint.py
        try:
            # This mimics: Path(__file__).resolve().parent.parent / "token_creation" / "jwks.json"
            # from Backend/Api_Layer/JWT/openid_config/openid_endpoint.py
            
            # Find the Backend directory
            current_file = Path(__file__).resolve()
            print(f"Current file: {current_file}")
            
            # Navigate up to find Backend folder
            backend_root = current_file.parent
            while backend_root.name != "Backend" and backend_root.parent != backend_root:
                backend_root = backend_root.parent
            
            print(f"Backend root found: {backend_root}")
            
            # Construct path like in openid_endpoint.py
            jwks_path1 = backend_root / "Api_Layer" / "JWT" / "token_creation" / "jwks.json"
            print(f"Strategy 1 - Path: {jwks_path1}")
            
            if jwks_path1.exists():
                self.jwks_path = jwks_path1
                print(f"✅ JWKS file found using strategy 1: {self.jwks_path}")
                return
                
        except Exception as e:
            print(f"Strategy 1 failed: {e}")
        
        # Strategy 2: Search for jwks.json files
        try:
            print("Strategy 2: Searching for jwks.json files...")
            
            # Start from current file and go up to find Backend
            search_root = Path(__file__).resolve().parent
            while search_root.name != "Backend" and search_root.parent != search_root:
                search_root = search_root.parent
                
            print(f"Searching in: {search_root}")
            jwks_files = list(search_root.glob("**/jwks.json"))
            
            print(f"Found {len(jwks_files)} jwks.json files:")
            for jwks_file in jwks_files:
                print(f"  - {jwks_file}")
                
            if jwks_files:
                # Use the first one found
                self.jwks_path = jwks_files[0]
                print(f"✅ JWKS file found using strategy 2: {self.jwks_path}")
                return
                
        except Exception as e:
            print(f"Strategy 2 failed: {e}")
        
        # Strategy 3: Use environment variable or hardcoded path
        try:
            jwks_env_path = os.getenv("JWKS_FILE_PATH")
            if jwks_env_path:
                jwks_path3 = Path(jwks_env_path)
                if jwks_path3.exists():
                    self.jwks_path = jwks_path3
                    print(f"✅ JWKS file found using environment variable: {self.jwks_path}")
                    return
        except Exception as e:
            print(f"Strategy 3 failed: {e}")
        
        # If all strategies fail
        raise FileNotFoundError("❌ Could not find JWKS file using any strategy. Please check file location.")

    def _load_config_from_file(self):
        """Load JWKS configuration directly from file - no HTTP requests needed"""
        with self._config_lock:
            if self._config_loaded:
                return
            
            try:
                print("Loading OIDC configuration from local file...")
                print(f"JWKS file path: {self.jwks_path}")
                
                if not self.jwks_path or not self.jwks_path.exists():
                    raise FileNotFoundError(f"JWKS file not found at: {self.jwks_path}")
                
                # Load JWKS from file
                with open(self.jwks_path, 'r', encoding='utf-8') as f:
                    jwks_data = json.load(f)
                
                print(f"JWKS file loaded, content preview: {str(jwks_data)[:200]}...")
                
                keys = jwks_data.get('keys', [])
                print(f"Found {len(keys)} keys in JWKS file")
                
                if not keys:
                    raise ValueError("No keys found in JWKS file")
                
                # Process each key
                for i, key in enumerate(keys):
                    try:
                        kid = key.get('kid')
                        if not kid:
                            print(f"Warning: Key {i+1} missing 'kid', skipping")
                            continue
                            
                        print(f"Processing key: {kid}")
                        print(f"Key details: kty={key.get('kty')}, alg={key.get('alg')}")
                        
                        # Convert JWK to RSA algorithm
                        rsa_key = algorithms.RSAAlgorithm.from_jwk(key)
                        self.jwks_dict[kid] = rsa_key
                        print(f"✅ Successfully processed key: {kid}")
                        
                    except Exception as key_error:
                        print(f"Failed to process key {i+1} ({kid}): {key_error}")
                        continue
                
                if not self.jwks_dict:
                    raise ValueError("No valid keys could be processed from JWKS file")
                
                self._config_loaded = True
                print(f"✅ OIDC configuration loaded successfully from file!")
                print(f"Available key IDs: {list(self.jwks_dict.keys())}")
                
            except FileNotFoundError as e:
                print(f"❌ JWKS file not found: {e}")
                self._suggest_file_solutions()
                raise
                
            except json.JSONDecodeError as e:
                print(f"❌ Invalid JSON in JWKS file: {e}")
                print(f"File content preview (first 500 chars):")
                try:
                    with open(self.jwks_path, 'r', encoding='utf-8') as f:
                        content = f.read(500)
                        print(content)
                except:
                    print("Could not read file content")
                raise
                
            except Exception as e:
                print(f"❌ Failed to load OIDC configuration from file: {e}")
                print(f"Error type: {type(e).__name__}")
                import traceback
                print(f"Traceback: {traceback.format_exc()}")
                self._suggest_file_solutions()
                raise

    def _suggest_file_solutions(self):
        """Suggest solutions for file-based loading issues"""
        print("\n🔧 File-based troubleshooting:")
        if self.jwks_path:
            print(f"1. Check if JWKS file exists: {self.jwks_path}")
            print(f"2. File exists check: {self.jwks_path.exists() if hasattr(self.jwks_path, 'exists') else 'Path object invalid'}")
        print("3. Ensure the file contains valid JSON with 'keys' array")
        print("4. Check file permissions for read access")
        print("5. Set environment variable JWKS_FILE_PATH if needed")
        print("6. Verify the JWKS file has the correct structure\n")

    def is_ready(self):
        """Check if configuration is loaded and ready"""
        return self._config_loaded

    def get_signing_key(self, kid: str):
        """Get signing key by key ID"""
        if not self.is_ready():
            raise RuntimeError("OIDC configuration not loaded")
        
        if kid not in self.jwks_dict:
            available_keys = list(self.jwks_dict.keys())
            raise ValueError(f"Key ID '{kid}' not found. Available keys: {available_keys}")
        
        return self.jwks_dict[kid]

# Global validator instance
_oidc_validator: Optional[OIDCValidator] = None
_oidc_lock = threading.Lock()

def get_oidc_validator():
    """
    Get OIDC validator instance - loads configuration from file on first call.
    NO HTTP REQUESTS - eliminates deadlock possibility.
    """
    global _oidc_validator
    
    # Double-checked locking pattern
    if _oidc_validator is not None and _oidc_validator.is_ready():
        return _oidc_validator
    
    with _oidc_lock:
        if _oidc_validator is None:
            print("🔐 Initializing file-based OIDC validator...")
            _oidc_validator = OIDCValidator()
        
        # Load configuration if not already loaded
        if not _oidc_validator.is_ready():
            print("📂 Loading OIDC configuration from local file...")
            _oidc_validator._load_config_from_file()
        
        return _oidc_validator

def reset_oidc_validator():
    """Reset validator - useful for testing or if config needs refresh"""
    global _oidc_validator
    with _oidc_lock:
        _oidc_validator = None
        print("🔄 OIDC validator reset.")

def check_oidc_health():
    """Check if OIDC configuration can be loaded from file"""
    try:
        validator = get_oidc_validator()
        return validator.is_ready()
    except Exception as e:
        print(f"❌ OIDC health check failed: {e}")
        return False

# Debug function
def debug_jwks_search():
    """Debug function to search for JWKS files"""
    print("🔍 Debug: Searching for JWKS files...")
    
    current_file = Path(__file__).resolve()
    print(f"Current file: {current_file}")
    
    # Find Backend root
    backend_root = current_file.parent
    while backend_root.name != "Backend" and backend_root.parent != backend_root:
        backend_root = backend_root.parent
        
    print(f"Backend root: {backend_root}")
    
    # Search for all JWKS files
    jwks_files = list(backend_root.glob("**/jwks.json"))
    print(f"Found {len(jwks_files)} jwks.json files:")
    
    for i, jwks_file in enumerate(jwks_files):
        print(f"  {i+1}. {jwks_file}")
        try:
            with open(jwks_file, 'r', encoding='utf-8') as f:
                content = json.load(f)
                keys = content.get('keys', [])
                print(f"     - Contains {len(keys)} keys")
                for key in keys:
                    kid = key.get('kid', 'unknown')
                    kty = key.get('kty', 'unknown')
                    print(f"       * {kid} ({kty})")
        except Exception as e:
            print(f"     - Error reading file: {e}")
    
    return jwks_files