from jwcrypto import jwk
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from sqlalchemy import update, delete
from Backend.Data_Access_Layer.utils.database import set_db_session, remove_db_session
from Backend.Data_Access_Layer.models.jwt import JWTKeys
from Backend.config.env_loader import get_env_var
from Backend.Api_Layer.JWT.token_creation.config import invalidate_jwks_cache
from Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config import reset_oidc_validator


def rotate_jwt_keys():
    """
    Rotates JWT keys securely.
    - Deletes expired keys
    - Deactivates old ones
    - Creates and stores a new encrypted key pair
    - Invalidates all caches so new key is picked up immediately
    """
    db = set_db_session()
    try:
        fernet_key = get_env_var("FERNET_SECRET_KEY")
        fernet = Fernet(fernet_key)

        # Delete expired keys
        deleted_result = db.execute(
            delete(JWTKeys).where(JWTKeys.expires_at < datetime.utcnow())
        )
        deleted_count = deleted_result.rowcount or 0
        print(f"🗑️ Deleted {deleted_count} expired keys.")

        # Deactivate old keys
        db.execute(update(JWTKeys).values(is_active=False))

        # Generate new RSA pair
        key = jwk.JWK.generate(kty="RSA", size=2048)
        kid = f"key-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        private_pem = key.export_to_pem(private_key=True, password=None).decode()
        public_pem = key.export_to_pem().decode()

        # Encrypt before saving
        encrypted_private = fernet.encrypt(private_pem.encode()).decode()
        encrypted_public = fernet.encrypt(public_pem.encode()).decode()

        new_key = JWTKeys(
            kid=kid,
            private_key=encrypted_private,
            public_key=encrypted_public,
            algorithm="RS256",
            is_active=True,
            expires_at=datetime.utcnow() + timedelta(days=3),
        )
        db.add(new_key)
        db.commit()
        print(f"✅ New key generated and inserted: {kid}")

        # ✅ Invalidate all caches so new key is picked up immediately
        invalidate_jwks_cache()  # clears JWKS endpoint cache
        reset_oidc_validator()  # clears internal validation cache

    except Exception as e:
        db.rollback()
        print(f"❌ Error rotating keys: {e}")
    finally:
        remove_db_session()
