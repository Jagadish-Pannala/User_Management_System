from datetime import datetime, timezone
from sqlalchemy import and_
from ....Data_Access_Layer.utils.database import get_db_session
from ....Data_Access_Layer.models.jwt import JWTKeys


ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour


def get_jwt_keys():
    """
    Fetch the active (non-expired) JWT keys from the database.
    Returns (private_key, public_key)
    """
    session = get_db_session()
    now = datetime.now(timezone.utc)

    jwt_key = (
        session.query(JWTKeys)
        .filter(
            and_(
                JWTKeys.is_active == 1,
                JWTKeys.expires_at > now
            )
        )
        .first()
    )

    if not jwt_key:
        raise Exception("❌ No active JWT keys found in the database.")

    print(f"✅ Active JWT key found (KID={jwt_key.kid}) valid until {jwt_key.expires_at}")

    return jwt_key.private_key, jwt_key.public_key, jwt_key.algorithm, jwt_key.kid
