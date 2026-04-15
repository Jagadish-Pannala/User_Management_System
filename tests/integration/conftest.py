"""
tests/integration/conftest.py
"""

import os

from Backend.config.env_loader import get_env_var



import pytest
import pytest_asyncio
import uuid
from httpx import AsyncClient
from sqlalchemy import create_engine, true, text
from sqlalchemy.orm import sessionmaker

# TEST_DATABASE_URL = "mysql+mysqlconnector://root:1234@localhost:3306/user_management"
# # os.environ["TEST_DATABASE_URL"] = TEST_DATABASE_URL

from Backend.main import app
from Backend.Business_Layer.utils.generate_uuid7 import generate_uuid7
from Backend.Business_Layer.utils.password_utils import hash_password
from Backend.Data_Access_Layer.models import models
from Backend.Data_Access_Layer.utils.database import Base
from Backend.Data_Access_Layer.utils.dependency import get_db

# TEST_DATABASE_URL = "mysql+mysqlconnector://root:1234@localhost:3306/user_management"
TEST_USER=get_env_var("TEST_USER")
TEST_PASSWORD=get_env_var("TEST_PASSWORD")
TEST_HOST=get_env_var("TEST_HOST")
TEST_PORT=get_env_var("TEST_PORT")
TEST_DB_NAME=get_env_var("TEST_DB_NAME")
TEST_DB_DRIVER=get_env_var("TEST_DB_DRIVER")

TEST_DATABASE_URL = f"{TEST_DB_DRIVER}://{TEST_USER}:{TEST_PASSWORD}@{TEST_HOST}:{TEST_PORT}/{TEST_DB_NAME}"

# ── DB engine ─────────────────────────────────

@pytest.fixture(scope="session")
def test_engine():
    engine = create_engine(TEST_DATABASE_URL)

    Base.metadata.create_all(engine)

    # Clear all tables to ensure clean state
    with engine.begin() as conn:
        conn.execute(text("SET FOREIGN_KEY_CHECKS = 0;"))
        for table in Base.metadata.sorted_tables:
            conn.execute(text(f"TRUNCATE TABLE {table.name};"))
        conn.execute(text("SET FOREIGN_KEY_CHECKS = 1;"))

    yield engine

    Base.metadata.drop_all(engine)


# ── DB session per test ───────────────────────

@pytest.fixture
def db_session(test_engine):
    Session = sessionmaker(bind=test_engine)

    session = Session()

    yield session

    session.rollback()
    session.close()


# ── FastAPI Async Client ──────────────────────

@pytest_asyncio.fixture
async def client(db_session):

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(app=app, base_url="http://127.0.0.1:8000") as client:
        yield client

    app.dependency_overrides.clear()


# ── Test User Fixtures ────────────────────────

@pytest.fixture
def existing_user(db_session):

    unique_id = uuid.uuid4()

    user = models.User(
        user_uuid=str(unique_id),
        first_name="John",
        last_name="Doe",
        mail=f"user_{unique_id}@example.com",
        contact=str(9000000000 + int(unique_id.int % 999999999)),
        password=hash_password("Paves@123"),
        is_active=True,
        gender="male",
    )

    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    return {
        "user_id": user.user_id,
        "user_uuid": user.user_uuid,
        "mail": user.mail,
        "password": "Paves@123"
    }


@pytest_asyncio.fixture
async def auth_token(client, db_session):
    admin_email = "super.admin@example.com"
    admin_password = "SuperAdmin@123"

    admin_user = db_session.query(models.User).filter_by(mail=admin_email).first()
    if not admin_user:
        super_admin_role = (
            db_session.query(models.Role).filter_by(role_name="Super Admin").first()
        )
        if not super_admin_role:
            super_admin_role = models.Role(
                role_uuid=generate_uuid7(),
                role_name="Super Admin",
            )
            db_session.add(super_admin_role)
            db_session.commit()
            db_session.refresh(super_admin_role)

        admin_user = models.User(
            user_uuid=generate_uuid7(),
            first_name="Super",
            last_name="Admin",
            mail=admin_email,
            contact="9999999999",
            password=hash_password(admin_password),
            is_active=True,
        )
        db_session.add(admin_user)
        db_session.commit()
        db_session.refresh(admin_user)

        db_session.add(
            models.User_Role(
                user_id=admin_user.user_id,
                role_id=super_admin_role.role_id,
                assigned_by=None,
            )
        )
        db_session.commit()

        # Ensure General role exists
        general_role = db_session.query(models.Role).filter_by(role_name="General").first()
        if not general_role:
            general_role = models.Role(
                role_uuid=generate_uuid7(),
                role_name="General",
            )
            db_session.add(general_role)
            db_session.commit()
            db_session.refresh(general_role)

    response = await client.post(
        "/auth/login",
        json={
            "email": admin_email,
            "password": admin_password
        }
    )

    return response.json()["access_token"]


@pytest_asyncio.fixture
async def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}