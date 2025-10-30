from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker,Session
from ...config.env_loader import get_env_var
from contextvars import ContextVar
from urllib.parse import quote_plus

# Your existing values
DB_USER = get_env_var("DB_USER")
DB_PASSWORD = get_env_var("DB_PASSWORD")
DB_HOST = get_env_var("DB_HOST")
DB_PORT = get_env_var("DB_PORT")
DB_NAME = get_env_var("DB_NAME")
DB_DRIVER = get_env_var("DB_DRIVER")
encoded_password = quote_plus(DB_PASSWORD)

DB_URL = f"{DB_DRIVER}://{DB_USER}:{encoded_password}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
engine = create_engine(
    DB_URL,
    pool_pre_ping=True,
    pool_size=10,          # increase baseline pool
    max_overflow=20,       # allow bursts
    pool_timeout=30,       # seconds to wait before raising
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ✅ Context variable for session
_db_context: ContextVar[Session] = ContextVar("db_session", default=None)

def set_db_session() -> Session:
    db = SessionLocal()
    _db_context.set(db)
    return db

def get_db_session() -> Session:
    db = _db_context.get()
    if db is None:
        raise RuntimeError("DB session not found in context")
    return db

def remove_db_session():
    db = _db_context.get()
    if db:
        db.close()
        _db_context.set(None)
