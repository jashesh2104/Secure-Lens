"""Database engine and session setup (synchronous SQLAlchemy 2.0 style).

The DATABASE_URL is read from settings so the same code targets SQLite locally
and Postgres on EC2. The `connect_args` SQLite tweak is the one place we touch
SQLite specifics, and it is a no-op for any other database.
"""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

settings = get_settings()

# SQLite + multithreaded servers (uvicorn) need this flag; for Postgres it's
# omitted because the default driver is already thread-safe.
_connect_args = (
    {"check_same_thread": False, "timeout": 30}
    if settings.database_url.startswith("sqlite")
    else {}
)

engine = create_engine(
    settings.database_url, connect_args=_connect_args, pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Declarative base all ORM models inherit from (added in Step 2)."""


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a DB session and always closes it.

    Using a generator dependency guarantees the session is released back to the
    pool even if the request handler raises.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
