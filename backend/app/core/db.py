"""Database engine, session factory, and declarative base.

Supports PostgreSQL (production) and SQLite (dev/test) from the same models.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings


class Base(DeclarativeBase):
    pass


def _make_engine():
    url = settings.database_url
    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
        if url.endswith("://"):
            # In-memory: one shared connection for the whole process (tests).
            return create_engine(
                url,
                connect_args=connect_args,
                poolclass=StaticPool,
                future=True,
            )
        return create_engine(url, connect_args=connect_args, future=True)
    return create_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=20, future=True)


engine = _make_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for non-request code (workers, CLI, bootstrap)."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def create_all() -> None:
    """Create tables directly (used for SQLite dev/test and as a prod fallback)."""
    # Import models so they register on Base.metadata.
    import app.models  # noqa: F401

    Base.metadata.create_all(bind=engine)
