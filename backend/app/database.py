# =============================================================================
# HexShield AI — Database Connection
# Establishes the SQLAlchemy engine, session factory, and base model class.
# All database interactions in the application go through this module.
# =============================================================================

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.pool import QueuePool
import logging

from app.config import settings

logger = logging.getLogger(__name__)


# =============================================================================
# SQLAlchemy Engine
# =============================================================================

engine = create_engine(
    settings.DATABASE_URL,
    poolclass=QueuePool,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_pre_ping=True,
    # pool_pre_ping=True verifies the connection is alive before using it.
    # Critical for Neon serverless which may suspend idle connections.
    echo=settings.DATABASE_ECHO,
    connect_args={
        "sslmode": "prefer",
        "connect_timeout": 40,
    },
)


# =============================================================================
# Session Factory
# =============================================================================

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    # expire_on_commit=False prevents SQLAlchemy from expiring objects after
    # commit, which would cause DetachedInstanceError in async contexts.
)


# =============================================================================
# Declarative Base
# All SQLAlchemy ORM models inherit from this class.
# =============================================================================

class Base(DeclarativeBase):
    pass


# =============================================================================
# Dependency — FastAPI Database Session
# Used with FastAPI's Depends() to provide a database session per request.
# Guarantees the session is always closed after the request completes.
# =============================================================================

def get_db():
    """
    FastAPI dependency that provides a database session.

    Usage in a router:
        from fastapi import Depends
        from app.database import get_db
        from sqlalchemy.orm import Session

        @router.get("/example")
        def example(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# =============================================================================
# Connection Health Check
# =============================================================================

def verify_database_connection() -> bool:
    """
    Verifies the database connection is alive and reachable.
    Called at application startup. Returns True if successful.
    """
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        logger.info("Database connection verified successfully.")
        return True
    except Exception as e:
        logger.critical(f"Database connection failed: {e}")
        return False