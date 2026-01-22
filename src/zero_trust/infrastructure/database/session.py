"""
Database session management.

Provides async database session handling using SQLAlchemy 2.0 patterns.
"""

from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from zero_trust.config import Settings, get_settings

# Global engine and session factory (initialized lazily)
_engine = None
_session_factory = None


def get_engine(settings: Settings | None = None):
    """Get or create the database engine."""
    global _engine

    if _engine is None:
        settings = settings or get_settings()
        _engine = create_async_engine(
            settings.database.url.get_secret_value(),
            pool_size=settings.database.pool_size,
            max_overflow=settings.database.max_overflow,
            echo=settings.database.echo,
        )

    return _engine


def get_session_factory(settings: Settings | None = None) -> async_sessionmaker[AsyncSession]:
    """Get or create the session factory."""
    global _session_factory

    if _session_factory is None:
        engine = get_engine(settings)
        _session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )

    return _session_factory


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides a database session.

    Usage:
        @app.get("/items")
        async def get_items(db: DatabaseSession):
            result = await db.execute(select(Item))
            return result.scalars().all()
    """
    session_factory = get_session_factory()
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# Type alias for dependency injection
DatabaseSession = Annotated[AsyncSession, Depends(get_db_session)]


async def init_db(settings: Settings | None = None) -> None:
    """
    Initialize database - create all tables.

    Should be called during application startup in development,
    or use Alembic migrations in production.
    """
    from zero_trust.infrastructure.database.models import Base

    engine = get_engine(settings)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Close database connections."""
    global _engine, _session_factory

    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
