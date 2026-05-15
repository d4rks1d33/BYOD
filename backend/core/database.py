from __future__ import annotations
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text
from .config import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_session_factory = None


def _get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.DATABASE_URL,
            pool_size=20,
            max_overflow=40,
            echo=settings.ENVIRONMENT == "development",
            pool_pre_ping=True,
        )
    return _engine


def _get_session_factory():
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=_get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    factory = _get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Initialize database: extensions + create tables from models."""
    engine = _get_engine()

    # Step 1: Create required extensions
    async with engine.begin() as conn:
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        await conn.execute(text('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"'))

    # Step 2: Import all models so SQLAlchemy knows about them
    # (importing here to avoid circular imports)
    from models.user import User  # noqa: F401
    from models.project import Project, ProjectMember  # noqa: F401
    from models.scan import Scan, ScanCheckpoint  # noqa: F401
    from models.finding import Finding  # noqa: F401
    from models.evidence import Evidence  # noqa: F401
    from models.audit_log import AuditLog  # noqa: F401
    from models.ai_model_config import AIModelConfig  # noqa: F401
    from models.plugin import Plugin  # noqa: F401
    from models.report_job import ReportJob  # noqa: F401
    from models.api_token import APIToken  # noqa: F401

    # Step 3: Create all tables (idempotent - won't fail if exists)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Step 4: Seed default admin user if no users exist
    await _seed_default_admin()


async def _seed_default_admin() -> None:
    """Create default admin user if no users exist."""
    import logging
    logger = logging.getLogger(__name__)

    try:
        from sqlalchemy import select
        from models.user import User
        from core.security import hash_password

        factory = _get_session_factory()
        async with factory() as session:
            result = await session.execute(select(User).limit(1))
            if result.scalar_one_or_none() is None:
                # No users exist - create default admin
                import uuid
                admin = User(
                    id=uuid.uuid4(),
                    email="admin@example.com",
                    full_name="Admin",
                    hashed_password=hash_password("admin123"),
                    role="admin",
                    is_active=True,
                )
                session.add(admin)
                await session.commit()
                logger.info("Created default admin: admin@example.com / admin123")
            else:
                logger.debug("Users exist - skipping default admin seed")
    except Exception as e:
        logger.error(f"Failed to seed default admin: {e}", exc_info=True)


async def close_db() -> None:
    global _engine
    if _engine:
        await _engine.dispose()
        _engine = None
