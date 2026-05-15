from __future__ import annotations
import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import context

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import all models so autogenerate can find them
from core.database import Base  # noqa: F401
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

target_metadata = Base.metadata


def get_url() -> str:
    from core.config import get_settings
    return get_settings().DATABASE_URL


def run_migrations_offline() -> None:
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    engine = create_async_engine(get_url(), poolclass=pool.NullPool)
    async with engine.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await engine.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
