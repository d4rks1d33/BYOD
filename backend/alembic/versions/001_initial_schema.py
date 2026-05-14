"""Initial schema - uses SQLAlchemy models directly

Revision ID: 001
Revises:
Create Date: 2026-05-13 00:00:00.000000

This migration creates all tables from the SQLAlchemy models defined in /app/models.
This approach guarantees the schema always matches the current models, eliminating
drift between manually-written migrations and model definitions.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Enable required extensions
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    # Import all models so SQLAlchemy registers them
    import sys
    import os
    sys.path.insert(0, "/app")

    from core.database import Base
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

    # Create all tables matching the model definitions
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind, checkfirst=True)


def downgrade() -> None:
    import sys
    sys.path.insert(0, "/app")

    from core.database import Base
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

    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
