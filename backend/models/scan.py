from __future__ import annotations
import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Text, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from core.database import Base
from .base import TimestampMixin
from .enums import ScanTypeEnum, ScanStatusEnum


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False, index=True)
    scan_type: Mapped[ScanTypeEnum] = mapped_column(default=ScanTypeEnum.full)
    status: Mapped[ScanStatusEnum] = mapped_column(default=ScanStatusEnum.queued, index=True)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    statistics: Mapped[dict] = mapped_column(JSONB, default=dict)

    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")
    checkpoints = relationship("ScanCheckpoint", back_populates="scan", cascade="all, delete-orphan")
    evidence = relationship("Evidence", back_populates="scan")
    report_jobs = relationship("ReportJob", back_populates="scan")


class ScanCheckpoint(Base):
    __tablename__ = "scan_checkpoints"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    phase: Mapped[str] = mapped_column(String(100), nullable=False)
    context_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    saved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    scan = relationship("Scan", back_populates="checkpoints")
