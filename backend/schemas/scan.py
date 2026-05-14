from __future__ import annotations
import uuid
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel


class ScanConfigSchema(BaseModel):
    intensity: str = "balanced"
    requests_per_second: int = 10
    total_timeout_minutes: int = 120
    tools: list[str] = ["nuclei", "ffuf", "katana"]
    vuln_types: Optional[list[str]] = None
    ai_model_id: Optional[uuid.UUID] = None
    wordlists: Optional[list[str]] = None


class ScanCreateSchema(BaseModel):
    scan_type: str = "full"
    config: Optional[ScanConfigSchema] = None


class ScanSchema(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    scan_type: str
    status: str
    config: dict[str, Any]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error: Optional[str]
    celery_task_id: Optional[str]
    statistics: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanDetailSchema(ScanSchema):
    checkpoints: list[dict[str, Any]] = []
    findings_summary: list[dict[str, Any]] = []


class AgentStatusSchema(BaseModel):
    agent: str
    status: str
    task: Optional[str]
    progress: int


class ScanProgressSchema(BaseModel):
    status: str
    current_phase: Optional[str]
    phase_progress_pct: int
    overall_progress_pct: int
    stats: dict[str, Any]
    active_agents: list[AgentStatusSchema]
