from __future__ import annotations
import uuid
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel


class ReportConfigSchema(BaseModel):
    audience: str = "technical"
    include_sections: list[str] = ["findings", "evidence", "remediation", "timeline"]
    severity_filter: list[str] = ["critical", "high", "medium", "low"]
    include_poc: bool = True
    include_evidence: bool = True
    custom_executive_summary: Optional[str] = None


class ReportCreateSchema(BaseModel):
    format: str = "html"
    scan_id: Optional[uuid.UUID] = None
    config: Optional[ReportConfigSchema] = None


class ReportJobSchema(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    scan_id: Optional[uuid.UUID]
    format: str
    status: str
    file_path: Optional[str]
    error: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]
    estimated_minutes: int = 2

    model_config = {"from_attributes": True}
