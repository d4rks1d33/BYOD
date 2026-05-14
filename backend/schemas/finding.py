from __future__ import annotations
import uuid
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel


class FindingSummarySchema(BaseModel):
    id: uuid.UUID
    title: str
    finding_type: str
    severity: str
    status: str
    endpoint: Optional[str]
    tool: Optional[str]
    cvss_score: Optional[float]
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingSchema(FindingSummarySchema):
    project_id: uuid.UUID
    scan_id: Optional[uuid.UUID]
    description: str
    http_method: Optional[str]
    parameter: Optional[str]
    cwe_id: Optional[str]
    cvss_vector: Optional[str]
    confidence: float


class FindingDetailSchema(FindingSchema):
    payload: Optional[str]
    remediation: Optional[str]
    poc_code: Optional[str]
    reproduction_steps: list[Any]
    notes: Optional[str]
    verified_at: Optional[datetime]
    correlated_finding_id: Optional[uuid.UUID]


class FindingUpdateSchema(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None


class FindingFilterSchema(BaseModel):
    severity: Optional[list[str]] = None
    type: Optional[list[str]] = None
    status: Optional[list[str]] = None
    scan_id: Optional[uuid.UUID] = None
    cwe: Optional[str] = None
    cvss_min: Optional[float] = None
    page: int = 1
    limit: int = 50
    sort: str = "severity_desc"
