from __future__ import annotations
import uuid
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel


class EvidenceSchema(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    scan_id: uuid.UUID
    evidence_type: str
    http_request: Optional[str]
    http_response: Optional[str]
    payload: Optional[str]
    screenshot_path: Optional[str]
    tool_output: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class ReplayRequestSchema(BaseModel):
    modified_headers: Optional[dict[str, str]] = None
    modified_body: Optional[str] = None
    modified_params: Optional[dict[str, str]] = None


class ReplayResponseSchema(BaseModel):
    status_code: int
    response_headers: dict[str, Any]
    response_body: str
    elapsed_ms: int
