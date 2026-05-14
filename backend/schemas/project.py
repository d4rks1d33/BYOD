from __future__ import annotations
import uuid
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, HttpUrl


class AuthConfigSchema(BaseModel):
    auth_type: str = "none"
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    oauth_client_id: Optional[str] = None
    oauth_client_secret: Optional[str] = None
    oauth_token_url: Optional[str] = None
    totp_secret: Optional[str] = None
    har_file_path: Optional[str] = None
    custom_headers: Optional[dict[str, str]] = None


class ScanDefaultsSchema(BaseModel):
    intensity: str = "balanced"
    requests_per_second: int = 10
    total_timeout_minutes: int = 120
    tools: list[str] = ["nuclei", "ffuf", "katana"]


class ProjectConfigSchema(BaseModel):
    auth: Optional[AuthConfigSchema] = None
    scan_defaults: Optional[ScanDefaultsSchema] = None
    environment: str = "staging"


class ProjectCreateSchema(BaseModel):
    name: str
    description: Optional[str] = None
    target_url: str
    target_type: str = "web_application"
    scope_urls: list[str] = []
    exclude_patterns: list[str] = []
    config: Optional[ProjectConfigSchema] = None


class ProjectUpdateSchema(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    scope_urls: Optional[list[str]] = None
    exclude_patterns: Optional[list[str]] = None
    config: Optional[ProjectConfigSchema] = None


class ProjectSchema(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str]
    target_url: str
    target_type: str
    scope_urls: list[str]
    exclude_patterns: list[str]
    config: dict[str, Any]
    owner_id: uuid.UUID
    archived_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ProjectMemberSchema(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    user_id: uuid.UUID
    role: str

    model_config = {"from_attributes": True}


class ProjectStatsSchema(BaseModel):
    total_findings: int
    findings_by_severity: dict[str, int]
    verified_findings: int
    false_positives: int
    total_scans: int
    last_scan_duration_ms: Optional[int]
    attack_surface_endpoints: int
    coverage_pct: float
