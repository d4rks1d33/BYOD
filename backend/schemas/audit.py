from __future__ import annotations
import uuid
from datetime import datetime
from typing import Optional, Any

from pydantic import BaseModel, ConfigDict


class AuditLogSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    actor_id: Optional[uuid.UUID]
    action: str
    resource_type: str
    resource_id: str
    detail: Optional[Any]
    ip_address: Optional[str]
    created_at: datetime
    hash: str
