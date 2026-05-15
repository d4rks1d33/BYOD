from __future__ import annotations
import uuid
from typing import Optional, Any

from pydantic import BaseModel, ConfigDict


class PluginSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    version: str
    description: str
    author: str
    code_path: str
    manifest: Optional[Any]
    enabled: bool


class PluginCreateSchema(BaseModel):
    name: str
    version: str
    description: str = ""
    author: str = ""
    code_path: str
    manifest: Optional[Any] = None
