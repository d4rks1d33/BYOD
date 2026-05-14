from __future__ import annotations
import uuid
from typing import Optional
from sqlalchemy import String, Boolean, Float, Integer
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from core.database import Base
from .base import TimestampMixin
from .enums import AIProviderEnum


class AIModelConfig(Base, TimestampMixin):
    __tablename__ = "ai_model_configs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[AIProviderEnum] = mapped_column(default=AIProviderEnum.llamacpp)
    model_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    ollama_host: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    vllm_base_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    api_key_encrypted: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    avg_inference_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    total_inferences: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
