from __future__ import annotations
import uuid
from typing import Optional, Any

from pydantic import BaseModel, ConfigDict, model_validator


class AIModelConfigSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: uuid.UUID
    name: str
    provider: str
    model_ref: str
    ollama_host: Optional[str] = None
    vllm_base_url: Optional[str] = None
    is_active: bool
    is_default: bool
    avg_inference_ms: Optional[float] = None
    total_inferences: int
    config: Optional[Any] = None
    has_api_key: bool = False

    @model_validator(mode="before")
    @classmethod
    def _compute_has_api_key(cls, data: Any) -> Any:
        # When loading from ORM (AIModelConfig instance)
        if hasattr(data, "api_key_encrypted"):
            has_key = bool(getattr(data, "api_key_encrypted", None))
            try:
                # Build dict representation
                return {
                    "id": data.id,
                    "name": data.name,
                    "provider": data.provider.value if hasattr(data.provider, "value") else str(data.provider),
                    "model_ref": data.model_ref,
                    "ollama_host": data.ollama_host,
                    "vllm_base_url": data.vllm_base_url,
                    "is_active": data.is_active,
                    "is_default": data.is_default,
                    "avg_inference_ms": data.avg_inference_ms,
                    "total_inferences": data.total_inferences,
                    "config": data.config,
                    "has_api_key": has_key,
                }
            except Exception:
                return data
        return data


class AIModelCreateSchema(BaseModel):
    name: str
    provider: str = "gemini"  # gemini | openai | anthropic | ollama | vllm | llamacpp | openrouter
    model_ref: str
    ollama_host: Optional[str] = None
    vllm_base_url: Optional[str] = None
    api_key: Optional[str] = None  # Will be stored; never returned via API
    gguf_path: Optional[str] = None  # For llamacpp local .gguf models
    config: Optional[Any] = None


class AIModelUpdateSchema(BaseModel):
    name: Optional[str] = None
    model_ref: Optional[str] = None
    ollama_host: Optional[str] = None
    vllm_base_url: Optional[str] = None
    api_key: Optional[str] = None
    gguf_path: Optional[str] = None
    config: Optional[Any] = None
