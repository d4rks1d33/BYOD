from __future__ import annotations
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from core.database import get_db
from api.deps import get_current_active_user, require_role
from models.user import User
from models.ai_model_config import AIModelConfig
from schemas.ai_model import AIModelConfigSchema, AIModelCreateSchema, AIModelUpdateSchema

router = APIRouter()


@router.get("/ai-models", response_model=list[AIModelConfigSchema])
async def list_ai_models(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    result = await db.execute(select(AIModelConfig))
    return result.scalars().all()


@router.post("/ai-models", response_model=AIModelConfigSchema)
async def create_ai_model(
    body: AIModelCreateSchema,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    payload = body.model_dump()
    api_key = payload.pop("api_key", None)
    gguf_path = payload.pop("gguf_path", None)

    config_dict = payload.pop("config", None) or {}
    if gguf_path:
        config_dict["gguf_path"] = gguf_path
    payload["config"] = config_dict

    config = AIModelConfig(**payload)
    if api_key:
        # TODO: encrypt using Fernet from cryptography
        config.api_key_encrypted = api_key

    db.add(config)
    await db.commit()
    await db.refresh(config)
    return config


@router.get("/ai-models/{model_id}", response_model=AIModelConfigSchema)
async def get_ai_model(
    model_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    result = await db.execute(select(AIModelConfig).where(AIModelConfig.id == model_id))
    config = result.scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
    return config


@router.patch("/ai-models/{model_id}", response_model=AIModelConfigSchema)
async def update_ai_model(
    model_id: uuid.UUID,
    body: AIModelUpdateSchema,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    result = await db.execute(select(AIModelConfig).where(AIModelConfig.id == model_id))
    config = result.scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})

    updates = body.model_dump(exclude_unset=True)
    api_key = updates.pop("api_key", None)
    gguf_path = updates.pop("gguf_path", None)

    if api_key is not None:
        # TODO: encrypt with Fernet
        config.api_key_encrypted = api_key if api_key else None

    if gguf_path is not None:
        current_config = dict(config.config or {})
        current_config["gguf_path"] = gguf_path
        config.config = current_config

    for field, value in updates.items():
        setattr(config, field, value)

    await db.commit()
    await db.refresh(config)
    return config


@router.post("/ai-models/{model_id}/activate", response_model=AIModelConfigSchema)
async def activate_ai_model(
    model_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    result = await db.execute(select(AIModelConfig).where(AIModelConfig.id == model_id))
    config = result.scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})

    # Mutual exclusivity: deactivate all, then activate this one
    await db.execute(update(AIModelConfig).values(is_default=False, is_active=False))
    config.is_default = True
    config.is_active = True
    await db.commit()
    await db.refresh(config)
    return config


@router.delete("/ai-models/{model_id}", status_code=204)
async def delete_ai_model(
    model_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    result = await db.execute(select(AIModelConfig).where(AIModelConfig.id == model_id))
    config = result.scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
    await db.delete(config)
    await db.commit()
