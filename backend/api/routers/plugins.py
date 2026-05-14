from __future__ import annotations
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.database import get_db
from api.deps import get_current_active_user, require_role
from models.user import User
from models.plugin import Plugin
from schemas.plugin import PluginSchema, PluginCreateSchema

router = APIRouter()


@router.get("/plugins", response_model=list[PluginSchema])
async def list_plugins(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Plugin))
    return result.scalars().all()


@router.post("/plugins", response_model=PluginSchema)
async def install_plugin(
    body: PluginCreateSchema,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    existing = await db.execute(select(Plugin).where(Plugin.name == body.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail={"code": "PLUGIN_EXISTS"})

    plugin = Plugin(
        name=body.name,
        version=body.version,
        description=body.description,
        author=body.author,
        code_path=body.code_path,
        manifest=body.manifest or {},
        enabled=False,
        installed_by_id=user.id,
    )
    db.add(plugin)
    await db.commit()
    await db.refresh(plugin)
    return plugin


@router.get("/plugins/{plugin_id}", response_model=PluginSchema)
async def get_plugin(
    plugin_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Plugin).where(Plugin.id == plugin_id))
    plugin = result.scalar_one_or_none()
    if not plugin:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
    return plugin


@router.post("/plugins/{plugin_id}/enable", response_model=PluginSchema)
async def enable_plugin(
    plugin_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    result = await db.execute(select(Plugin).where(Plugin.id == plugin_id))
    plugin = result.scalar_one_or_none()
    if not plugin:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
    plugin.enabled = True
    await db.commit()
    await db.refresh(plugin)
    return plugin


@router.post("/plugins/{plugin_id}/disable", response_model=PluginSchema)
async def disable_plugin(
    plugin_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    result = await db.execute(select(Plugin).where(Plugin.id == plugin_id))
    plugin = result.scalar_one_or_none()
    if not plugin:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
    plugin.enabled = False
    await db.commit()
    await db.refresh(plugin)
    return plugin


@router.delete("/plugins/{plugin_id}", status_code=204)
async def uninstall_plugin(
    plugin_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    result = await db.execute(select(Plugin).where(Plugin.id == plugin_id))
    plugin = result.scalar_one_or_none()
    if not plugin:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
    await db.delete(plugin)
    await db.commit()
