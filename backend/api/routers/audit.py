from __future__ import annotations
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from core.database import get_db
from api.deps import get_current_active_user, require_role
from models.user import User
from models.audit_log import AuditLog
from schemas.audit import AuditLogSchema
from schemas.common import PaginatedResponse

router = APIRouter()


@router.get("/audit/logs", response_model=PaginatedResponse[AuditLogSchema])
async def list_audit_logs(
    resource_type: Optional[str] = None,
    resource_id: Optional[uuid.UUID] = None,
    actor_id: Optional[uuid.UUID] = None,
    action: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "analyst")),
):
    filters = []
    if resource_type:
        filters.append(AuditLog.resource_type == resource_type)
    if resource_id:
        filters.append(AuditLog.resource_id == str(resource_id))
    if actor_id:
        filters.append(AuditLog.actor_id == actor_id)
    if action:
        filters.append(AuditLog.action == action)

    query = select(AuditLog).order_by(AuditLog.created_at.desc())
    if filters:
        query = query.where(*filters)
    query = query.offset((page - 1) * limit).limit(limit)

    result = await db.execute(query)
    logs = result.scalars().all()

    count_query = select(func.count(AuditLog.id))
    if filters:
        count_query = count_query.where(*filters)
    count_result = await db.execute(count_query)
    total = count_result.scalar_one()

    return PaginatedResponse(items=list(logs), total=total, page=page, limit=limit)
