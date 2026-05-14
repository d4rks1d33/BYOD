from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy import update
import redis.asyncio as aioredis

from core.database import get_db
from core.redis import get_redis
from api.deps import get_current_active_user, get_project_or_404
from models.user import User
from models.scan import Scan, ScanCheckpoint
from models.finding import Finding
from schemas.scan import ScanCreateSchema, ScanSchema, ScanDetailSchema, ScanProgressSchema
from schemas.common import PaginatedResponse

router = APIRouter()


@router.post("/projects/{project_id}/scans", response_model=ScanSchema, status_code=202)
async def create_scan(
    project_id: uuid.UUID,
    body: ScanCreateSchema,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
    redis: aioredis.Redis = Depends(get_redis),
):
    project = await get_project_or_404(project_id, db, user)

    # Check concurrent scan limit
    from core.config import get_settings
    settings = get_settings()
    running_count = await db.execute(
        select(func.count(Scan.id)).where(Scan.status == "running")
    )
    if running_count.scalar_one() >= settings.MAX_CONCURRENT_SCANS:
        raise HTTPException(status_code=409, detail={"code": "MAX_SCANS_REACHED", "message": "Maximum concurrent scans reached"})

    config = body.config.model_dump() if body.config else {}
    config.setdefault("target_url", project.target_url)
    config.setdefault("scope_urls", project.scope_urls)

    scan = Scan(
        id=uuid.uuid4(),
        project_id=project_id,
        scan_type=body.scan_type,
        status="queued",
        config=config,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Enqueue Celery task
    from workers.tasks.scan_tasks import run_full_scan
    task = run_full_scan.apply_async(args=[str(scan.id)], queue="dast")

    from sqlalchemy import update
    await db.execute(update(Scan).where(Scan.id == scan.id).values(celery_task_id=task.id))
    await db.commit()

    # Initialize scan state in Redis
    await redis.hset(f"scan:state:{scan.id}", mapping={
        "status": "queued",
        "current_phase": "initializing",
        "phase_progress_pct": "0",
        "overall_progress_pct": "0",
    })

    return scan


@router.get("/projects/{project_id}/scans", response_model=PaginatedResponse[ScanSchema])
async def list_scans(
    project_id: uuid.UUID,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    await get_project_or_404(project_id, db, user)
    offset = (page - 1) * limit

    filters = [Scan.project_id == project_id]
    if status:
        filters.append(Scan.status == status)

    result = await db.execute(
        select(Scan).where(*filters).offset(offset).limit(limit).order_by(Scan.created_at.desc())
    )
    scans = result.scalars().all()

    count_result = await db.execute(select(func.count(Scan.id)).where(*filters))
    total = count_result.scalar_one()

    return PaginatedResponse(items=list(scans), total=total, page=page, limit=limit)


@router.get("/scans/{scan_id}", response_model=ScanDetailSchema)
async def get_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND"})

    await get_project_or_404(scan.project_id, db, user)

    cp_result = await db.execute(
        select(ScanCheckpoint).where(ScanCheckpoint.scan_id == scan_id).order_by(ScanCheckpoint.saved_at)
    )
    checkpoints = [{"phase": cp.phase, "saved_at": cp.saved_at.isoformat()} for cp in cp_result.scalars().all()]

    # findings summary
    summary = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        cnt = await db.execute(select(func.count(Finding.id)).where(Finding.scan_id == scan_id, Finding.severity == sev))
        c = cnt.scalar_one()
        if c > 0:
            summary.append({"severity": sev, "count": c})

    return ScanDetailSchema(
        **ScanSchema.model_validate(scan).model_dump(),
        checkpoints=checkpoints,
        findings_summary=summary,
    )


@router.get("/scans/{scan_id}/progress", response_model=ScanProgressSchema)
async def get_scan_progress(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
    redis: aioredis.Redis = Depends(get_redis),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND"})
    await get_project_or_404(scan.project_id, db, user)

    state = await redis.hgetall(f"scan:state:{scan_id}") or {}

    return ScanProgressSchema(
        status=state.get("status", scan.status.value),
        current_phase=state.get("current_phase"),
        phase_progress_pct=int(state.get("phase_progress_pct", 0)),
        overall_progress_pct=int(state.get("overall_progress_pct", 0)),
        stats=scan.statistics or {},
        active_agents=[],
    )


@router.get("/scans/{scan_id}/logs")
async def get_scan_logs(
    scan_id: uuid.UUID,
    limit: int = Query(500, ge=1, le=5000),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
    redis: aioredis.Redis = Depends(get_redis),
):
    """Get persisted scan logs from Redis stream."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND"})
    await get_project_or_404(scan.project_id, db, user)

    log_key = f"scan:log:{scan_id}"
    try:
        # Read from Redis stream
        entries = await redis.xrange(log_key, count=limit)
    except Exception as e:
        return {"logs": [], "error": str(e)}

    logs = []
    for entry_id, fields in entries:
        log_entry = {}
        for k, v in fields.items():
            k_str = k.decode() if isinstance(k, bytes) else k
            v_str = v.decode() if isinstance(v, bytes) else v
            log_entry[k_str] = v_str
        log_entry["id"] = entry_id.decode() if isinstance(entry_id, bytes) else entry_id
        logs.append(log_entry)

    return {"logs": logs, "total": len(logs)}


@router.post("/scans/{scan_id}/pause", status_code=202)
async def pause_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
    redis: aioredis.Redis = Depends(get_redis),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan or scan.status.value != "running":
        raise HTTPException(status_code=409, detail={"code": "SCAN_NOT_RUNNING"})
    await get_project_or_404(scan.project_id, db, user)

    await redis.set(f"scan:control:{scan_id}", "pause", ex=3600)
    return {"message": "Pause signal sent. Scan will pause at next checkpoint."}


@router.post("/scans/{scan_id}/resume", status_code=202)
async def resume_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
    redis: aioredis.Redis = Depends(get_redis),
):
    from sqlalchemy import update
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan or scan.status.value != "paused":
        raise HTTPException(status_code=409, detail={"code": "SCAN_NOT_PAUSED"})
    await get_project_or_404(scan.project_id, db, user)

    await redis.delete(f"scan:control:{scan_id}")
    await db.execute(update(Scan).where(Scan.id == scan_id).values(status="running"))
    await db.commit()

    from workers.tasks.scan_tasks import run_full_scan
    run_full_scan.apply_async(args=[str(scan_id)], queue="dast")
    return {"message": "Scan resumed from checkpoint."}


@router.post("/scans/{scan_id}/cancel", status_code=202)
async def cancel_scan(
    scan_id: uuid.UUID,
    body: Optional[dict] = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
    redis: aioredis.Redis = Depends(get_redis),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND"})
    await get_project_or_404(scan.project_id, db, user)
    await db.execute(update(Scan).where(Scan.id == scan_id).values(status="cancelled"))
    await db.commit()
    await redis.set(f"scan:control:{scan_id}", "cancel", ex=3600)
    await redis.hset(f"scan:state:{scan_id}", "status", "cancelled")
    if scan.celery_task_id:
        celery_app.control.revoke(scan.celery_task_id, terminate=True, signal='SIGKILL')

    return {"message": "Scan cancelled immediately."}
