from __future__ import annotations
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import redis.asyncio as aioredis

from core.database import get_db
from core.redis import get_redis

router = APIRouter()


@router.get("/")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@router.get("/ready")
async def readiness(
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
):
    checks: dict[str, str] = {}

    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {str(e)[:100]}"

    try:
        await redis.ping()
        checks["redis"] = "ok"
    except Exception as e:
        checks["redis"] = f"error: {str(e)[:100]}"

    all_ok = all(v == "ok" for v in checks.values())
    return JSONResponse(
        content={"status": "ready" if all_ok else "degraded", "checks": checks},
        status_code=200 if all_ok else 503,
    )


@router.get("/workers")
async def worker_health():
    from core.celery_app import celery_app
    try:
        inspect = celery_app.control.inspect(timeout=5)
        active = inspect.active() or {}
        stats = inspect.stats() or {}

        worker_status = {}
        for worker_name, worker_stats in stats.items():
            worker_status[worker_name] = {
                "status": "ok",
                "active_tasks": len(active.get(worker_name, [])),
                "uptime": worker_stats.get("uptime"),
                "pool": worker_stats.get("pool", {}).get("implementation"),
            }

        return {"total_workers": len(worker_status), "workers": worker_status}
    except Exception as e:
        return {"total_workers": 0, "workers": {}, "error": str(e)}
