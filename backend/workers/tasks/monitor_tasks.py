from __future__ import annotations
import json
import logging
from datetime import datetime, timezone, timedelta

from core.celery_app import celery_app

logger = logging.getLogger(__name__)


def _get_sync_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from core.config import get_settings
    engine = create_engine(get_settings().DATABASE_URL_SYNC, pool_pre_ping=True)
    return sessionmaker(bind=engine)()


def _get_sync_redis():
    import redis as redis_sync
    from core.config import get_settings
    return redis_sync.from_url(get_settings().REDIS_URL, decode_responses=True)


@celery_app.task(queue="default", ignore_result=True, name="monitor_tasks.check_for_stalled_scans")
def check_for_stalled_scans() -> None:
    from sqlalchemy import select, update as sql_update
    from models.scan import Scan

    db = _get_sync_db()
    redis = _get_sync_redis()

    try:
        running_scans = db.execute(select(Scan).where(Scan.status == "running")).scalars().all()
        stalled = 0
        for scan in running_scans:
            scan_id = str(scan.id)
            if redis.get(f"scan:heartbeat:{scan_id}"):
                continue
            logger.warning("Stalled scan: %s", scan_id)
            error_msg = "Scan stalled — worker lost connection. Check logs."
            db.execute(sql_update(Scan).where(Scan.id == scan.id).values(
                status="failed", error=error_msg, completed_at=datetime.now(timezone.utc)
            ))
            redis.publish(
                f"ws:pubsub:project:{scan.project_id}",
                json.dumps({"type": "scan.failed", "scan_id": scan_id, "error": error_msg}),
            )
            stalled += 1

        if stalled:
            logger.info("Stall check: marked %d scans as failed", stalled)
        db.commit()
    except Exception:
        logger.exception("check_for_stalled_scans failed")
        db.rollback()
    finally:
        db.close()


@celery_app.task(queue="default", ignore_result=True, name="monitor_tasks.update_queue_metrics")
def update_queue_metrics() -> None:
    redis = _get_sync_redis()
    try:
        from api.routers.metrics import QUEUE_DEPTH
        for queue in ["dast", "sast", "ai", "report", "default"]:
            depth = redis.llen(f"celery:{queue}") or 0
            QUEUE_DEPTH.labels(queue=queue).set(depth)
    except Exception:
        pass  # Metrics are best-effort
