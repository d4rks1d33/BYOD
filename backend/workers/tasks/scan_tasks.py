from __future__ import annotations
import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from core.celery_app import celery_app

logger = logging.getLogger(__name__)


def _get_sync_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from core.config import get_settings
    settings = get_settings()
    url = settings.DATABASE_URL_SYNC
    engine = create_engine(url, pool_pre_ping=True)
    Session = sessionmaker(bind=engine)
    return Session()


def _get_sync_redis():
    import redis as redis_sync
    from core.config import get_settings
    settings = get_settings()
    url = settings.REDIS_URL
    return redis_sync.from_url(url, decode_responses=True)


def _check_signal(scan_id: str, redis_client) -> Optional[str]:
    if redis_client.get(f"scan:control:{scan_id}") == "cancel":
        return "cancel"
    if redis_client.get(f"scan:control:{scan_id}") == "pause":
        return "pause"
    return None


def _update_progress(scan_id: str, redis_client, **kwargs) -> None:
    from services.scan_progress import ScanProgressTracker
    tracker = ScanProgressTracker(scan_id, redis_client)

    async def _run():
        await tracker.update(**kwargs)
        await tracker.refresh_heartbeat()

    try:
        loop = asyncio.new_event_loop()
        loop.run_until_complete(_run())
        loop.close()
    except Exception as e:
        logger.warning("Progress update failed: %s", e)


def _append_log(scan_id: str, redis_client, level: str, agent: str, message: str) -> None:
    from services.scan_progress import ScanProgressTracker
    tracker = ScanProgressTracker(scan_id, redis_client)

    async def _run():
        await tracker.append_log(level, agent, message)

    try:
        loop = asyncio.new_event_loop()
        loop.run_until_complete(_run())
        loop.close()
    except Exception as e:
        logger.warning("Log append failed: %s", e)


@celery_app.task(bind=True, queue="dast", max_retries=0, time_limit=7200, name="scan_tasks.run_full_scan")
def run_full_scan(self, scan_id: str) -> dict:
    from sqlalchemy import select, update as sql_update
    from models.scan import Scan

    db = _get_sync_db()
    redis = _get_sync_redis()

    def progress(phase: str, pct: int, msg: str = ""):
        _update_progress(scan_id, redis, current_phase=phase, overall_progress_pct=pct, message=msg)

    def log(level: str, msg: str):
        _append_log(scan_id, redis, level, "orchestrator", msg)

    try:
        scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
        if not scan:
            return {"status": "error", "error": "Scan not found"}

        db.execute(sql_update(Scan).where(Scan.id == scan_id).values(
            status="running", started_at=datetime.now(timezone.utc)
        ))
        db.commit()

        scan_config = scan.config or {}
        scan_type = scan.scan_type.value if hasattr(scan.scan_type, "value") else str(scan.scan_type)
        target_url = scan_config.get("target_url", "")

        progress("init", 5, "Scan initialized")
        log("INFO", f"Starting AI-driven audit {scan_id} type={scan_type} target={target_url}")

        # Determine scan mode: multi-agent (new), AI-single (legacy AI), tools-only (very legacy)
        scan_mode = scan_config.get("scan_mode", "multi_agent")  # multi_agent | ai_single | tools_only

        scan_failed = False
        scan_error_msg = None

        if scan_mode == "multi_agent":
            # NEW: MULTI-AGENT MODE - Specialized AI agents collaborate
            log("INFO", "Starting MULTI-AGENT autonomous audit (Recon + Exploit + Analysis + Report)")
            progress("multi_agent", 10, "Multi-agent system analyzing target...")

            if _check_signal(scan_id, redis):
                _handle_signal(scan_id, redis, db, Scan, sql_update)
                return {"status": "stopped"}

            try:
                # Call pure function directly (avoids "Never call result.get() within a task!" error)
                from workers.tasks.ai_audit_tasks import _do_multi_agent_audit
                result = _do_multi_agent_audit(scan_id, scan_config)

                if result.get("status") == "error":
                    scan_failed = True
                    scan_error_msg = result.get("error", "Multi-agent audit returned error status")
                    log("ERROR", f"Multi-agent audit error: {scan_error_msg}")
                else:
                    progress("multi_agent", 95, f"Audit complete: {result.get('findings_count', 0)} findings")
                    log("INFO", f"Multi-agent audit completed with {result.get('findings_count', 0)} findings")

            except Exception as exc:
                scan_failed = True
                scan_error_msg = str(exc)
                log("ERROR", f"Multi-agent audit failed: {exc}")
                logger.exception("Multi-agent audit error")

        elif scan_mode == "ai_single":
            # LEGACY: AI single-agent mode
            log("INFO", "Starting AI single-agent audit")
            progress("audit", 10, "AI auditor analyzing target...")

            if _check_signal(scan_id, redis):
                _handle_signal(scan_id, redis, db, Scan, sql_update)
                return {"status": "stopped"}

            try:
                from workers.tasks.ai_audit_tasks import _do_ai_audit
                result = _do_ai_audit(scan_id, scan_config)

                if result.get("status") == "error":
                    scan_failed = True
                    scan_error_msg = result.get("error", "AI audit returned error status")
                    log("ERROR", f"AI audit error: {scan_error_msg}")
                else:
                    progress("audit", 95, f"AI audit complete: {result.get('findings_count', 0)} findings")
                    log("INFO", f"AI audit completed with {result.get('findings_count', 0)} findings")

            except Exception as exc:
                scan_failed = True
                scan_error_msg = str(exc)
                log("ERROR", f"AI audit failed: {exc}")
                logger.exception("AI audit error")

        elif scan_mode == "tools_only":
            # VERY LEGACY: Traditional tool-driven mode
            log("INFO", "Running traditional tool-driven scan (legacy mode)")

            # Phase 1: Recon
            if _check_signal(scan_id, redis):
                _handle_signal(scan_id, redis, db, Scan, sql_update)
                return {"status": "stopped"}

            progress("recon", 10, "Running recon")
            log("INFO", "Starting recon phase")
            try:
                _run_katana(scan_id, target_url, scan_config, redis)
                progress("recon", 20, "Recon complete")
            except Exception as exc:
                log("WARN", f"Recon partial failure: {exc}")

            # Phase 2: DAST
            if "sast" not in scan_type or "dast" in scan_type or scan_type == "full":
                if _check_signal(scan_id, redis):
                    _handle_signal(scan_id, redis, db, Scan, sql_update)
                    return {"status": "stopped"}

                progress("dast", 25, "Starting DAST scan")
                log("INFO", "Running DAST pipeline")
                try:
                    from workers.tasks.dast_tasks import run_dast_scan
                    run_dast_scan.apply(args=[scan_id, scan_config])
                    progress("dast", 65, "DAST complete")
                except Exception as exc:
                    log("ERROR", f"DAST failed: {exc}")

            # Phase 3: SAST
            if "sast" in scan_type or scan_type == "full" or scan_type == "sast_only":
                if _check_signal(scan_id, redis):
                    _handle_signal(scan_id, redis, db, Scan, sql_update)
                    return {"status": "stopped"}

                progress("sast", 66, "Starting SAST scan")
                log("INFO", "Running SAST pipeline")
                try:
                    from workers.tasks.sast_tasks import run_sast_scan
                    run_sast_scan.apply(args=[scan_id, scan_config])
                    progress("sast", 80, "SAST complete")
                except Exception as exc:
                    log("WARN", f"SAST failed: {exc}")

            # Phase 4: Correlation
            progress("correlation", 82, "Running correlation")
            try:
                from workers.tasks.ai_tasks import run_correlation_analysis
                run_correlation_analysis.apply(args=[scan_id])
                progress("correlation", 90, "Correlation complete")
            except Exception as exc:
                log("WARN", f"Correlation failed: {exc}")

        # Complete - mark as failed if any phase failed
        completed_at = datetime.now(timezone.utc)
        final_status = "failed" if scan_failed else "completed"
        update_values = {
            "status": final_status,
            "completed_at": completed_at,
        }
        if scan_failed and scan_error_msg:
            update_values["error"] = str(scan_error_msg)[:1000]

        db.execute(sql_update(Scan).where(Scan.id == scan_id).values(**update_values))
        db.commit()

        _update_progress(scan_id, redis, status=final_status, overall_progress_pct=100)

        # Find project_id to publish ws event
        scan_refreshed = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
        if scan_refreshed:
            redis.publish(
                f"ws:pubsub:project:{scan_refreshed.project_id}",
                json.dumps({
                    "type": f"scan.{final_status}",
                    "scan_id": scan_id,
                    "error": scan_error_msg if scan_failed else None,
                }),
            )

        log("INFO" if not scan_failed else "ERROR", f"Scan {scan_id} {final_status}")
        return {"status": final_status, "scan_id": scan_id, "error": scan_error_msg}

    except Exception as exc:
        logger.exception("run_full_scan error for %s", scan_id)
        try:
            from sqlalchemy import update as sql_update2
            from models.scan import Scan as Scan2
            db.execute(sql_update2(Scan2).where(Scan2.id == scan_id).values(
                status="failed", error=str(exc)[:500], completed_at=datetime.now(timezone.utc)
            ))
            db.commit()
        except Exception:
            pass
        raise
    finally:
        db.close()


def _run_katana(scan_id: str, target_url: str, config: dict, redis) -> None:
    import subprocess, tempfile
    if not target_url:
        return
    rate = config.get("requests_per_second", 10)
    depth = config.get("max_depth", 3)
    try:
        result = subprocess.run(
            ["katana", "-u", target_url, "-d", str(depth), "-rl", str(rate), "-silent"],
            capture_output=True, text=True, timeout=120
        )
        urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        _append_log(scan_id, redis, "INFO", "katana", f"Katana found {len(urls)} URLs")
    except FileNotFoundError:
        _append_log(scan_id, redis, "WARN", "katana", "katana not installed, skipping crawl")
    except Exception as e:
        _append_log(scan_id, redis, "WARN", "katana", f"katana failed: {e}")


def _handle_signal(scan_id, redis, db, Scan, sql_update) -> None:
    signal = _check_signal(scan_id, redis)
    if signal == "cancel":
        db.execute(sql_update(Scan).where(Scan.id == scan_id).values(
            status="cancelled", completed_at=datetime.now(timezone.utc)
        ))
    elif signal == "pause":
        db.execute(sql_update(Scan).where(Scan.id == scan_id).values(status="paused"))
    db.commit()
