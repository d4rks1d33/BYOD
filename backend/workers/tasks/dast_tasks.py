from __future__ import annotations
import asyncio
import json
import logging
import os
import subprocess
import tempfile
from typing import Optional

from core.celery_app import celery_app

logger = logging.getLogger(__name__)


def _get_sync_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from core.config import get_settings
    settings = get_settings()
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    return sessionmaker(bind=engine)()


def _get_sync_redis():
    import redis as redis_sync
    from core.config import get_settings
    return redis_sync.from_url(get_settings().REDIS_URL, decode_responses=True)


def check_pause_cancel(scan_id: str, redis_client) -> Optional[str]:
    val = redis_client.get(f"scan:control:{scan_id}")
    if val in ("cancel", "pause"):
        return val
    return None


@celery_app.task(bind=True, queue="dast", max_retries=2, time_limit=5400, name="dast_tasks.run_dast_scan")
def run_dast_scan(self, scan_id: str, config: dict) -> dict:
    from sqlalchemy import select
    from models.scan import Scan
    from services.finding_service import FindingService

    db = _get_sync_db()
    redis = _get_sync_redis()

    def log(level: str, msg: str):
        from services.scan_progress import ScanProgressTracker
        tracker = ScanProgressTracker(scan_id, redis)
        loop = asyncio.new_event_loop()
        loop.run_until_complete(tracker.append_log(level, "dast_runner", msg))
        loop.run_until_complete(tracker.refresh_heartbeat())
        loop.close()

    try:
        scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        target_url = config.get("target_url") or str(scan.project_id)
        scope_urls = config.get("scope_urls", [target_url])
        rate_limit = config.get("requests_per_second", 10)

        log("INFO", f"Starting DAST: {target_url}")
        findings_stored = 0

        # Run Nuclei
        if not check_pause_cancel(scan_id, redis):
            try:
                nuclei_result = run_nuclei_scan.apply(args=[scan_id, target_url, config])
                if nuclei_result.result:
                    findings_stored += nuclei_result.result.get("findings_stored", 0)
            except Exception as exc:
                log("WARN", f"Nuclei failed: {exc}")

        # Run ffuf
        if not check_pause_cancel(scan_id, redis):
            try:
                ffuf_result = run_ffuf_scan.apply(args=[scan_id, target_url, config])
                if ffuf_result.result:
                    findings_stored += ffuf_result.result.get("findings_stored", 0)
            except Exception as exc:
                log("WARN", f"ffuf failed: {exc}")

        log("INFO", f"DAST complete: {findings_stored} total findings")
        return {"status": "completed", "findings_stored": findings_stored}

    except Exception as exc:
        logger.exception("run_dast_scan failed for %s", scan_id)
        raise
    finally:
        db.close()


@celery_app.task(bind=True, queue="dast", max_retries=1, time_limit=1800, name="dast_tasks.run_nuclei_scan")
def run_nuclei_scan(self, scan_id: str, target_url: str, config: dict) -> dict:
    from sqlalchemy import select
    from models.scan import Scan
    from services.finding_service import FindingService
    from core.config import get_settings

    settings = get_settings()
    db = _get_sync_db()

    try:
        scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
        if not scan:
            return {"status": "error", "error": "Scan not found"}

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as out:
            out_path = out.name

        cmd = [
            "nuclei", "-u", target_url,
            "-json-export", out_path,
            "-timeout", "10",
            "-rate-limit", str(config.get("requests_per_second", 10)),
            "-silent",
        ]

        logger.info("Running: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1700)

        findings_stored = 0
        try:
            with open(out_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw = json.loads(line)
                        finding_data = {
                            "scan_id": scan_id,
                            "project_id": str(scan.project_id),
                            "source": "dast",
                            "tool": "nuclei",
                            "finding_type": "nuclei_finding",
                            "severity": raw.get("info", {}).get("severity", "medium"),
                            "title": raw.get("info", {}).get("name", "Nuclei Finding"),
                            "description": raw.get("info", {}).get("description", ""),
                            "endpoint_url": raw.get("matched-at", target_url),
                            "cwe_id": "",
                        }
                        FindingService.store_finding(db, finding_data)
                        db.commit()
                        findings_stored += 1
                    except Exception:
                        pass
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass

        return {"status": "completed", "findings_stored": findings_stored}

    except FileNotFoundError:
        logger.warning("nuclei not installed")
        return {"status": "skipped", "reason": "nuclei_not_found", "findings_stored": 0}
    except Exception as exc:
        logger.exception("run_nuclei_scan failed for %s", scan_id)
        return {"status": "error", "error": str(exc), "findings_stored": 0}
    finally:
        db.close()


@celery_app.task(bind=True, queue="dast", max_retries=1, time_limit=1800, name="dast_tasks.run_ffuf_scan")
def run_ffuf_scan(self, scan_id: str, target_url: str, config: dict) -> dict:
    from sqlalchemy import select
    from models.scan import Scan
    from services.finding_service import FindingService

    db = _get_sync_db()

    try:
        scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
        if not scan:
            return {"status": "error", "error": "Scan not found"}

        wordlist = config.get("wordlist", "/app/wordlists/common.txt")
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wordlist):
            logger.warning("No wordlist found for ffuf, skipping")
            return {"status": "skipped", "reason": "no_wordlist", "findings_stored": 0}

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as out:
            out_path = out.name

        fuzz_url = target_url.rstrip("/") + "/FUZZ"
        cmd = [
            "ffuf", "-u", fuzz_url, "-w", wordlist,
            "-of", "json", "-o", out_path,
            "-rate", str(config.get("requests_per_second", 50)),
            "-t", "10", "-timeout", "10",
            "-mc", "200,201,204,301,302,401,403",
            "-s",
        ]

        logger.info("Running ffuf: %s", " ".join(cmd))
        subprocess.run(cmd, capture_output=True, text=True, timeout=1700)

        findings_stored = 0
        try:
            with open(out_path) as f:
                data = json.load(f)
            for item in data.get("results", []):
                status = item.get("status", 200)
                url = item.get("url", "")
                severity = "medium" if status in (401, 403) else "info"
                finding_data = {
                    "scan_id": scan_id,
                    "project_id": str(scan.project_id),
                    "source": "dast",
                    "tool": "ffuf",
                    "finding_type": "access_control" if status in (401, 403) else "endpoint_discovery",
                    "severity": severity,
                    "title": f"ffuf: {url} ({status})",
                    "endpoint_url": url,
                    "method": "GET",
                }
                FindingService.store_finding(db, finding_data)
                db.commit()
                findings_stored += 1
        except Exception as e:
            logger.warning("ffuf output parse error: %s", e)
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass

        return {"status": "completed", "findings_stored": findings_stored}

    except FileNotFoundError:
        logger.warning("ffuf not installed")
        return {"status": "skipped", "reason": "ffuf_not_found", "findings_stored": 0}
    except Exception as exc:
        logger.exception("run_ffuf_scan failed for %s", scan_id)
        return {"status": "error", "error": str(exc), "findings_stored": 0}
    finally:
        db.close()
