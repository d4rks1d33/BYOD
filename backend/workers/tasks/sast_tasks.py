from __future__ import annotations
import asyncio
import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path

from core.celery_app import celery_app

logger = logging.getLogger(__name__)


def _get_sync_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from core.config import get_settings
    settings = get_settings()
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    return sessionmaker(bind=engine)()


@celery_app.task(bind=True, queue="sast", max_retries=2, time_limit=5400, name="sast_tasks.run_sast_scan")
def run_sast_scan(self, scan_id: str, config: dict) -> dict:
    from sqlalchemy import select
    from models.scan import Scan
    from services.finding_service import FindingService

    db = _get_sync_db()

    try:
        scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
        if not scan:
            return {"status": "error", "error": "Scan not found"}

        repo_url = config.get("repo_url") or config.get("git_url")
        local_path = config.get("local_path")

        if not repo_url and not local_path:
            logger.info("No repo configured for SAST scan %s, skipping", scan_id)
            return {"status": "skipped", "reason": "no_repo"}

        work_dir = tempfile.mkdtemp(prefix=f"sast_{scan_id[:8]}_")
        repo_path = local_path or work_dir

        if repo_url:
            try:
                subprocess.run(
                    ["git", "clone", "--depth=1", repo_url, work_dir],
                    check=True, capture_output=True, timeout=300
                )
                repo_path = work_dir
            except Exception as e:
                logger.warning("Git clone failed: %s", e)
                return {"status": "error", "error": f"Clone failed: {e}"}

        all_findings = []
        findings_stored = 0

        # Semgrep
        try:
            semgrep_r = run_semgrep_scan.apply(args=[scan_id, repo_path, ["python", "javascript"]])
            if semgrep_r.result:
                all_findings.extend(semgrep_r.result.get("raw_findings", []))
        except Exception as exc:
            logger.warning("Semgrep failed: %s", exc)

        # trufflehog
        try:
            th_r = run_trufflehog_scan.apply(args=[scan_id, repo_path])
            if th_r.result:
                all_findings.extend(th_r.result.get("raw_findings", []))
        except Exception as exc:
            logger.warning("trufflehog failed: %s", exc)

        # Dependency audit
        try:
            dep_r = run_dependency_audit.apply(args=[scan_id, repo_path])
            if dep_r.result:
                all_findings.extend(dep_r.result.get("raw_findings", []))
        except Exception as exc:
            logger.warning("Dependency audit failed: %s", exc)

        # Store all findings
        for raw in all_findings:
            try:
                fd = {
                    "scan_id": scan_id,
                    "project_id": str(scan.project_id),
                    "source": "sast",
                    "tool": raw.get("tool"),
                    "finding_type": raw.get("finding_type", "code_issue"),
                    "severity": raw.get("severity", "medium"),
                    "title": raw.get("message", raw.get("rule_id", "SAST Finding"))[:255],
                    "description": raw.get("message", ""),
                    "file_path": raw.get("source_file"),
                    "line": raw.get("source_line"),
                    "function_name": raw.get("function_name"),
                    "cwe_id": raw.get("cwe_id", ""),
                }
                FindingService.store_finding(db, fd)
                db.commit()
                findings_stored += 1
            except Exception as store_exc:
                logger.warning("SAST finding store error: %s", store_exc)
                db.rollback()

        return {"status": "completed", "findings_stored": findings_stored}

    except Exception as exc:
        logger.exception("run_sast_scan failed for %s", scan_id)
        raise
    finally:
        db.close()


@celery_app.task(bind=True, queue="sast", max_retries=1, time_limit=900, name="sast_tasks.run_semgrep_scan")
def run_semgrep_scan(self, scan_id: str, repo_path: str, languages: list) -> dict:
    RULESET_MAP = {
        "python": ["p/python", "p/flask", "p/django"],
        "javascript": ["p/javascript", "p/nodejs"],
        "typescript": ["p/typescript"],
        "java": ["p/java"],
        "go": ["p/golang"],
    }

    rulesets = []
    for lang in languages:
        rulesets.extend(RULESET_MAP.get(lang.lower(), []))
    if not rulesets:
        rulesets = ["p/default"]

    ruleset_args = []
    for r in rulesets:
        ruleset_args.extend(["--config", r])

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as out:
        out_path = out.name

    cmd = ["semgrep"] + ruleset_args + [
        "--json", "--output", out_path,
        "--no-git-ignore",
        repo_path
    ]

    try:
        logger.info("Running semgrep")
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        findings = []
        with open(out_path) as f:
            data = json.load(f)
        for result in data.get("results", []):
            findings.append({
                "tool": "semgrep",
                "finding_type": result.get("check_id", "code_issue"),
                "severity": _map_semgrep_severity(result.get("extra", {}).get("severity", "WARNING")),
                "message": result.get("extra", {}).get("message", result.get("check_id", "")),
                "source_file": result.get("path"),
                "source_line": result.get("start", {}).get("line"),
                "rule_id": result.get("check_id"),
                "cwe_id": _extract_cwe(result.get("extra", {}).get("metadata", {})),
            })

        os.unlink(out_path)
        return {"status": "completed", "raw_findings": findings, "findings_count": len(findings)}

    except FileNotFoundError:
        logger.warning("semgrep not installed")
        return {"status": "skipped", "raw_findings": []}
    except Exception as exc:
        logger.exception("semgrep failed")
        return {"status": "error", "error": str(exc), "raw_findings": []}


@celery_app.task(bind=True, queue="sast", max_retries=1, time_limit=600, name="sast_tasks.run_trufflehog_scan")
def run_trufflehog_scan(self, scan_id: str, repo_path: str) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as out:
        out_path = out.name

    cmd = ["trufflehog", "filesystem", repo_path, "--json", "--no-update"]

    try:
        logger.info("Running trufflehog")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                findings.append({
                    "tool": "trufflehog",
                    "finding_type": "hardcoded_secret",
                    "severity": "high",
                    "message": f"Secret detected: {raw.get('DetectorName', 'unknown')}",
                    "source_file": raw.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file"),
                    "cwe_id": "CWE-798",
                })
            except Exception:
                pass

        return {"status": "completed", "raw_findings": findings, "findings_count": len(findings)}

    except FileNotFoundError:
        logger.warning("trufflehog not installed")
        return {"status": "skipped", "raw_findings": []}
    except Exception as exc:
        logger.exception("trufflehog failed")
        return {"status": "error", "error": str(exc), "raw_findings": []}


@celery_app.task(bind=True, queue="sast", max_retries=1, time_limit=600, name="sast_tasks.run_dependency_audit")
def run_dependency_audit(self, scan_id: str, repo_path: str) -> dict:
    findings = []

    # npm audit
    pkg_json = os.path.join(repo_path, "package.json")
    if os.path.exists(pkg_json):
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=repo_path, capture_output=True, text=True, timeout=120
            )
            data = json.loads(result.stdout)
            for vuln_id, vuln in (data.get("vulnerabilities") or {}).items():
                severity = vuln.get("severity", "moderate")
                findings.append({
                    "tool": "npm_audit",
                    "finding_type": "vulnerable_dependency",
                    "severity": _map_npm_severity(severity),
                    "message": f"{vuln_id}: {vuln.get('title', '')}",
                    "cwe_id": "CWE-1035",
                })
        except Exception as exc:
            logger.warning("npm audit failed: %s", exc)

    # pip-audit
    req_txt = os.path.join(repo_path, "requirements.txt")
    if os.path.exists(req_txt):
        try:
            result = subprocess.run(
                ["pip-audit", "--format=json", "-r", req_txt],
                capture_output=True, text=True, timeout=120
            )
            data = json.loads(result.stdout)
            for dep in (data.get("dependencies") or []):
                for vuln in (dep.get("vulns") or []):
                    findings.append({
                        "tool": "pip_audit",
                        "finding_type": "vulnerable_dependency",
                        "severity": "high",
                        "message": f"{dep.get('name')}: {vuln.get('id', '')} {vuln.get('description', '')}",
                        "cwe_id": "CWE-1035",
                    })
        except Exception as exc:
            logger.warning("pip-audit failed: %s", exc)

    return {"status": "completed", "raw_findings": findings, "findings_count": len(findings)}


def _map_semgrep_severity(s: str) -> str:
    return {"ERROR": "high", "WARNING": "medium", "INFO": "info"}.get(s.upper(), "medium")


def _map_npm_severity(s: str) -> str:
    return {"critical": "critical", "high": "high", "moderate": "medium", "low": "low"}.get(s, "medium")


def _extract_cwe(metadata: dict) -> str:
    cwe = metadata.get("cwe") or metadata.get("cwe_id") or ""
    if isinstance(cwe, list):
        return cwe[0] if cwe else ""
    return str(cwe)
