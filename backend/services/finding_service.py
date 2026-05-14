from __future__ import annotations
import hashlib
import logging
from typing import Optional
from uuid import UUID

logger = logging.getLogger(__name__)


class FindingService:

    @staticmethod
    def compute_dedup_hash(finding_data: dict) -> str:
        source = finding_data.get("source", "dast")
        if source == "sast":
            parts = [
                str(finding_data.get("file_path", "") or ""),
                str(finding_data.get("line", "") or ""),
                str(finding_data.get("function_name", "") or ""),
                str(finding_data.get("finding_type", "") or ""),
                str(finding_data.get("cwe_id", "") or ""),
            ]
        else:
            parts = [
                str(finding_data.get("endpoint_url", "") or ""),
                str(finding_data.get("method", "") or ""),
                str(finding_data.get("parameter", "") or ""),
                str(finding_data.get("finding_type", "") or ""),
                str(finding_data.get("cwe_id", "") or ""),
            ]
        canonical = "|".join(parts)
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def store_finding(db, finding_data: dict):
        from datetime import datetime, timezone
        from models.finding import Finding
        from sqlalchemy import select

        dedup_hash = FindingService.compute_dedup_hash(finding_data)
        now = datetime.now(timezone.utc)

        existing = db.execute(select(Finding).where(Finding.dedup_hash == dedup_hash)).scalar_one_or_none()
        if existing:
            existing.updated_at = now
            if finding_data.get("severity"):
                existing.severity = finding_data["severity"]
            db.flush()
            return existing

        finding = Finding(
            scan_id=finding_data.get("scan_id"),
            project_id=finding_data.get("project_id"),
            finding_type=finding_data.get("finding_type", "unknown"),
            severity=finding_data.get("severity", "medium"),
            title=finding_data.get("title", "Finding")[:512],
            description=finding_data.get("description", ""),
            endpoint=finding_data.get("endpoint_url"),
            http_method=finding_data.get("method"),
            parameter=finding_data.get("parameter"),
            payload=finding_data.get("payload"),
            cwe_id=finding_data.get("cwe_id"),
            tool=finding_data.get("tool"),
            dedup_hash=dedup_hash,
        )
        db.add(finding)
        db.flush()
        logger.info("Finding stored: type=%s severity=%s", finding.finding_type, finding.severity)
        return finding
