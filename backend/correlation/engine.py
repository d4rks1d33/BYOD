from __future__ import annotations
import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

CWE_FAMILIES = {
    "injection": {"CWE-89", "CWE-564", "CWE-943", "CWE-1024"},
    "xss": {"CWE-79", "CWE-80", "CWE-83", "CWE-86"},
    "auth": {"CWE-287", "CWE-306", "CWE-384", "CWE-522"},
    "crypto": {"CWE-327", "CWE-328", "CWE-330", "CWE-338"},
    "path_traversal": {"CWE-22", "CWE-23", "CWE-24"},
    "ssrf": {"CWE-918"},
    "rce": {"CWE-78", "CWE-94", "CWE-95"},
    "disclosure": {"CWE-200", "CWE-209", "CWE-497"},
    "secrets": {"CWE-798", "CWE-259"},
}

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

FRAMEWORK_PATTERNS = {
    "express": (r":([a-zA-Z_][a-zA-Z0-9_]*)", r"{\1}"),
    "fastapi": (r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", r"{\1}"),
    "django": (r"<(?:int|str|uuid|slug):([a-zA-Z_][a-zA-Z0-9_]*)>", r"{\1}"),
}


def normalize_route(path: str) -> str:
    # Remove query strings
    path = path.split("?")[0]
    # Normalize UUIDs
    path = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "{uuid}", path)
    # Normalize numeric IDs
    path = re.sub(r"/\d+(/|$)", r"/{id}\1", path)
    # Normalize base64-like tokens
    path = re.sub(r"/[A-Za-z0-9+/]{20,}={0,2}(/|$)", r"/{token}\1", path)
    return path.lower()


def escalate_severity(sast_sev: str, dast_sev: str) -> str:
    sast_idx = SEVERITY_ORDER.index(sast_sev.lower()) if sast_sev.lower() in SEVERITY_ORDER else 2
    dast_idx = SEVERITY_ORDER.index(dast_sev.lower()) if dast_sev.lower() in SEVERITY_ORDER else 2
    max_idx = max(sast_idx, dast_idx)
    # Escalate by 1 when correlated
    escalated = min(max_idx + 1, len(SEVERITY_ORDER) - 1)
    return SEVERITY_ORDER[escalated]


def _cwe_family(cwe_id: str) -> Optional[str]:
    cwe = (cwe_id or "").upper()
    for family, cwes in CWE_FAMILIES.items():
        if cwe in cwes:
            return family
    return None


class CorrelationEngine:
    def __init__(self, db) -> None:
        self.db = db

    async def correlate(self, scan_id: str) -> list[dict]:
        from sqlalchemy import select
        from models.finding import Finding

        db = self.db
        sast_findings = db.execute(
            select(Finding).where(Finding.scan_id == scan_id, Finding.finding_type.like("%sast%"))
        ).scalars().all()
        dast_findings = db.execute(
            select(Finding).where(Finding.scan_id == scan_id).filter(~Finding.finding_type.like("%sast%"))
        ).scalars().all()

        correlations = []
        matched_dast = set()

        for sast in sast_findings:
            best_match = None
            best_confidence = 0.0

            sast_route = normalize_route(sast.endpoint or "")
            sast_family = _cwe_family(sast.cwe_id or "")

            for dast in dast_findings:
                if dast.id in matched_dast:
                    continue

                dast_route = normalize_route(dast.endpoint or "")
                confidence = 0.0

                # Tier 1: exact route match
                if sast_route and dast_route and sast_route == dast_route:
                    confidence = 0.95

                # Tier 2: CWE family + parameter match
                elif sast_family and _cwe_family(dast.cwe_id or "") == sast_family:
                    confidence = 0.55
                    if sast.parameter and dast.parameter and sast.parameter == dast.parameter:
                        confidence = 0.70

                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = dast

            if best_match and best_confidence >= 0.55:
                matched_dast.add(best_match.id)
                unified_severity = escalate_severity(
                    sast.severity.value if hasattr(sast.severity, "value") else str(sast.severity),
                    best_match.severity.value if hasattr(best_match.severity, "value") else str(best_match.severity),
                )

                # Update SAST finding to link to DAST finding
                try:
                    sast.correlated_finding_id = best_match.id
                    db.flush()
                except Exception as e:
                    logger.warning("Failed to link correlated findings: %s", e)

                correlations.append({
                    "sast_id": str(sast.id),
                    "dast_id": str(best_match.id),
                    "confidence": best_confidence,
                    "unified_severity": unified_severity,
                })
                logger.info("Correlated: %s <-> %s (conf=%.2f)", sast.id, best_match.id, best_confidence)

        try:
            db.commit()
        except Exception:
            db.rollback()

        return correlations
