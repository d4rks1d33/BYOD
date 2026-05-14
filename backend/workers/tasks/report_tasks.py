from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from core.celery_app import celery_app

logger = logging.getLogger(__name__)


def _get_sync_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from core.config import get_settings
    engine = create_engine(get_settings().DATABASE_URL_SYNC, pool_pre_ping=True)
    return sessionmaker(bind=engine)()


@celery_app.task(bind=True, queue="report", max_retries=3, time_limit=600, name="report_tasks.generate_report")
def generate_report(self, report_job_id: str) -> dict:
    from sqlalchemy import select, update as sql_update
    from models.report_job import ReportJob
    from models.finding import Finding
    from core.config import get_settings

    settings = get_settings()
    db = _get_sync_db()

    try:
        job = db.execute(select(ReportJob).where(ReportJob.id == report_job_id)).scalar_one_or_none()
        if not job:
            return {"status": "error", "error": "ReportJob not found"}

        if job.status == "completed" and job.file_path:
            return {"status": "already_completed", "file_path": job.file_path}

        db.execute(sql_update(ReportJob).where(ReportJob.id == report_job_id).values(status="running"))
        db.commit()

        # Load findings
        query = select(Finding)
        if job.scan_id:
            query = query.where(Finding.scan_id == job.scan_id)
        elif job.project_id:
            query = query.where(Finding.project_id == job.project_id)

        findings = db.execute(query).scalars().all()

        # Build report data
        severity_order = ["critical", "high", "medium", "low", "info"]
        grouped = {s: [] for s in severity_order}
        for f in findings:
            sev = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower()
            grouped.setdefault(sev, []).append({
                "id": str(f.id),
                "title": f.title,
                "finding_type": f.finding_type,
                "severity": sev,
                "description": f.description,
                "endpoint": str(f.endpoint) if f.endpoint else None,
                "cwe_id": f.cwe_id,
                "tool": f.tool,
                "cvss_score": f.cvss_score,
                "poc_code": f.poc_code or None,
                "payload": f.payload or None,
            })

        report_data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_id": str(job.scan_id) if job.scan_id else None,
            "project_id": str(job.project_id) if job.project_id else None,
            "total_findings": len(findings),
            "findings_by_severity": {s: len(grouped[s]) for s in severity_order},
            "findings": grouped,
        }

        # Save file
        storage_root = Path(settings.EVIDENCE_STORAGE_PATH or "/data/evidence")
        reports_dir = storage_root / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        fmt = job.format.value if hasattr(job.format, "value") else str(job.format)
        filename = f"report_{report_job_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.{fmt}"
        file_path = reports_dir / filename

        if fmt == "json":
            file_path.write_text(json.dumps(report_data, indent=2, default=str))
        elif fmt == "html":
            html = _render_html(report_data)
            file_path.write_text(html)
        else:
            # Fallback to JSON
            file_path = reports_dir / filename.replace(f".{fmt}", ".json")
            file_path.write_text(json.dumps(report_data, indent=2, default=str))

        db.execute(sql_update(ReportJob).where(ReportJob.id == report_job_id).values(
            status="completed",
            file_path=str(file_path),
            completed_at=datetime.now(timezone.utc),
        ))
        db.commit()

        logger.info("Report generated: %s", file_path)
        return {"status": "completed", "file_path": str(file_path), "findings_count": len(findings)}

    except Exception as exc:
        logger.exception("generate_report failed for job %s", report_job_id)
        try:
            db.execute(sql_update(ReportJob).where(ReportJob.id == report_job_id).values(
                status="failed", error=str(exc)[:500]
            ))
            db.commit()
        except Exception:
            pass
        try:
            self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            pass
        raise
    finally:
        db.close()


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _render_html(data: dict) -> str:
    findings_html = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        for f in data["findings"].get(sev, []):
            color = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#2563eb", "info": "#6b7280"}.get(sev, "#666")

            poc_block = ""
            if f.get("poc_code"):
                poc_block = f"""
              <details style="margin-top:12px">
                <summary style="cursor:pointer;font-size:13px;font-weight:600;color:#7c3aed;user-select:none">
                  &#128273; Proof of Concept Script
                </summary>
                <pre style="background:#0d1117;color:#e6edf3;padding:16px;border-radius:6px;overflow-x:auto;font-size:12px;line-height:1.5;margin:8px 0"><code>{_esc(f['poc_code'])}</code></pre>
                {f'<details style="margin-top:4px"><summary style="cursor:pointer;font-size:12px;color:#6b7280">Output / Evidence</summary><pre style="background:#1a1a1a;color:#aaaaaa;padding:12px;border-radius:4px;font-size:11px;overflow-x:auto;margin:4px 0">{_esc(f.get("description","")[:2000])}</pre></details>' if f.get("description") else ""}
              </details>"""

            payload_badge = ""
            if f.get("payload"):
                payload_badge = f'<span style="margin-left:16px;font-family:monospace;background:#fef3c7;color:#92400e;padding:1px 6px;border-radius:3px;font-size:11px">{_esc(str(f["payload"])[:80])}</span>'

            findings_html += f"""
            <div style="border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:16px">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
                <span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600">{sev.upper()}</span>
                <strong>{_esc(f['title'])}</strong>
              </div>
              <p style="color:#374151;margin:8px 0">{_esc(f.get('description','')[:500])}</p>
              <div style="font-size:12px;color:#6b7280">
                {f'<span>Endpoint: <code>{_esc(f["endpoint"])}</code></span>' if f.get("endpoint") else ""}
                {f'<span style="margin-left:16px">CWE: {_esc(str(f["cwe_id"]))}</span>' if f.get("cwe_id") else ""}
                {f'<span style="margin-left:16px">Tool: {_esc(str(f["tool"]))}</span>' if f.get("tool") else ""}
                {payload_badge}
              </div>
              {poc_block}
            </div>"""

    poc_count = sum(
        1 for sev in data["findings"].values() for f in sev if f.get("poc_code")
    )
    poc_banner = (
        f'<div style="background:#f5f3ff;border:1px solid #7c3aed;border-radius:8px;padding:12px 16px;margin-bottom:24px">'
        f'&#128273; <strong>{poc_count} confirmed vulnerabilit{"y" if poc_count==1 else "ies"}</strong> '
        f'include a Proof of Concept script — expand each finding below to view the exploit code and output.'
        f'</div>'
    ) if poc_count else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AutoPentest Security Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 1200px; margin: 0 auto; padding: 32px; color: #111; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin: 24px 0; }}
  .stat-card {{ border-radius: 8px; padding: 16px; text-align: center; }}
  h1 {{ color: #111827; }} h2 {{ color: #374151; border-bottom: 1px solid #e5e7eb; padding-bottom: 8px; }}
  details > summary {{ list-style: none; }} details > summary::-webkit-details-marker {{ display: none; }}
</style>
</head>
<body>
<h1>Security Assessment Report</h1>
<p style="color:#6b7280">Generated: {data['generated_at']}</p>
<h2>Executive Summary</h2>
<div class="stat-grid">
  <div class="stat-card" style="background:#fef2f2"><div style="font-size:32px;font-weight:700;color:#dc2626">{data['findings_by_severity'].get('critical',0)}</div><div>Critical</div></div>
  <div class="stat-card" style="background:#fff7ed"><div style="font-size:32px;font-weight:700;color:#ea580c">{data['findings_by_severity'].get('high',0)}</div><div>High</div></div>
  <div class="stat-card" style="background:#fffbeb"><div style="font-size:32px;font-weight:700;color:#d97706">{data['findings_by_severity'].get('medium',0)}</div><div>Medium</div></div>
  <div class="stat-card" style="background:#eff6ff"><div style="font-size:32px;font-weight:700;color:#2563eb">{data['findings_by_severity'].get('low',0)}</div><div>Low</div></div>
  <div class="stat-card" style="background:#f9fafb"><div style="font-size:32px;font-weight:700;color:#6b7280">{data['total_findings']}</div><div>Total</div></div>
</div>
{poc_banner}
<h2>Findings</h2>
{findings_html if findings_html else '<p style="color:#6b7280">No findings recorded.</p>'}
</body>
</html>"""
