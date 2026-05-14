from __future__ import annotations
import json
from datetime import datetime
from typing import Any


SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#16a34a",
    "info": "#2563eb",
}


def render_html(data: dict[str, Any]) -> str:
    project = data.get("project", {})
    findings = data.get("findings", [])
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    findings_by_sev: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        findings_by_sev.setdefault(sev, []).append(f)

    stats = {sev: len(items) for sev, items in findings_by_sev.items()}

    def finding_rows(fs: list) -> str:
        rows = []
        for f in fs:
            sev = str(f.get("severity", "info")).lower()
            color = SEVERITY_COLORS.get(sev, "#6b7280")
            rows.append(f"""
            <tr>
                <td><span style="color:{color};font-weight:600">{sev.upper()}</span></td>
                <td>{_esc(f.get('title', ''))}</td>
                <td>{_esc(str(f.get('endpoint', '')))}</td>
                <td>{_esc(f.get('cwe_id', ''))}</td>
                <td>{_esc(f.get('status', ''))}</td>
            </tr>""")
        return "\n".join(rows)

    all_rows = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        all_rows += finding_rows(findings_by_sev.get(sev, []))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Report — {_esc(project.get('name', 'Unknown'))}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #1f2937; background: #f9fafb; }}
  h1 {{ color: #111827; border-bottom: 3px solid #6366f1; padding-bottom: 8px; }}
  .meta {{ color: #6b7280; font-size: 0.9em; margin-bottom: 24px; }}
  .stats {{ display: flex; gap: 16px; margin-bottom: 32px; }}
  .stat {{ background: white; border-radius: 8px; padding: 16px 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .stat-label {{ font-size: 0.8em; text-transform: uppercase; color: #6b7280; }}
  .stat-value {{ font-size: 2em; font-weight: 700; }}
  table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }}
  th {{ background: #374151; color: white; text-align: left; padding: 12px 16px; font-size: 0.85em; text-transform: uppercase; }}
  td {{ padding: 10px 16px; border-bottom: 1px solid #e5e7eb; font-size: 0.9em; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f3f4f6; }}
</style>
</head>
<body>
<h1>Security Assessment Report</h1>
<div class="meta">
  <strong>Target:</strong> {_esc(project.get('name', ''))} &nbsp;|&nbsp;
  <strong>URL:</strong> {_esc(str(project.get('target_url', '')))} &nbsp;|&nbsp;
  <strong>Generated:</strong> {generated_at}
</div>

<h2>Executive Summary</h2>
<div class="stats">
  <div class="stat"><div class="stat-label">Critical</div><div class="stat-value" style="color:#dc2626">{stats.get('critical',0)}</div></div>
  <div class="stat"><div class="stat-label">High</div><div class="stat-value" style="color:#ea580c">{stats.get('high',0)}</div></div>
  <div class="stat"><div class="stat-label">Medium</div><div class="stat-value" style="color:#ca8a04">{stats.get('medium',0)}</div></div>
  <div class="stat"><div class="stat-label">Low</div><div class="stat-value" style="color:#16a34a">{stats.get('low',0)}</div></div>
  <div class="stat"><div class="stat-label">Info</div><div class="stat-value" style="color:#2563eb">{stats.get('info',0)}</div></div>
  <div class="stat"><div class="stat-label">Total</div><div class="stat-value">{len(findings)}</div></div>
</div>

<h2>Findings</h2>
<table>
  <thead><tr><th>Severity</th><th>Title</th><th>Endpoint</th><th>CWE</th><th>Status</th></tr></thead>
  <tbody>{all_rows}</tbody>
</table>
</body>
</html>"""


def _esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
    )
