# AutoPentest — Reporting Engine Design

## Report Data Model

```python
# backend/reports/models.py
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class ReportFinding:
    id: str
    title: str
    severity: str
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    cwe_id: Optional[str]
    cve_ids: list[str]
    finding_type: str
    endpoint_url: Optional[str]
    parameter: Optional[str]
    source_file: Optional[str]
    source_line: Optional[int]
    description: str
    reproduction_steps: list[str]
    poc_code: Optional[str]
    remediation: str
    evidence: list[dict]
    correlated: bool
    status: str
    verified_at: Optional[str]

@dataclass
class ReportData:
    project_name: str
    target_url: str
    generated_at: str
    generated_by: str
    scan_dates: list[str]
    executive_summary: str         # AI-generated
    scope: list[str]
    methodology: str
    findings: list[ReportFinding]
    statistics: dict
    appendix_requests: list[dict]  # Raw HTTP evidence (technical reports)
    risk_rating: str               # Overall risk: Critical/High/Medium/Low
    recommendations: list[str]     # Top remediation priorities
```

---

## CVSS v3.1 Score Calculation

```python
# backend/reports/cvss.py
from dataclasses import dataclass
from typing import Optional
import math

@dataclass
class CVSSVector:
    """CVSS v3.1 Base Score vector components."""
    # Attack Vector: N(etwork), A(djacent), L(ocal), P(hysical)
    AV: str = "N"
    # Attack Complexity: L(ow), H(igh)
    AC: str = "L"
    # Privileges Required: N(one), L(ow), H(igh)
    PR: str = "N"
    # User Interaction: N(one), R(equired)
    UI: str = "N"
    # Scope: U(nchanged), C(hanged)
    S: str = "U"
    # Confidentiality Impact: N(one), L(ow), H(igh)
    C: str = "H"
    # Integrity Impact: N(one), L(ow), H(igh)
    I: str = "H"
    # Availability Impact: N(one), L(ow), H(igh)
    A: str = "H"

    AV_MAP = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_MAP = {"L": 0.77, "H": 0.44}
    PR_MAP_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # Scope Unchanged
    PR_MAP_C = {"N": 0.85, "L": 0.68, "H": 0.50}  # Scope Changed
    UI_MAP = {"N": 0.85, "R": 0.62}
    C_MAP = {"N": 0.00, "L": 0.22, "H": 0.56}
    I_MAP = {"N": 0.00, "L": 0.22, "H": 0.56}
    A_MAP = {"N": 0.00, "L": 0.22, "H": 0.56}

    def base_score(self) -> float:
        av = self.AV_MAP[self.AV]
        ac = self.AC_MAP[self.AC]
        pr_map = self.PR_MAP_C if self.S == "C" else self.PR_MAP_U
        pr = pr_map[self.PR]
        ui = self.UI_MAP[self.UI]
        c = self.C_MAP[self.C]
        i = self.I_MAP[self.I]
        a = self.A_MAP[self.A]

        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        exploitability = 8.22 * av * ac * pr * ui

        if self.S == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        if impact <= 0:
            return 0.0

        if self.S == "U":
            score = min(impact + exploitability, 10)
        else:
            score = min(1.08 * (impact + exploitability), 10)

        # Round up to nearest 0.1
        return math.ceil(score * 10) / 10

    def to_string(self) -> str:
        return (f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}/"
                f"UI:{self.UI}/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}")

    def severity_label(self) -> str:
        score = self.base_score()
        if score == 0.0: return "None"
        if score < 4.0:  return "Low"
        if score < 7.0:  return "Medium"
        if score < 9.0:  return "High"
        return "Critical"


DEFAULT_CVSS_BY_TYPE = {
    "sqli":             CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),  # 10.0
    "xss":              CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"),  # 6.1
    "ssrf":             CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="L", A="N"),  # 8.6
    "rce":              CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),  # 10.0
    "idor":             CVSSVector(AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="H", A="N"),  # 8.1
    "secret":           CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),  # 7.5
    "open_redirect":    CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="N", A="N"),  # 4.3
    "cors":             CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="H", A="N"),  # 7.6
}
```

---

## CWE/CVE Mapping

```python
# backend/reports/cwe_mapping.py
class CWEMapper:
    """
    Maps finding types to CWE entries. Uses bundled CWE database (offline).
    """
    FINDING_TO_CWE = {
        "sqli":                     "CWE-89",   # SQL Injection
        "xss":                      "CWE-79",   # XSS
        "ssrf":                     "CWE-918",  # SSRF
        "rce":                      "CWE-78",   # OS Command Injection
        "lfi":                      "CWE-22",   # Path Traversal
        "xxe":                      "CWE-611",  # XML External Entity
        "ssti":                     "CWE-94",   # Code Injection
        "idor":                     "CWE-639",  # Authorization bypass
        "broken_auth":              "CWE-287",  # Improper Authentication
        "open_redirect":            "CWE-601",  # Open Redirect
        "sensitive_data":           "CWE-312",  # Cleartext Storage of Sensitive Info
        "secret":                   "CWE-798",  # Hardcoded Credentials
        "vulnerable_dependency":    "CWE-1035", # Using Vulnerable Component
        "cors":                     "CWE-942",  # Overly Permissive CORS
        "csrf":                     "CWE-352",  # CSRF
        "jwt_weak":                 "CWE-347",  # Improper JWT Verification
        "graphql_introspection":    "CWE-200",  # Exposure of Sensitive Info
        "iac_misconfiguration":     "CWE-250",  # Execution with Unnecessary Privileges
    }

    def get_cwe_description(self, cwe_id: str) -> dict:
        """Load CWE description from bundled SQLite database."""
        import sqlite3
        conn = sqlite3.connect("/opt/cwe/cwe.db")
        row = conn.execute(
            "SELECT name, description, url FROM cwes WHERE cwe_id = ?", (cwe_id,)
        ).fetchone()
        conn.close()
        if row:
            return {"id": cwe_id, "name": row[0], "description": row[1], "url": row[2]}
        return {"id": cwe_id, "name": "Unknown", "description": "", "url": ""}
```

---

## HTML Report Renderer (Jinja2)

```python
# backend/reports/html_renderer.py
from jinja2 import Environment, FileSystemLoader
import datetime

class HTMLReportRenderer:
    def __init__(self, templates_dir: str = "backend/reports/templates"):
        self.env = Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=True,      # XSS prevention — escape all template variables
        )
        self.env.filters["severity_color"] = self._severity_color
        self.env.filters["cvss_badge"] = self._cvss_badge

    def render(self, report_data: ReportData, audience: str = "technical") -> str:
        template_name = f"{audience}_report.html.j2"
        template = self.env.get_template(template_name)
        return template.render(
            report=report_data,
            generated_at=datetime.datetime.utcnow().isoformat(),
            version="1.0"
        )

    def _severity_color(self, severity: str) -> str:
        return {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#ca8a04",
            "low": "#2563eb",
            "info": "#6b7280",
        }.get(severity, "#6b7280")

    def _cvss_badge(self, score: float) -> str:
        if score >= 9.0: return f'<span class="badge critical">{score} Critical</span>'
        if score >= 7.0: return f'<span class="badge high">{score} High</span>'
        if score >= 4.0: return f'<span class="badge medium">{score} Medium</span>'
        return f'<span class="badge low">{score} Low</span>'
```

### Technical Report Template Structure (`technical_report.html.j2`)

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Assessment: {{ report.project_name }}</title>
  <style>/* Inline CSS for self-contained report */</style>
</head>
<body>
  <header>
    <h1>Security Assessment Report</h1>
    <h2>{{ report.project_name }}</h2>
    <table class="metadata">
      <tr><td>Target:</td><td>{{ report.target_url }}</td></tr>
      <tr><td>Assessment Date:</td><td>{{ report.scan_dates | join(", ") }}</td></tr>
      <tr><td>Report Generated:</td><td>{{ report.generated_at }}</td></tr>
      <tr><td>Prepared By:</td><td>AutoPentest v1.0 + {{ report.generated_by }}</td></tr>
    </table>
  </header>

  <section id="executive-summary">
    <h2>Executive Summary</h2>
    <p>{{ report.executive_summary }}</p>
    <div class="risk-badge severity-{{ report.risk_rating | lower }}">
      Overall Risk: {{ report.risk_rating }}
    </div>
    <!-- Findings distribution chart (SVG inline) -->
  </section>

  <section id="scope">
    <h2>Scope and Methodology</h2>
    <ul>{% for url in report.scope %}<li>{{ url }}</li>{% endfor %}</ul>
    <p>{{ report.methodology }}</p>
  </section>

  <section id="findings">
    <h2>Findings ({{ report.findings | length }})</h2>
    {% for finding in report.findings | sort(attribute='cvss_score', reverse=True) %}
    <div class="finding" id="finding-{{ finding.id }}">
      <h3>
        <span class="severity-badge" style="background:{{ finding.severity | severity_color }}">
          {{ finding.severity | upper }}
        </span>
        {{ finding.title }}
        {% if finding.cvss_score %}
          {{ finding.cvss_score | cvss_badge }}
        {% endif %}
      </h3>
      <table class="finding-meta">
        <tr><td>CWE:</td><td>{{ finding.cwe_id }}</td></tr>
        <tr><td>CVE:</td><td>{{ finding.cve_ids | join(", ") or "N/A" }}</td></tr>
        {% if finding.endpoint_url %}
        <tr><td>Endpoint:</td><td><code>{{ finding.http_method }} {{ finding.endpoint_url }}</code></td></tr>
        {% endif %}
        {% if finding.source_file %}
        <tr><td>Location:</td><td><code>{{ finding.source_file }}:{{ finding.source_line }}</code></td></tr>
        {% endif %}
      </table>
      <h4>Description</h4>
      <p>{{ finding.description }}</p>
      <h4>Proof of Concept</h4>
      <pre><code>{{ finding.poc_code }}</code></pre>
      <h4>Reproduction Steps</h4>
      <ol>{% for step in finding.reproduction_steps %}<li>{{ step }}</li>{% endfor %}</ol>
      <h4>Remediation</h4>
      <p>{{ finding.remediation }}</p>
    </div>
    {% endfor %}
  </section>

  <section id="appendix">
    <h2>Appendix: HTTP Evidence</h2>
    {% for req in report.appendix_requests %}
    <div class="http-evidence">
      <h4>{{ req.finding_title }}</h4>
      <pre class="request">{{ req.request }}</pre>
      <pre class="response">{{ req.response }}</pre>
    </div>
    {% endfor %}
  </section>
</body>
</html>
```

---

## PDF Generation (WeasyPrint)

```python
# backend/reports/pdf_renderer.py
from weasyprint import HTML, CSS
import tempfile, os

class PDFRenderer:
    def render(self, html_content: str) -> bytes:
        """Convert HTML report to PDF using WeasyPrint (no headless Chrome needed)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            html = HTML(string=html_content, base_url=tmpdir)
            css = CSS(string=self._get_print_css())
            return html.write_pdf(stylesheets=[css])

    def _get_print_css(self) -> str:
        return """
@page {
    size: A4;
    margin: 2cm 1.5cm;
    @top-center {
        content: "AutoPentest Security Report — CONFIDENTIAL";
        font-size: 9pt;
        color: #666;
    }
    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 9pt;
    }
}
.finding { page-break-inside: avoid; }
pre { white-space: pre-wrap; font-size: 8pt; background: #f5f5f5; padding: 8px; }
.severity-badge { padding: 2px 8px; border-radius: 3px; color: white; font-weight: bold; }
"""
```

---

## Executive Summary AI Prompt

```python
EXECUTIVE_SUMMARY_PROMPT = """
You are writing the executive summary for a security assessment report.
The audience is senior management and non-technical stakeholders.

Assessment target: {target_url}
Assessment scope: {scope}
Scan date: {scan_date}

Findings summary:
- Critical: {critical_count} findings
- High: {high_count} findings  
- Medium: {medium_count} findings
- Low: {low_count} findings
- Total verified: {verified_count}

Most significant findings:
{top_findings_json}

Write a 2-3 paragraph executive summary that:
1. States the overall security posture and risk level (Critical/High/Medium/Low)
2. Highlights the most impactful findings in non-technical language
3. Provides a clear, actionable recommendation

Do NOT use technical jargon. Do NOT mention specific CVE IDs or CWE numbers.
Use plain language that a CEO can understand.
Keep the summary under 300 words.
"""
```

---

## Report Generation Celery Task

```python
# backend/workers/tasks/report_tasks.py
@celery_app.task(
    queue="report",
    bind=True,
    max_retries=3,
    soft_time_limit=600,
    time_limit=660,
)
def generate_report(self, report_job_id: str):
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_async_generate_report(report_job_id))
    finally:
        loop.close()

async def _async_generate_report(report_job_id: str):
    async with get_db_session() as db:
        job = await db.get(ReportJob, report_job_id)
        await db.execute(update(ReportJob).where(ReportJob.id == report_job_id)
                         .values(status="generating"))
        await db.commit()

        try:
            # Collect data
            findings = await FindingService(db).get_for_report(
                project_id=job.project_id,
                scan_id=job.scan_id,
                config=job.config
            )

            # Generate executive summary via AI
            ai_client = await ModelManager().get_client(db)
            exec_summary = await generate_executive_summary(ai_client, findings, job.config)

            report_data = await build_report_data(findings, exec_summary, job, db)

            # Render in requested format
            if job.format == "html":
                content = HTMLReportRenderer().render(report_data, job.config.get("audience", "technical"))
                file_ext = "html"
                content_bytes = content.encode()
            elif job.format == "pdf":
                html_content = HTMLReportRenderer().render(report_data, job.config.get("audience", "technical"))
                content_bytes = PDFRenderer().render(html_content)
                file_ext = "pdf"
            elif job.format == "json":
                content_bytes = JSONReportRenderer().render(report_data).encode()
                file_ext = "json"

            # Store
            file_path = await EvidenceStore().store_report(
                content_bytes,
                filename=f"report-{job.project_id}-{datetime.now().strftime('%Y%m%d')}.{file_ext}"
            )

            await db.execute(update(ReportJob).where(ReportJob.id == report_job_id).values(
                status="complete",
                file_path=file_path,
                file_size_bytes=len(content_bytes),
                completed_at=datetime.utcnow()
            ))

        except Exception as e:
            await db.execute(update(ReportJob).where(ReportJob.id == report_job_id).values(
                status="failed", error=str(e)
            ))
            raise
```
