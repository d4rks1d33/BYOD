# AutoPentest — SAST+DAST Correlation Engine

## Design Overview

The correlation engine unifies findings from static analysis (code-level) and dynamic analysis (runtime-level) into richer, higher-confidence findings. A correlated finding provides:

1. **Code-level context**: where the vulnerability lives in the source code
2. **Runtime evidence**: proof that the vulnerability is exploitable at the endpoint
3. **Unified severity**: combining CVSS base score with code exploitability analysis
4. **Reduced noise**: many SAST false positives are eliminated when DAST cannot confirm them

---

## Data Structures

```python
# backend/engines/correlation/engine.py
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class SASTFinding:
    id: str                          # UUID from findings table
    file_path: str                   # "src/api/users.js"
    line_number: int                 # 45
    function_name: str               # "getUserById"
    sink_type: str                   # "sql_query", "exec", "render_template", etc.
    sink_code: str                   # Vulnerable code snippet
    taint_source: str                # "req.params.id" — where user input enters
    cwe_id: str                      # "CWE-89"
    severity: str
    framework_route: Optional[str]   # "/api/users/:id" if extractable from routing
    data_flow: list[str] = field(default_factory=list)  # AST path from source to sink
    embedding: Optional[list[float]] = None   # 768-dim nomic-embed-text vector

@dataclass
class DASTFinding:
    id: str
    endpoint_url: str                # "https://target.com/api/users/123"
    method: str                      # "GET"
    parameter: str                   # "id"
    parameter_location: str          # "path", "query", "header", "body"
    payload_used: str                # "' OR 1=1--"
    response_evidence: str           # Response snippet confirming injection
    cwe_id: str
    severity: str
    embedding: Optional[list[float]] = None

@dataclass
class CorrelatedFinding:
    sast_finding: SASTFinding
    dast_finding: DASTFinding
    correlation_score: float         # 0.0–1.0
    correlation_method: str          # "exact_route" | "semantic" | "cwe_param"
    confidence: str                  # "high" (>0.9), "medium" (0.6-0.9), "low" (<0.6)
    unified_title: str
    unified_severity: str            # May be escalated if both agree
    requires_review: bool            # True for low-confidence correlations
```

---

## 3-Tier Correlation Algorithm

### Tier 1: Exact Route Match (Confidence: 0.85–0.98)

Maps SAST framework routes to DAST endpoint URLs through normalization.

```python
class RouteNormalizer:
    """
    Normalizes routes from different frameworks to a canonical form.
    Canonical: lowercase, path segments, parameters as {param_name}
    """

    FRAMEWORK_PATTERNS = {
        # Express.js: /api/users/:id  →  /api/users/{id}
        "express": (r':([a-zA-Z_][a-zA-Z0-9_]*)', r'{\1}'),
        # FastAPI/Flask: /api/users/{id}  →  /api/users/{id} (already canonical)
        "fastapi": (r'\{([^}]+)\}', r'{\1}'),
        # Django: /api/users/<int:id>/  →  /api/users/{id}
        "django": (r'<(?:\w+:)?([^>]+)>', r'{\1}'),
        # Spring Boot: /api/users/{id}  →  already canonical
        "spring": (r'\{([^}]+)\}', r'{\1}'),
        # Laravel: /api/users/{id}  →  already canonical
        "laravel": (r'\{([^}?]+)\??}', r'{\1}'),
    }

    def normalize_sast_route(self, route: str) -> Optional[str]:
        """Convert framework-specific route to canonical form."""
        if not route:
            return None
        import re
        route = route.lower().rstrip('/')
        # Try each framework pattern
        for framework, (pattern, replacement) in self.FRAMEWORK_PATTERNS.items():
            route = re.sub(pattern, replacement, route)
        return route

    def normalize_dast_url(self, url: str) -> str:
        """Extract path from URL and normalize dynamic segments."""
        from urllib.parse import urlparse
        import re
        path = urlparse(url).path.lower().rstrip('/')
        # Normalize numeric IDs: /users/123 → /users/{id}
        path = re.sub(r'/\d{1,20}(?=/|$)', '/{id}', path)
        # Normalize UUIDs: /users/550e8400-... → /users/{uuid}
        path = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                      '/{uuid}', path)
        # Normalize base64-like tokens: /token/abc123XY → /token/{token}
        path = re.sub(r'/[A-Za-z0-9+/=]{20,}', '/{token}', path)
        return path


class CorrelationEngine:
    def __init__(self, embedding_client, db_session):
        self.embedder = embedding_client
        self.db = db_session
        self.normalizer = RouteNormalizer()
        self.SEMANTIC_THRESHOLD = 0.75
        self.CWE_FAMILIES = self._load_cwe_families()

    async def correlate(
        self,
        sast_findings: list[SASTFinding],
        dast_findings: list[DASTFinding]
    ) -> list[CorrelatedFinding]:

        correlated = []
        matched_sast_ids = set()
        matched_dast_ids = set()

        # ── TIER 1: Exact Route Match ──────────────────────────────────
        for sast in sast_findings:
            norm_sast_route = self.normalizer.normalize_sast_route(sast.framework_route)
            if not norm_sast_route:
                continue

            for dast in dast_findings:
                norm_dast_path = self.normalizer.normalize_dast_url(dast.endpoint_url)

                if norm_sast_route == norm_dast_path:
                    # CWE must match (exact or same family)
                    if self._cwe_compatible(sast.cwe_id, dast.cwe_id):
                        score = 0.95 if sast.cwe_id == dast.cwe_id else 0.85
                        correlated.append(self._build_correlation(
                            sast, dast, score, "exact_route"
                        ))
                        matched_sast_ids.add(sast.id)
                        matched_dast_ids.add(dast.id)

        # ── TIER 2: Semantic Similarity ────────────────────────────────
        unmatched_sast = [s for s in sast_findings if s.id not in matched_sast_ids]
        unmatched_dast = [d for d in dast_findings if d.id not in matched_dast_ids]

        if unmatched_sast and unmatched_dast:
            # Lazy-load embeddings (may already be in DB from when finding was stored)
            sast_texts = [
                f"{s.sink_type} vulnerability in {s.function_name} "
                f"taint source {s.taint_source} file {s.file_path.split('/')[-1]}"
                for s in unmatched_sast
            ]
            dast_texts = [
                f"{d.parameter} parameter injection at path "
                f"{self.normalizer.normalize_dast_url(d.endpoint_url)} "
                f"via {d.parameter_location}"
                for d in unmatched_dast
            ]

            sast_embeddings = await self.embedder.embed_batch(sast_texts)
            dast_embeddings = await self.embedder.embed_batch(dast_texts)

            sim_matrix = self._cosine_similarity_matrix(sast_embeddings, dast_embeddings)

            for i, sast in enumerate(unmatched_sast):
                for j, dast in enumerate(unmatched_dast):
                    sim = float(sim_matrix[i][j])
                    if (sim >= self.SEMANTIC_THRESHOLD
                            and self._cwe_compatible(sast.cwe_id, dast.cwe_id)
                            and dast.id not in matched_dast_ids):
                        correlated.append(self._build_correlation(
                            sast, dast, sim, "semantic_similarity"
                        ))
                        matched_sast_ids.add(sast.id)
                        matched_dast_ids.add(dast.id)

        # ── TIER 3: CWE + Parameter Name Match (low confidence) ─────────
        still_unmatched_sast = [s for s in sast_findings if s.id not in matched_sast_ids]
        still_unmatched_dast = [d for d in dast_findings if d.id not in matched_dast_ids]

        for sast in still_unmatched_sast:
            for dast in still_unmatched_dast:
                if (self._same_cwe_category(sast.cwe_id, dast.cwe_id)
                        and sast.taint_source.lower() == dast.parameter.lower()
                        and dast.id not in matched_dast_ids):
                    correlated.append(self._build_correlation(
                        sast, dast, 0.55, "cwe_param_match"
                    ))
                    matched_dast_ids.add(dast.id)

        return correlated

    def _build_correlation(
        self,
        sast: SASTFinding,
        dast: DASTFinding,
        score: float,
        method: str
    ) -> CorrelatedFinding:
        confidence = "high" if score > 0.9 else "medium" if score > 0.6 else "low"
        return CorrelatedFinding(
            sast_finding=sast,
            dast_finding=dast,
            correlation_score=score,
            correlation_method=method,
            confidence=confidence,
            unified_title=f"{dast.endpoint_url}: {sast.sink_type} confirmed at source",
            unified_severity=self._compute_unified_severity(sast, dast),
            requires_review=(confidence == "low")
        )

    def _compute_unified_severity(self, sast: SASTFinding, dast: DASTFinding) -> str:
        """
        Escalate severity if both agree, downgrade if only one side confirms.
        Correlated (SAST + DAST confirmed) is always at least one tier higher than
        DAST-only findings, because code-level analysis confirms the sink is reachable.
        """
        SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        sast_level = SEVERITY_ORDER.get(sast.severity, 2)
        dast_level = SEVERITY_ORDER.get(dast.severity, 2)
        # Take the maximum, escalate by 1 for confirmed correlation
        max_level = max(sast_level, dast_level)
        escalated = min(max_level + 1, 4)
        reverse_map = {v: k for k, v in SEVERITY_ORDER.items()}
        return reverse_map[escalated]

    def _cwe_compatible(self, cwe1: str, cwe2: str) -> bool:
        """Check if two CWEs belong to the same vulnerability family."""
        if cwe1 == cwe2:
            return True
        return self._same_cwe_category(cwe1, cwe2)

    def _same_cwe_category(self, cwe1: str, cwe2: str) -> bool:
        return (self.CWE_FAMILIES.get(cwe1) is not None
                and self.CWE_FAMILIES.get(cwe1) == self.CWE_FAMILIES.get(cwe2))

    def _load_cwe_families(self) -> dict[str, str]:
        """Map CWE IDs to their top-level category."""
        return {
            # Injection family
            "CWE-89": "injection", "CWE-564": "injection",
            "CWE-78": "injection", "CWE-88": "injection",
            "CWE-79": "xss", "CWE-80": "xss", "CWE-116": "xss",
            "CWE-918": "ssrf", "CWE-611": "xxe",
            "CWE-94": "code_injection", "CWE-95": "code_injection",
            "CWE-502": "deserialization", "CWE-915": "deserialization",
            "CWE-22": "path_traversal", "CWE-23": "path_traversal",
            "CWE-98": "file_inclusion",
            "CWE-284": "auth", "CWE-285": "auth", "CWE-287": "auth",
            "CWE-312": "secrets", "CWE-313": "secrets", "CWE-798": "secrets",
        }

    def _cosine_similarity_matrix(self, a: list, b: list):
        import numpy as np
        a_arr = np.array(a)
        b_arr = np.array(b)
        # Normalize
        a_norm = a_arr / (np.linalg.norm(a_arr, axis=1, keepdims=True) + 1e-8)
        b_norm = b_arr / (np.linalg.norm(b_arr, axis=1, keepdims=True) + 1e-8)
        return a_norm @ b_norm.T
```

---

## Framework Route Extraction

For SAST to populate `framework_route`, a pre-analysis step extracts routing information:

```python
# backend/engines/sast/route_extractor.py
class RouteExtractor:
    """
    Extracts route patterns from framework routing files.
    Runs before SAST analysis to populate framework_route on findings.
    """

    async def extract(self, repo_path: str, framework: str) -> dict[str, str]:
        """
        Returns: {function_name: route_pattern}
        e.g., {"getUserById": "/api/users/:id"}
        """
        extractors = {
            "express": self._extract_express,
            "fastapi": self._extract_fastapi,
            "django": self._extract_django,
            "spring": self._extract_spring,
            "laravel": self._extract_laravel,
            "nestjs": self._extract_nestjs,
        }
        extractor = extractors.get(framework)
        if not extractor:
            return {}
        return await extractor(repo_path)

    async def _extract_fastapi(self, repo_path: str) -> dict[str, str]:
        """
        Finds @router.get("/path/{param}") decorators above async def function_name
        """
        import ast, os
        routes = {}
        for root, _, files in os.walk(repo_path):
            for fname in files:
                if not fname.endswith('.py'):
                    continue
                path = os.path.join(root, fname)
                try:
                    tree = ast.parse(open(path).read())
                    for node in ast.walk(tree):
                        if isinstance(node, ast.FunctionDef):
                            for decorator in node.decorator_list:
                                if (isinstance(decorator, ast.Call)
                                        and hasattr(decorator.func, 'attr')
                                        and decorator.func.attr in ('get','post','put','delete','patch')):
                                    if decorator.args:
                                        route = ast.literal_eval(decorator.args[0])
                                        routes[node.name] = route
                except Exception:
                    pass
        return routes
```

---

## Correlation Agent Integration

```python
# backend/agents/correlation.py
class CorrelationAgent(BaseAgent):
    role = "Expert security analyst specializing in vulnerability correlation and root cause analysis"
    goal = "Unify SAST and DAST findings into correlated, high-confidence findings"

    async def run_correlation(self, scan_id: str, db) -> list[CorrelatedFinding]:
        from backend.engines.correlation.engine import CorrelationEngine
        from backend.services.finding_service import FindingService

        # Load all findings for this scan
        svc = FindingService(db)
        sast_findings = await svc.get_sast_findings(scan_id)
        dast_findings = await svc.get_dast_findings(scan_id)

        engine = CorrelationEngine(self.embedder, db)
        correlations = await engine.correlate(sast_findings, dast_findings)

        # Update findings in DB with correlation links
        for corr in correlations:
            await svc.link_correlation(
                sast_id=corr.sast_finding.id,
                dast_id=corr.dast_finding.id,
                score=corr.correlation_score,
                method=corr.correlation_method,
                unified_severity=corr.unified_severity
            )

        # Use LLM to write narrative for high-confidence correlations
        for corr in [c for c in correlations if c.confidence in ("high", "medium")]:
            narrative = await self._generate_correlation_narrative(corr)
            await svc.update_finding_description(corr.dast_finding.id, narrative)

        return correlations

    async def _generate_correlation_narrative(self, corr: CorrelatedFinding) -> str:
        prompt = f"""A security vulnerability has been confirmed through both static and dynamic analysis:

SAST finding: {corr.sast_finding.sink_type} sink in function {corr.sast_finding.function_name}
at {corr.sast_finding.file_path}:{corr.sast_finding.line_number}
Taint source: {corr.sast_finding.taint_source}
Vulnerable code: {corr.sast_finding.sink_code}

DAST finding: Exploitable at {corr.dast_finding.endpoint_url}
Parameter: {corr.dast_finding.parameter} ({corr.dast_finding.parameter_location})
Confirmed with payload: {corr.dast_finding.payload_used}

Write a technical description of this vulnerability (2-3 sentences) explaining:
1. What the vulnerability is and why it exists in the code
2. How it was confirmed at runtime
3. The potential impact"""

        response = await self.llm.generate(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=512,
            temperature=0.3
        )
        return response.content
```

---

## Deduplication Logic

```python
# backend/services/finding_service.py
import hashlib, json

class FindingService:
    def compute_dedup_hash(self, finding: dict) -> str:
        """
        Hash that identifies a unique finding regardless of which scan found it.
        DAST findings: hash endpoint + parameter + finding_type + cwe
        SAST findings: hash file_path + function_name + sink_type + cwe
        """
        if finding.get("endpoint_url"):
            # DAST finding
            key = {
                "type": "dast",
                "endpoint": finding["endpoint_url"],
                "method": finding.get("http_method", "").upper(),
                "parameter": finding.get("parameter", ""),
                "finding_type": finding["finding_type"],
                "cwe": finding.get("cwe_id", "")
            }
        else:
            # SAST finding
            key = {
                "type": "sast",
                "file": finding.get("source_file", ""),
                "line": finding.get("source_line", 0),
                "function": finding.get("source_function", ""),
                "finding_type": finding["finding_type"],
                "cwe": finding.get("cwe_id", "")
            }
        canonical = json.dumps(key, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()[:32]

    async def store_finding(self, finding: dict, project_id: str, scan_id: str, db) -> str:
        """
        Upsert finding by (project_id, dedup_hash).
        Returns finding ID (new or existing).
        """
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from backend.models.finding import Finding

        dedup_hash = self.compute_dedup_hash(finding)
        finding["dedup_hash"] = dedup_hash
        finding["project_id"] = project_id
        finding["scan_id"] = scan_id

        stmt = pg_insert(Finding).values(**finding)
        stmt = stmt.on_conflict_do_update(
            index_elements=["project_id", "dedup_hash"],
            set_={
                "scan_id": finding["scan_id"],   # Update to latest scan
                "updated_at": "now()"
                # Don't overwrite status, verified_by, etc.
            }
        ).returning(Finding.id)

        result = await db.execute(stmt)
        await db.commit()
        return str(result.scalar_one())
```
