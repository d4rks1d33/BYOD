# AutoPentest — System Architecture

## Overview

AutoPentest is a self-hosted, air-gapped-capable AI security testing platform combining DAST, SAST, and multi-agent AI orchestration into a unified, offline-first tool. It is designed for authorized penetration testing engagements by security analysts.

---

## System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              PUBLIC / ANALYST TIER                               │
│                                                                                  │
│   Browser ──HTTPS──► Next.js 14 Frontend (port 3000)                           │
│                              │ API calls / WebSocket                            │
└──────────────────────────────┼──────────────────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────────────────┐
│                              APPLICATION TIER                                    │
│                                                                                  │
│   FastAPI Backend (port 8000)                                                   │
│   ├── REST API (JWT/API-key auth)                                               │
│   ├── WebSocket Hub (live scan events)                                          │
│   ├── BFF (Backend-for-Frontend) endpoints                                      │
│   └── Background task dispatch → Redis queues                                   │
│                                                                                  │
└──────────┬──────────────────────────────────────────┬───────────────────────────┘
           │                                          │
┌──────────▼──────────────────┐   ┌──────────────────▼──────────────────────────┐
│       STORAGE TIER          │   │                 WORKER TIER                  │
│                             │   │                                              │
│  PostgreSQL 15 + pgvector   │   │  queue.dast   → worker-scan (4 CPU, 4GB)   │
│  ├── Projects, Scans        │   │  queue.sast   → worker-scan (4 CPU, 4GB)   │
│  ├── Findings, Evidence     │   │  queue.ai     → worker-ai  (GPU + 24GB)    │
│  ├── Users, RBAC            │   │  queue.report → worker-rpt (2 CPU, 2GB)    │
│  ├── Audit Logs             │   │  queue.default→ worker-scan (shared)        │
│  └── Vector embeddings      │   │                                              │
│                             │   │  Each worker type runs in its own           │
│  Redis 7.2                  │   │  Docker service with resource limits        │
│  ├── Celery broker          │   │                                              │
│  ├── Result backend         │   └──────────────┬───────────────────────────────┘
│  ├── WS pub/sub             │                  │
│  ├── Rate limit counters    │   ┌──────────────▼───────────────────────────────┐
│  └── Scan state cache       │   │               AI/LLM TIER                    │
│                             │   │                                              │
└─────────────────────────────┘   │  llama-cpp-python (local .gguf model)       │
                                  │  ├── Model: llama3-8b-instruct.Q4_K_M.gguf  │
┌─────────────────────────────┐   │  ├── Or: Ollama REST API (local)            │
│       SANDBOX TIER          │   │  └── Or: vLLM (OpenAI-compat endpoint)      │
│                             │   │                                              │
│  sandbox-proxy service      │   │  nomic-embed-text (via Ollama)              │
│  ├── Docker-in-Docker or    │   │  └── For RAG embeddings (vector search)     │
│  │   host socket proxy      │   │                                              │
│  ├── Per-scan containers    │   └──────────────────────────────────────────────┘
│  │   (Playwright workers)   │
│  ├── Firejail profiles for  │   ┌──────────────────────────────────────────────┐
│  │   CLI tools              │   │            TOOL EXECUTION TIER               │
│  └── Network isolation      │   │                                              │
│      per container          │   │  Nuclei, ffuf, katana, Semgrep, CodeQL,     │
│                             │   │  trufflehog, OWASP ZAP, Burp Suite API      │
└─────────────────────────────┘   │                                              │
                                  │  All wrapped in Firejail + Docker            │
                                  │  sandboxes; output normalized before         │
                                  │  storage                                     │
                                  │                                              │
                                  └──────────────────────────────────────────────┘
```

---

## Data Flow: Key Scenarios

### A. Creating a Project and Starting a Scan

```
1. Analyst fills 5-step wizard → POST /api/projects (FastAPI)
2. FastAPI validates scope, creates project record in PostgreSQL
3. Analyst clicks "Start Scan" → POST /api/projects/{id}/scans
4. FastAPI creates scan record (status=pending), dispatches Celery chord:
   chain(run_recon, run_auth, run_api_agent) | group(run_dast, run_sast) | run_correlation | run_report
5. Redis receives the job chain; worker-scan picks up run_recon task
6. worker-scan creates AgentContext in scan_checkpoints table
7. AgentContext propagates through agents via DB reads/writes (NOT task args)
8. FastAPI WebSocket broadcasts scan.started event to connected browser
9. Browser xterm.js receives log stream via WS → renders in live console
```

### B. AI Agent Generating an Exploit Payload

```
1. Celery task run_exploit_agent wakes on worker-ai (GPU queue)
2. Agent reads AgentContext from scan_checkpoints (has discovered endpoints, auth tokens)
3. Agent calls llama-cpp-python with system prompt (role/goal/backstory/tools)
4. LLM returns tool_call: test_payload(url, method, params, payload)
5. Agent validates payload against scope allowlist + destructive pattern blocklist
6. Agent sends payload via httpx inside Docker sandbox container
7. Response fed back to LLM: "observe_response result: {status, body, timing}"
8. LLM evaluates response, decides to escalate or try next payload
9. If confirmed finding: agent calls report_finding(evidence) tool
10. Finding stored in PostgreSQL with dedup_hash check; WS broadcasts finding.new event
```

### C. SAST+DAST Finding Correlation

```
1. CorrelationAgent task wakes after both DAST and SAST agents complete (chord callback)
2. Loads all SAST findings for this scan (with file paths, function names, sink types)
3. Loads all DAST findings for this scan (with endpoint URLs, parameters, CWE IDs)
4. Tier 1: Normalize framework routes (Express/:id → /api/users/{id}) vs DAST URLs
5.   → Exact match found: SQLi sink getUserById ↔ DAST SQLi at /api/users/123
6. Tier 2: Semantic similarity via pgvector cosine search on finding embeddings
7. Correlated pairs stored as CorrelatedFinding records with confidence score
8. Confidence < 0.6: flagged for analyst review, not auto-unified
```

---

## Complete Folder Structure

```
autopentest/
├── frontend/                          # Next.js 14 App Router application
│   ├── app/                           # Next.js App Router pages
│   │   ├── (auth)/                    # Auth layout group
│   │   │   ├── login/page.tsx
│   │   │   └── register/page.tsx
│   │   ├── (app)/                     # Main app layout group
│   │   │   ├── layout.tsx             # App shell (sidebar, topnav)
│   │   │   ├── projects/
│   │   │   │   ├── page.tsx           # Projects list
│   │   │   │   ├── new/
│   │   │   │   │   └── page.tsx       # Wizard (5 steps)
│   │   │   │   └── [id]/
│   │   │   │       ├── layout.tsx     # Project layout (subnav)
│   │   │   │       ├── page.tsx       # Project dashboard
│   │   │   │       ├── scan/page.tsx  # Live scan console
│   │   │   │       ├── findings/
│   │   │   │       │   ├── page.tsx   # Findings browser
│   │   │   │       │   └── [fid]/page.tsx  # Finding detail
│   │   │   │       ├── reports/
│   │   │   │       │   ├── page.tsx
│   │   │   │       │   ├── new/page.tsx
│   │   │   │       │   └── [rid]/page.tsx
│   │   │   │       ├── evidence/page.tsx
│   │   │   │       └── settings/page.tsx
│   │   │   └── settings/
│   │   │       ├── layout.tsx
│   │   │       ├── models/page.tsx    # AI model config
│   │   │       ├── users/page.tsx     # RBAC user management
│   │   │       └── plugins/page.tsx   # Plugin management
│   │   └── api/                       # Next.js API routes (BFF proxy)
│   │       ├── auth/[...nextauth]/route.ts
│   │       └── proxy/[...path]/route.ts  # Proxies to FastAPI
│   ├── components/
│   │   ├── ui/                        # shadcn/ui base components (auto-generated)
│   │   ├── layout/
│   │   │   ├── AppSidebar.tsx
│   │   │   ├── ProjectSubnav.tsx
│   │   │   └── TopNav.tsx
│   │   ├── projects/
│   │   │   ├── ProjectCard.tsx
│   │   │   ├── ProjectStatusBadge.tsx
│   │   │   └── CreateProjectWizard/
│   │   │       ├── WizardStepper.tsx
│   │   │       ├── Step1TargetType.tsx
│   │   │       ├── Step2TargetConfig.tsx
│   │   │       ├── Step3AuthConfig.tsx
│   │   │       ├── Step4ScanConfig.tsx
│   │   │       └── Step5Review.tsx
│   │   ├── dashboard/
│   │   │   ├── StatsRow.tsx
│   │   │   ├── AttackSurfaceTreemap.tsx
│   │   │   ├── FindingsTimeline.tsx
│   │   │   ├── AgentStatusCard.tsx
│   │   │   └── ScanHistoryTable.tsx
│   │   ├── scan/
│   │   │   ├── ScanTerminal.tsx       # xterm.js wrapper
│   │   │   ├── ScanPhaseTracker.tsx
│   │   │   ├── LiveStatsGrid.tsx
│   │   │   ├── HttpInterceptorTable.tsx
│   │   │   └── ScanControls.tsx
│   │   ├── findings/
│   │   │   ├── FindingsTable.tsx
│   │   │   ├── FindingsFilterSidebar.tsx
│   │   │   ├── FindingCard.tsx
│   │   │   ├── SeverityBadge.tsx
│   │   │   ├── EvidenceViewer.tsx
│   │   │   ├── SastCorrelationPanel.tsx
│   │   │   └── RemediationCard.tsx
│   │   ├── reports/
│   │   │   ├── ReportCard.tsx
│   │   │   ├── ReportRenderer.tsx
│   │   │   └── ExportBar.tsx
│   │   └── common/
│   │       ├── CodeBlock.tsx          # Syntax-highlighted code block
│   │       ├── HttpTransactionSheet.tsx
│   │       ├── MetricCard.tsx
│   │       └── MultiValueInput.tsx    # Tag-input for URL lists
│   ├── lib/
│   │   ├── api/                       # API client functions (typed)
│   │   │   ├── projects.ts
│   │   │   ├── scans.ts
│   │   │   ├── findings.ts
│   │   │   └── reports.ts
│   │   ├── websocket.ts               # WS client + reconnect logic
│   │   └── utils.ts
│   ├── hooks/
│   │   ├── useScan.ts                 # React Query + WS combined
│   │   ├── useFindings.ts
│   │   └── useWebSocket.ts
│   ├── stores/
│   │   ├── useScanStore.ts            # Zustand: active scan state
│   │   ├── useProjectStore.ts
│   │   ├── useWebSocketStore.ts
│   │   ├── useAIModelStore.ts
│   │   └── useNotificationStore.ts
│   ├── types/
│   │   ├── api.ts                     # API response types (generated from OpenAPI)
│   │   ├── scan.ts
│   │   └── finding.ts
│   ├── next.config.ts
│   ├── tailwind.config.ts
│   └── package.json
│
├── backend/                           # FastAPI Python 3.12 application
│   ├── api/
│   │   ├── __init__.py
│   │   ├── main.py                    # FastAPI app factory
│   │   ├── routers/
│   │   │   ├── auth.py               # POST /auth/login, /refresh, /logout
│   │   │   ├── projects.py           # CRUD /projects
│   │   │   ├── scans.py              # Scan lifecycle
│   │   │   ├── findings.py           # Findings CRUD + verification
│   │   │   ├── evidence.py           # Evidence retrieval + replay
│   │   │   ├── reports.py            # Report generation + download
│   │   │   ├── ai_models.py          # AI model config
│   │   │   ├── plugins.py            # Plugin management
│   │   │   ├── users.py              # User management + RBAC
│   │   │   ├── audit.py              # Audit log query
│   │   │   └── websocket.py          # WS /ws/scans/{id}/live
│   │   ├── dependencies/
│   │   │   ├── auth.py               # get_current_user, require_role
│   │   │   ├── db.py                 # get_db async session
│   │   │   └── rbac.py               # permission_required decorator
│   │   └── middleware/
│   │       ├── audit.py              # Auto-audit on mutating requests
│   │       ├── rate_limit.py         # Redis-backed rate limiting
│   │       └── security_headers.py   # HSTS, CSP, X-Frame-Options
│   ├── core/
│   │   ├── config.py                 # Pydantic Settings (env vars)
│   │   ├── database.py               # Async SQLAlchemy engine + session
│   │   ├── redis_client.py           # Redis connection pool
│   │   ├── security.py               # Password hashing, JWT encode/decode
│   │   └── encryption.py             # AES-256-GCM field encryption
│   ├── models/                        # SQLAlchemy ORM models (one per table)
│   │   ├── user.py
│   │   ├── project.py
│   │   ├── scan.py
│   │   ├── finding.py
│   │   ├── evidence.py
│   │   ├── audit_log.py
│   │   ├── plugin.py
│   │   ├── ai_model_config.py
│   │   └── report_job.py
│   ├── schemas/                       # Pydantic v2 request/response schemas
│   │   ├── auth.py
│   │   ├── project.py
│   │   ├── scan.py
│   │   ├── finding.py
│   │   └── report.py
│   ├── services/                      # Business logic (called by routers)
│   │   ├── scan_service.py           # Scan orchestration, Celery dispatch
│   │   ├── finding_service.py        # Finding CRUD, dedup logic
│   │   ├── evidence_service.py
│   │   ├── report_service.py
│   │   └── user_service.py
│   ├── workers/                       # Celery worker app + task definitions
│   │   ├── celery_app.py             # Celery app factory with queue config
│   │   ├── tasks/
│   │   │   ├── dast_tasks.py         # run_dast_crawl, run_dast_fuzz, etc.
│   │   │   ├── sast_tasks.py         # clone_repo, run_semgrep, etc.
│   │   │   ├── ai_tasks.py           # run_agent_*, run_llm_inference
│   │   │   └── report_tasks.py       # generate_html/pdf/json_report
│   │   └── orchestrator.py           # Builds Celery chain/chord scan workflow
│   ├── agents/                        # AI agent implementations
│   │   ├── base.py                   # BaseAgent ABC, AgentContext, AgentTool
│   │   ├── recon.py                  # ReconAgent
│   │   ├── auth.py                   # AuthAgent
│   │   ├── api_agent.py              # APIAgent (OpenAPI/GraphQL/Postman)
│   │   ├── exploit.py                # ExploitAgent
│   │   ├── code_review.py            # CodeReviewAgent (SAST contextual)
│   │   ├── correlation.py            # CorrelationAgent
│   │   └── report.py                 # ReportAgent
│   ├── engines/
│   │   ├── dast/
│   │   │   ├── crawler.py            # Playwright-based JS-aware crawler
│   │   │   ├── fuzzer.py             # Parameter mutation engine
│   │   │   ├── auth_flow.py          # Multi-step auth handler
│   │   │   ├── payload_library.py    # Curated payloads by vuln type
│   │   │   └── response_analyzer.py  # Response diff, error detection
│   │   ├── sast/
│   │   │   ├── repo_manager.py       # Clone, detect language, build
│   │   │   ├── context_manager.py    # File prioritization, chunking
│   │   │   ├── sink_detector.py      # AST-based sink/source tracking
│   │   │   └── output_normalizer.py  # Normalize Semgrep/CodeQL output
│   │   └── correlation/
│   │       ├── engine.py             # CorrelationEngine (3-tier matching)
│   │       ├── route_normalizer.py   # Framework route → canonical form
│   │       └── embedder.py           # Batch embedding for semantic match
│   ├── integrations/                  # External tool wrappers
│   │   ├── nuclei.py
│   │   ├── semgrep.py
│   │   ├── codeql.py
│   │   ├── ffuf.py
│   │   ├── katana.py
│   │   ├── zap.py
│   │   ├── burp.py
│   │   └── trufflehog.py
│   ├── sandbox/
│   │   ├── docker_sandbox.py         # Docker SDK wrapper for per-scan isolation
│   │   ├── firejail_profiles/        # .profile files per tool
│   │   │   ├── nuclei.profile
│   │   │   ├── ffuf.profile
│   │   │   └── semgrep.profile
│   │   └── network_policy.py         # Block internal IPs from scan networks
│   ├── llm/
│   │   ├── base_client.py            # Abstract LLM client
│   │   ├── llamacpp_client.py        # llama-cpp-python backend
│   │   ├── ollama_client.py          # Ollama REST client
│   │   ├── vllm_client.py            # vLLM OpenAI-compat client
│   │   ├── model_manager.py          # Hot-swap, load, unload models
│   │   └── rag/
│   │       ├── vector_store.py       # pgvector queries
│   │       ├── embedder.py           # nomic-embed-text via Ollama
│   │       ├── ingestion.py          # Ingest CVE/CWE/patterns into vector store
│   │       └── retriever.py          # RAG query → formatted context
│   ├── plugins/
│   │   ├── base_plugin.py            # AbstractPlugin with all lifecycle hooks
│   │   ├── registry.py               # Plugin loader, sandbox runner
│   │   ├── manifest_schema.py        # Plugin manifest JSON schema validation
│   │   └── builtin/                  # Bundled first-party plugins
│   │       ├── nuclei_templates.py
│   │       └── custom_payloads.py
│   ├── reports/
│   │   ├── html_renderer.py          # Jinja2 HTML report
│   │   ├── pdf_renderer.py           # WeasyPrint PDF
│   │   ├── json_renderer.py          # Structured JSON report
│   │   ├── markdown_renderer.py
│   │   └── templates/
│   │       ├── technical_report.html.j2
│   │       └── executive_report.html.j2
│   ├── storage/
│   │   ├── evidence_store.py         # Encrypted filesystem evidence storage
│   │   └── s3_backend.py             # Optional S3-compatible (MinIO) backend
│   └── migrations/                    # Alembic migration files
│       ├── env.py
│       ├── script.py.mako
│       └── versions/
│           └── 0001_initial_schema.py
│
├── docker/
│   ├── Dockerfile.frontend            # Node 20 Alpine, builds Next.js
│   ├── Dockerfile.api                 # Python 3.12-slim, installs backend deps
│   ├── Dockerfile.worker              # Python 3.12-slim + security tools
│   ├── Dockerfile.worker-ai           # Python 3.12 + CUDA + llama-cpp-python
│   └── Dockerfile.tools               # Security tools installer base image
│
├── docker-compose.yml                 # Production compose
├── docker-compose.dev.yml             # Dev override (hot reload, dev DBs)
│
├── scripts/
│   ├── setup.sh                       # First-run setup (DB init, tool check)
│   ├── install-tools.sh               # Install Nuclei, ffuf, katana, etc.
│   ├── seed-db.py                     # Seed admin user, default model config
│   ├── update-nuclei-templates.sh     # Offline template sync
│   ├── update-semgrep-rules.sh        # Offline ruleset sync
│   └── backup.sh                      # PostgreSQL backup + evidence archive
│
└── docs/                              # This documentation
    ├── 01-ARCHITECTURE.md             # (this file)
    ├── 02-DATABASE.md
    ├── 03-API.md
    ├── 04-FRONTEND.md
    ├── 05-AI-AGENTS.md
    ├── 06-DAST-PIPELINE.md
    ├── 07-SAST-PIPELINE.md
    ├── 08-CORRELATION.md
    ├── 09-TOOLS.md
    ├── 10-SECURITY.md
    ├── 11-THREAT-MODEL.md
    ├── 12-REPORTING.md
    ├── 13-OBSERVABILITY.md
    └── 14-ROADMAP.md
```

---

## Docker Compose Service Topology

| Service | Image/Build | Purpose | Ports | GPU | Key Env Vars |
|---------|------------|---------|-------|-----|-------------|
| `frontend` | `docker/Dockerfile.frontend` | Next.js app | `3000:3000` | No | `NEXT_PUBLIC_API_URL`, `NEXTAUTH_SECRET` |
| `api` | `docker/Dockerfile.api` | FastAPI backend | `8000:8000` | No | `DATABASE_URL`, `REDIS_URL`, `SECRET_KEY` |
| `worker-scan` | `docker/Dockerfile.worker` | Celery DAST/SAST workers | - | No | `CELERY_QUEUES=dast,sast,default` |
| `worker-ai` | `docker/Dockerfile.worker-ai` | Celery AI/LLM workers | - | Yes (NVIDIA) | `CELERY_QUEUES=ai`, `MODEL_PATH`, `N_GPU_LAYERS` |
| `worker-report` | `docker/Dockerfile.worker` | Report generation | - | No | `CELERY_QUEUES=report` |
| `postgres` | `pgvector/pgvector:pg15` | Primary database | `5432` (internal) | No | `POSTGRES_PASSWORD`, `POSTGRES_DB=autopentest` |
| `redis` | `redis:7.2-alpine` | Task queue + cache | `6379` (internal) | No | `--requirepass ${REDIS_PASSWORD}` |
| `sandbox-proxy` | `docker/Dockerfile.api` | Docker socket proxy (read/create/kill only) | Unix socket | No | `DOCKER_HOST` |
| `flower` (optional) | `mher/flower` | Celery task monitoring | `5555:5555` | No | `FLOWER_BASIC_AUTH` |

**Networks:**
- `frontend-net`: frontend ↔ api
- `api-net`: api ↔ workers ↔ postgres ↔ redis
- `sandbox-net`: per-scan container networks (ephemeral, created/destroyed per scan)

**Volumes:**
- `postgres-data`: PostgreSQL data directory
- `redis-data`: Redis AOF persistence
- `evidence-store`: Encrypted evidence files (shared api ↔ workers)
- `model-store`: .gguf model files (read-only mount to worker-ai)
- `tool-data`: Nuclei templates, Semgrep rules (read-only)

---

## Plugin Architecture

### Plugin Manifest (JSON Schema)

```json
{
  "$schema": "https://autopentest.local/schemas/plugin-manifest.json",
  "name": "custom-jwt-attack",
  "version": "1.0.0",
  "description": "Extends JWT testing with custom algorithm confusion payloads",
  "author": "analyst@company.com",
  "hooks": ["on_scan_start", "on_payload_generated", "on_finding"],
  "capabilities": ["dast_payload_injection", "finding_enrichment"],
  "permissions": {
    "network": false,
    "filesystem": false,
    "subprocess": false
  },
  "config_schema": {
    "type": "object",
    "properties": {
      "custom_keys_path": { "type": "string" }
    }
  },
  "entrypoint": "plugin.py",
  "min_platform_version": "1.0.0"
}
```

### Plugin Abstract Base Class

```python
from abc import ABC
from typing import Optional

class AbstractPlugin(ABC):
    name: str
    version: str

    def on_scan_start(self, scan_config: dict) -> Optional[dict]:
        """Called when a scan begins. Can modify scan config."""
        return None

    def on_finding(self, finding: dict) -> Optional[dict]:
        """Called when a finding is created. Can enrich or suppress."""
        return finding

    def on_scan_complete(self, scan_id: str, summary: dict) -> None:
        """Called when scan finishes. Read-only — for notifications."""
        pass

    def on_request_intercepted(self, request: dict) -> Optional[dict]:
        """Called before each HTTP request. Can modify headers/body."""
        return request

    def on_payload_generated(self, payload: str, context: dict) -> str:
        """Called when AI generates a payload. Can mutate it."""
        return payload

    def on_report_generated(self, report: dict) -> Optional[dict]:
        """Called before report is finalized. Can add custom sections."""
        return report
```

### Plugin Sandboxing

Plugins run in **RestrictedPython** with a locked-down execution environment:
- No `import os`, `subprocess`, `socket`, `sys` unless `permissions.network = true` declared
- No filesystem access beyond read-only `/tmp/plugin-data/{plugin_id}/`
- CPU time limit: 5 seconds per hook invocation
- Memory limit: 128MB per plugin process
- Plugins are loaded in a forked subprocess; exceptions are caught and logged without crashing the main worker

### Plugin Installation Flow

```
Upload ZIP → Validate manifest JSON schema → Extract to /tmp/plugin-staging/{id}/
→ Run plugin in test sandbox with mock scan_config → Capture output/exceptions
→ If passes: compute SHA-256 checksum → Insert into plugins table (enabled=false)
→ Admin enables plugin → Registry cache refreshed → Available in next scan
```

---

## Scalability Strategy

### Worker Auto-Scaling

```yaml
# docker-compose.yml resource constraints
worker-scan:
  deploy:
    replicas: 2  # Start with 2, scale to 8
    resources:
      limits:
        cpus: '4.0'
        memory: 4G
    update_config:
      parallelism: 1

# Celery autoscale config in celery_app.py
CELERY_WORKER_AUTOSCALE = "8,2"  # max 8, min 2 concurrent tasks
```

### Queue Depth-Based Scaling Signal

```python
# In api/routers/admin.py
def get_queue_depths() -> dict:
    r = redis_client.pipeline()
    for queue in ['dast', 'sast', 'ai', 'report']:
        r.llen(f"celery:{queue}")
    return dict(zip(['dast','sast','ai','report'], r.execute()))

# Expose as /api/admin/metrics/queues for external autoscaler (e.g., KEDA)
```

### Database Connection Pooling

```ini
# pgbouncer.ini (transaction pooling mode)
[databases]
autopentest = host=postgres port=5432 dbname=autopentest

[pgbouncer]
pool_mode = transaction
max_client_conn = 200
default_pool_size = 20
min_pool_size = 5
reserve_pool_size = 10
reserve_pool_timeout = 5
```

### Evidence Storage Scaling

```python
# storage/evidence_store.py — pluggable backend
class EvidenceStore:
    def __init__(self, backend: str = "local"):
        if backend == "local":
            self._backend = LocalEncryptedBackend("/data/evidence")
        elif backend == "s3":
            self._backend = S3Backend(endpoint=os.environ["S3_ENDPOINT"])

    async def store(self, evidence_type: str, data: bytes, metadata: dict) -> str:
        return await self._backend.write(data, metadata)
```

**Local → S3 migration**: Evidence paths in the DB are relative (e.g., `evidence/scan-123/req-456.bin`). The backend resolves the absolute path at read time, so swapping backends requires only a data copy + config change.

---

## Technology Stack Decision Summary

| Layer | Technology | Version | Why |
|-------|-----------|---------|-----|
| Frontend | Next.js | 14 (App Router) | Server Components + streaming; best DX for security dashboards |
| UI Components | shadcn/ui + Tailwind | latest | Unstyled primitives; dark mode; no opinionated design lock-in |
| State | Zustand + TanStack Query | 4.x / 5.x | Zustand for WS/scan state (ephemeral); TQ for server state (cache) |
| Terminal | xterm.js | 5.x | Industry standard for browser-based terminals; supports Unicode, colors |
| Backend | FastAPI | 0.111+ | Async-native; Pydantic v2; auto OpenAPI; best Python AI ecosystem access |
| ORM | SQLAlchemy 2.0 async | 2.0+ | Async-first; full type safety with Mapped[]; Alembic migrations |
| Workers | Celery + Redis | 5.x / 7.2 | Proven at scale; chord/group for DAG; visibility via Flower |
| Database | PostgreSQL 15 + pgvector | 15 / 0.7 | pgvector = no separate vector DB; JSON/JSONB for flexible configs |
| Local LLM | llama-cpp-python | 0.2+ | Best llama.cpp Python binding; supports CUDA/Metal/CPU |
| Embeddings | nomic-embed-text (Ollama) | 1.5 | 137M params; 768 dims; fast; runs on CPU; Apache licensed |
| PDF Reports | WeasyPrint | 62+ | Pure Python; CSS→PDF; no headless Chrome required |
| DAST Browser | Playwright | 1.42+ | Multi-browser; stealth mode available; async Python API |
| Secret Scanning | trufflehog v3 | 3.x | Best regex + semantic entropy patterns; git-native |
| Code Analysis | Semgrep | 1.x | SAST with 3000+ community rules; fast; multi-language |
