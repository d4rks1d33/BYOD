# AutoPentest — Database Design

## PostgreSQL 15 + pgvector Schema

### Enums

```sql
-- Run in migration 0001
CREATE TYPE target_type_enum AS ENUM (
    'web_application', 'rest_api', 'graphql_api', 'repository', 'mobile_backend'
);

CREATE TYPE scan_type_enum AS ENUM (
    'dast', 'sast', 'dast_sast', 'recon_only', 'api_testing',
    'auth_testing', 'dependency_analysis', 'secret_scanning'
);

CREATE TYPE scan_status_enum AS ENUM (
    'pending', 'queued', 'running', 'paused', 'completed',
    'failed', 'cancelled', 'partial'
);

CREATE TYPE severity_enum AS ENUM (
    'critical', 'high', 'medium', 'low', 'info', 'unknown'
);

CREATE TYPE finding_status_enum AS ENUM (
    'new', 'verified', 'false_positive', 'fixed', 'accepted_risk'
);

CREATE TYPE confidence_enum AS ENUM ('high', 'medium', 'low');

CREATE TYPE evidence_type_enum AS ENUM (
    'http_request_response', 'screenshot', 'code_snippet',
    'payload', 'tool_output', 'har_file', 'stack_trace'
);

CREATE TYPE report_format_enum AS ENUM ('html', 'pdf', 'json', 'markdown', 'xlsx');

CREATE TYPE report_status_enum AS ENUM ('pending', 'generating', 'complete', 'failed');

CREATE TYPE system_role_enum AS ENUM ('super_admin', 'admin', 'analyst', 'viewer');

CREATE TYPE project_role_enum AS ENUM ('project_owner', 'project_analyst', 'project_viewer');

CREATE TYPE ai_provider_enum AS ENUM ('llama_cpp', 'ollama', 'vllm', 'openai_compat');
```

---

### Table: `users`

```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL UNIQUE,
    hashed_password TEXT NOT NULL,           -- bcrypt, cost 12
    full_name       TEXT NOT NULL,
    role            system_role_enum NOT NULL DEFAULT 'analyst',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    mfa_secret      TEXT,                    -- TOTP secret, encrypted at rest
    last_login_at   TIMESTAMPTZ,
    failed_logins   SMALLINT NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,             -- After 5 failed attempts
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_email ON users(email);
```

---

### Table: `projects`

```sql
CREATE TABLE projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT,
    target_url      TEXT NOT NULL,
    target_type     target_type_enum NOT NULL,
    owner_id        UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    -- Encrypted JSONB: auth credentials, custom headers, API keys
    -- Decrypted with per-project key derived from master key + project_id
    config          JSONB NOT NULL DEFAULT '{}',
    scope_urls      TEXT[] NOT NULL DEFAULT '{}',      -- Allowed scope prefixes
    exclude_patterns TEXT[] NOT NULL DEFAULT '{}',
    status          scan_status_enum NOT NULL DEFAULT 'pending',
    last_scan_at    TIMESTAMPTZ,
    archived_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_projects_owner ON projects(owner_id);
CREATE INDEX idx_projects_status ON projects(status);
CREATE INDEX idx_projects_archived ON projects(archived_at) WHERE archived_at IS NULL;
```

---

### Table: `project_members`

```sql
CREATE TABLE project_members (
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        project_role_enum NOT NULL DEFAULT 'project_viewer',
    added_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, user_id)
);

CREATE INDEX idx_project_members_user ON project_members(user_id);
```

---

### Table: `scans`

```sql
CREATE TABLE scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scan_type       scan_type_enum NOT NULL,
    status          scan_status_enum NOT NULL DEFAULT 'pending',
    -- Full scan config snapshot at time of scan creation (immutable)
    config          JSONB NOT NULL DEFAULT '{}',
    -- Runtime statistics updated by workers
    statistics      JSONB NOT NULL DEFAULT '{
        "requests_made": 0,
        "endpoints_found": 0,
        "findings_count": 0,
        "payloads_tested": 0,
        "errors_count": 0,
        "coverage_pct": 0
    }',
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    paused_at       TIMESTAMPTZ,
    error           TEXT,
    worker_id       TEXT,                   -- Celery worker hostname
    celery_task_id  TEXT,                   -- Root chord task ID
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_scans_project ON scans(project_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);
```

---

### Table: `findings`

```sql
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,         -- AI-generated narrative
    finding_type    TEXT NOT NULL,          -- e.g., 'sqli', 'xss', 'ssrf', 'secrets'
    severity        severity_enum NOT NULL,
    cvss_score      REAL,                   -- 0.0-10.0
    cvss_vector     TEXT,                   -- e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cwe_id          TEXT,                   -- e.g., "CWE-89"
    cve_ids         TEXT[] DEFAULT '{}',
    -- Endpoint details (DAST)
    endpoint_url    TEXT,
    http_method     TEXT,
    parameter       TEXT,
    parameter_location TEXT,                -- 'query', 'body', 'header', 'path'
    -- Code location (SAST)
    source_file     TEXT,
    source_line     INTEGER,
    source_function TEXT,
    sink_code       TEXT,
    -- Status management
    status          finding_status_enum NOT NULL DEFAULT 'new',
    confidence      confidence_enum NOT NULL DEFAULT 'medium',
    verified_at     TIMESTAMPTZ,
    verified_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    false_positive_at TIMESTAMPTZ,
    -- Deduplication (prevents duplicate findings from concurrent workers)
    dedup_hash      TEXT NOT NULL,
    -- Reproduction and remediation (AI-generated)
    reproduction_steps JSONB DEFAULT '[]',
    poc_code        TEXT,
    remediation     TEXT,
    -- Correlation
    correlated_finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
    correlation_score REAL,                 -- 0.0-1.0
    correlation_method TEXT,
    -- Vector embedding for semantic search and future RAG
    embedding       vector(768),            -- nomic-embed-text dimensions
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Deduplication: one finding per (project, dedup_hash)
CREATE UNIQUE INDEX idx_findings_dedup ON findings(project_id, dedup_hash);
CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_project_severity ON findings(project_id, severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_type ON findings(finding_type);
-- pgvector ANN index for semantic similarity search
CREATE INDEX idx_findings_embedding ON findings USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);
```

---

### Table: `evidence`

```sql
CREATE TABLE evidence (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id      UUID REFERENCES findings(id) ON DELETE SET NULL,  -- nullable: captured before dedup
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    evidence_type   evidence_type_enum NOT NULL,
    -- HTTP evidence (stored as text to enable search; large bodies truncated to 64KB)
    http_request    TEXT,
    http_response   TEXT,
    response_status INTEGER,
    response_time_ms INTEGER,
    -- Payload that triggered the finding
    payload         TEXT,
    -- File-based evidence (screenshots, HARs, etc.) — path is relative to evidence-store volume
    file_path       TEXT,
    file_size_bytes BIGINT,
    -- Tool output
    tool_name       TEXT,
    tool_output     TEXT,
    -- Additional context
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_evidence_finding ON evidence(finding_id);
CREATE INDEX idx_evidence_scan ON evidence(scan_id);
CREATE INDEX idx_evidence_type ON evidence(evidence_type);
```

---

### Table: `ai_model_configs`

```sql
CREATE TABLE ai_model_configs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    provider    ai_provider_enum NOT NULL,
    -- For llama_cpp: absolute path to .gguf file on server
    -- For ollama/vllm: model tag/id
    model_ref   TEXT NOT NULL,
    config      JSONB NOT NULL DEFAULT '{
        "temperature": 0.7,
        "context_size": 8192,
        "gpu_layers": -1,
        "threads": 8,
        "top_p": 0.95,
        "top_k": 40,
        "max_tokens": 2048
    }',
    -- llama_cpp-specific
    ollama_host TEXT DEFAULT 'http://ollama:11434',
    vllm_base_url TEXT,
    -- Encrypted API key for OpenAI-compat providers
    api_key_enc TEXT,
    is_active   BOOLEAN NOT NULL DEFAULT false,
    is_default  BOOLEAN NOT NULL DEFAULT false,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Enforce single default model
CREATE UNIQUE INDEX idx_ai_model_default ON ai_model_configs(is_default)
    WHERE is_default = true;
```

---

### Table: `plugins`

```sql
CREATE TABLE plugins (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    version         TEXT NOT NULL,
    manifest        JSONB NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT false,
    -- Plugin-specific configuration (validated against manifest.config_schema)
    config          JSONB DEFAULT '{}',
    -- File path to extracted plugin directory (relative to plugin-store volume)
    plugin_path     TEXT NOT NULL,
    checksum        TEXT NOT NULL,          -- SHA-256 of uploaded ZIP
    installed_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    installed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT,                   -- Last sandbox execution error
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

### Table: `audit_logs`

```sql
CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Actor (null for system actions)
    actor_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_email     TEXT,                   -- Denormalized for log integrity
    -- Action
    action          TEXT NOT NULL,          -- e.g., 'project.create', 'scan.start', 'finding.verify'
    resource_type   TEXT NOT NULL,          -- e.g., 'project', 'scan', 'finding'
    resource_id     UUID,
    -- Context
    details         JSONB DEFAULT '{}',     -- Before/after for updates; params for creates
    ip_address      INET,
    user_agent      TEXT,
    request_id      TEXT,                   -- Correlation with HTTP request
    -- Tamper detection: hash of (prev_hash || this_record_json)
    chain_hash      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (created_at);

-- Monthly partitions (auto-managed by pg_partman in production)
CREATE TABLE audit_logs_2026_05 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

CREATE INDEX idx_audit_created ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_actor ON audit_logs(actor_id);
CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_action ON audit_logs(action);
```

---

### Table: `api_tokens`

```sql
CREATE TABLE api_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    -- SHA-256 hash of the actual token (token shown to user only once at creation)
    token_hash  TEXT NOT NULL UNIQUE,
    scopes      TEXT[] NOT NULL DEFAULT '{}', -- e.g., ['scans:read', 'findings:read']
    last_used_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_api_tokens_user ON api_tokens(user_id);
CREATE INDEX idx_api_tokens_hash ON api_tokens(token_hash);
```

---

### Table: `scan_checkpoints`

```sql
-- Enables pause/resume: stores agent execution state at each phase
CREATE TABLE scan_checkpoints (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    phase       TEXT NOT NULL,              -- Agent name: 'recon', 'auth', 'dast', etc.
    -- Full AgentContext serialized as JSON (does NOT contain secrets — those are in projects.config)
    state       JSONB NOT NULL DEFAULT '{}',
    version     INTEGER NOT NULL DEFAULT 0, -- Incremented on every update
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_checkpoints_scan_phase ON scan_checkpoints(scan_id, phase);
```

---

### Table: `report_jobs`

```sql
CREATE TABLE report_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scan_id         UUID REFERENCES scans(id) ON DELETE SET NULL,
    format          report_format_enum NOT NULL,
    status          report_status_enum NOT NULL DEFAULT 'pending',
    -- Config: which sections to include, audience (technical/executive), etc.
    config          JSONB DEFAULT '{}',
    -- Relative path in evidence store once generated
    file_path       TEXT,
    file_size_bytes BIGINT,
    error           TEXT,
    celery_task_id  TEXT,
    requested_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_report_jobs_project ON report_jobs(project_id);
```

---

### Row-Level Security (RLS) Policies

```sql
-- Enable RLS on all tenant-scoped tables
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;

-- Application sets this at session start via a custom parameter
-- In SQLAlchemy: event.listen(engine, "after_begin", set_app_user)
-- async def set_app_user(conn, branch, is_real_trans):
--     await conn.execute(text(f"SET LOCAL app.current_user_id = '{user_id}'"))

-- Projects: visible if owner OR project_member
CREATE POLICY project_isolation ON projects
    FOR ALL TO app_user
    USING (
        owner_id = current_setting('app.current_user_id')::uuid
        OR id IN (
            SELECT project_id FROM project_members
            WHERE user_id = current_setting('app.current_user_id')::uuid
        )
    );

-- Scans: visible if project is visible (inherits project policy)
CREATE POLICY scan_isolation ON scans
    FOR ALL TO app_user
    USING (
        project_id IN (
            SELECT id FROM projects  -- RLS on projects applies here too
        )
    );

-- Findings: same isolation as scans
CREATE POLICY finding_isolation ON findings
    FOR ALL TO app_user
    USING (
        project_id IN (SELECT id FROM projects)
    );
```

---

## Redis Data Structures

| Key Pattern | Type | Content | TTL | Usage |
|-------------|------|---------|-----|-------|
| `celery:dast` | List | Celery serialized task payloads | - | DAST job queue |
| `celery:sast` | List | Celery serialized task payloads | - | SAST job queue |
| `celery:ai` | List | Celery serialized task payloads | - | AI/LLM job queue |
| `celery:report` | List | Celery serialized task payloads | - | Report generation queue |
| `scan:state:{scan_id}` | Hash | `{phase, progress_pct, requests_made, findings_count, status}` | 24h | Live scan stats cache (worker writes, API reads) |
| `scan:log:{scan_id}` | Stream | `{ts, level, agent, message}` | 24h | Log stream; WebSocket hub reads via XREAD |
| `ws:pubsub:project:{id}` | Pub/Sub | `{event_type, payload}` JSON | - | Fan-out to all browsers watching this project |
| `ws:subs:{scan_id}` | Set | Session IDs of connected browsers | 1h | Track active WebSocket subscribers |
| `ratelimit:{scan_id}:{target_host}` | String (counter) | Request count in current window | TTL = window size | Enforce per-target rate limit |
| `ratelimit:api:{user_id}` | String (counter) | API request count per minute | 60s | API rate limiting |
| `auth:refresh:{token_family_id}` | Hash | `{user_id, issued_at, consumed}` | 30d | Refresh token family (RFC rotation) |
| `model:inference:cache:{prompt_hash}` | String | JSON inference result | 1h | Cache repeated identical prompts |
| `plugin:registry` | Hash | `{plugin_name: manifest_json}` | No TTL (invalidated on change) | In-memory plugin registry cache |
| `scan:heartbeat:{scan_id}` | String | Worker hostname + timestamp | 90s | Stall detection: if key expires, scan is stalled |

---

## Database Migration Strategy

### Tool: Alembic + Async SQLAlchemy

```python
# migrations/env.py
from sqlalchemy.ext.asyncio import create_async_engine
from alembic import context

target_metadata = Base.metadata

def run_migrations_online():
    connectable = create_async_engine(config.get_main_option("sqlalchemy.url"))
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
```

### Naming Convention

```
NNNN_description_in_snake_case.py
# Examples:
0001_initial_schema.py
0002_add_correlation_fields_to_findings.py
0003_add_pgvector_embeddings.py
```

### Zero-Downtime Migration Rules

1. **Additive changes** (new columns, new tables) — deploy without downtime. New columns must be nullable or have defaults.
2. **Column renames** — two-step: (a) add new column + copy data in background, (b) update app to use new name, (c) drop old column in next deployment.
3. **Column type changes** — same two-step. Never ALTER TYPE on a large table directly.
4. **Index creation** — always `CREATE INDEX CONCURRENTLY` to avoid table lock.
5. **Constraint additions** — add as `NOT VALID`, then `VALIDATE CONSTRAINT` in a separate migration.

### Seed Data

```python
# scripts/seed_db.py
async def seed():
    # Default super admin
    admin = User(email="admin@local", role="super_admin", ...)
    # Default llama.cpp model config pointing to /models/ volume
    model = AIModelConfig(name="Llama-3-8B-Local", provider="llama_cpp",
                          model_ref="/models/llama3-8b-instruct.Q4_K_M.gguf",
                          is_default=True)
    # Built-in plugins (disabled by default)
    session.add_all([admin, model])
    await session.commit()
```

### Rollback Strategy

Every migration file has a `downgrade()` function. Before deploying a migration to production:
1. Test `alembic upgrade head` on a copy of prod database
2. Test `alembic downgrade -1` confirms clean reversal
3. Backup production database with `pg_dump` before running migration
