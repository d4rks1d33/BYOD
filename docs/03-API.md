# AutoPentest — Internal API Specification

## Authentication

All endpoints require JWT authentication unless marked `[Public]`.

**JWT format:** `Authorization: Bearer <token>`
**Token lifetime:** 15 minutes (access), 30 days (refresh)
**API tokens:** `Authorization: Bearer <api_token>` — token validated against `api_tokens.token_hash`

---

## Auth Routes

### `POST /auth/login` [Public]
```
Request: { email: string, password: string, mfa_code?: string }
Response 200: { access_token: string, refresh_token: string, user: UserSchema }
Response 401: { code: "INVALID_CREDENTIALS" }
Response 423: { code: "ACCOUNT_LOCKED", locked_until: string }
Rate limit: 10 req/min per IP
```

### `POST /auth/refresh` [Public]
```
Request: { refresh_token: string }
Response 200: { access_token: string, refresh_token: string }
Response 401: { code: "TOKEN_INVALID_OR_EXPIRED" }
Note: Refresh token rotation — old token is consumed, new pair issued
```

### `POST /auth/logout`
```
Request: { refresh_token: string }
Response 204: (empty)
Note: Revokes refresh token family
```

### `POST /auth/register` [Admin role required]
```
Request: { email: string, full_name: string, role: "analyst" | "viewer" }
Response 201: { user: UserSchema, temporary_password: string }
Note: Returns one-time password; user must change on first login
```

---

## Projects

### `GET /projects`
```
Query: page=1, limit=20, status=, archived=false
Response 200: { items: ProjectSchema[], total: int, page: int }
Note: RLS enforces visibility (only projects user is owner or member of)
```

### `POST /projects`
```
Request: ProjectCreateSchema {
  name: string,
  description?: string,
  target_url: string,
  target_type: "web_application" | "rest_api" | "graphql_api" | "repository" | "mobile_backend",
  scope_urls: string[],
  exclude_patterns: string[],
  config: {
    auth?: AuthConfigSchema,
    scan_defaults?: ScanDefaultsSchema,
    environment: "production" | "staging" | "development"
  }
}
Response 201: ProjectSchema
Response 409: { code: "DUPLICATE_NAME" }
```

### `GET /projects/{id}`
```
Response 200: ProjectSchema with stats
Response 404: { code: "PROJECT_NOT_FOUND" }
```

### `PUT /projects/{id}`
```
Request: ProjectUpdateSchema (same as create, all optional)
Response 200: ProjectSchema
Note: Cannot change target_url after scans exist (requires archive+new project)
```

### `DELETE /projects/{id}` [project_owner role]
```
Response 204
Note: Soft delete — sets archived_at. Evidence retained for audit.
```

### `GET /projects/{id}/stats`
```
Response 200: {
  total_findings: int,
  findings_by_severity: { critical: int, high: int, medium: int, low: int, info: int },
  verified_findings: int,
  false_positives: int,
  total_scans: int,
  last_scan_duration_ms: int,
  attack_surface_endpoints: int,
  coverage_pct: float
}
```

### `POST /projects/{id}/members`
```
Request: { user_id: UUID, role: "project_analyst" | "project_viewer" }
Response 201: ProjectMemberSchema
```

### `DELETE /projects/{id}/members/{user_id}`
```
Response 204
```

---

## Scans

### `POST /projects/{id}/scans`
```
Request: ScanCreateSchema {
  scan_type: scan_type_enum,
  config: {
    intensity: "passive" | "balanced" | "aggressive" | "custom",
    requests_per_second: int,
    total_timeout_minutes: int,
    tools: string[],              // ["nuclei", "semgrep", "ffuf", ...]
    vuln_types?: string[],        // Override default vuln types to test
    ai_model_id?: UUID,           // Override default model
    wordlists?: string[],         // Custom wordlist file paths
  }
}
Response 202: { scan_id: UUID, celery_task_id: string, status: "queued" }
```

### `GET /projects/{id}/scans`
```
Query: page=1, limit=20, status=
Response 200: { items: ScanSummarySchema[], total: int }
```

### `GET /scans/{id}`
```
Response 200: ScanDetailSchema {
  ...scan fields,
  statistics: ScanStatisticsSchema,
  checkpoints: { phase: string, saved_at: string }[],
  findings_summary: { severity: string, count: int }[]
}
```

### `GET /scans/{id}/progress`
```
Response 200: {
  status: scan_status_enum,
  current_phase: string,
  phase_progress_pct: int,
  overall_progress_pct: int,
  stats: ScanStatisticsSchema,
  active_agents: AgentStatusSchema[]
}
Note: Polling endpoint — use WebSocket for live updates
```

### `POST /scans/{id}/pause`
```
Response 202: { message: "Pause signal sent. Scan will pause at next checkpoint." }
Response 409: { code: "SCAN_NOT_RUNNING" }
```

### `POST /scans/{id}/resume`
```
Response 202: { message: "Scan resumed from checkpoint.", resumed_from_phase: string }
Response 409: { code: "SCAN_NOT_PAUSED" }
```

### `POST /scans/{id}/cancel`
```
Request: { reason?: string }
Response 202: { message: "Cancel signal sent." }
```

---

## Findings

### `GET /projects/{id}/findings`
```
Query: 
  severity=critical,high
  type=sqli,xss
  status=new,verified
  scan_id=UUID
  cwe=CWE-89
  cvss_min=7.0
  page=1, limit=50
  sort=severity_desc | cvss_desc | created_asc
Response 200: { items: FindingSummarySchema[], total: int, filters_applied: dict }
```

### `GET /findings/{id}`
```
Response 200: FindingDetailSchema {
  ...finding fields,
  evidence: EvidenceSchema[],
  correlated_finding: FindingSummarySchema | null,
  reproduction_steps: ReproStepSchema[],
  poc_code: string,
  remediation: string
}
```

### `PATCH /findings/{id}`
```
Request: { status?: finding_status_enum, notes?: string }
Response 200: FindingDetailSchema
Note: Creates audit log entry for status changes
```

### `POST /findings/{id}/verify`
```
Request: { notes?: string }
Response 200: { ...finding, status: "verified", verified_at: string, verified_by: UserSchema }
```

### `POST /findings/{id}/false-positive`
```
Request: { reason: string }
Response 200: { ...finding, status: "false_positive" }
```

### `GET /projects/{id}/findings/export`
```
Query: format=json|csv|xlsx, severity=, status=
Response 200: File download (Content-Disposition: attachment)
```

---

## Evidence

### `GET /findings/{id}/evidence`
```
Response 200: EvidenceSchema[] {
  id: UUID,
  evidence_type: evidence_type_enum,
  http_request: string | null,   // Truncated to 64KB
  http_response: string | null,
  payload: string | null,
  screenshot_url: string | null,  // Presigned URL to encrypted file
  created_at: string
}
```

### `GET /evidence/{id}`
```
Response 200: EvidenceDetailSchema
Note: Requires project membership
```

### `POST /evidence/{id}/replay`
```
Request: {
  modified_headers?: dict,
  modified_body?: string,
  modified_params?: dict
}
Response 200: {
  status_code: int,
  response_headers: dict,
  response_body: string,     // Truncated to 64KB
  elapsed_ms: int
}
Note: Replays the original request with optional modifications. Runs inside sandbox.
Authorization check: confirms URL is in scope before replaying.
```

---

## Reports

### `POST /projects/{id}/reports`
```
Request: ReportCreateSchema {
  format: report_format_enum,
  scan_id?: UUID,          // null = all scans
  config: {
    audience: "technical" | "executive",
    include_sections: string[],  // ["findings", "evidence", "remediation", "timeline"]
    severity_filter: string[],
    include_poc: bool,
    include_evidence: bool,
    custom_executive_summary?: string
  }
}
Response 202: { report_job_id: UUID, status: "pending", estimated_minutes: int }
```

### `GET /projects/{id}/reports`
```
Response 200: ReportJobSchema[]
```

### `GET /reports/{id}`
```
Response 200: ReportJobDetailSchema { ...job, download_url?: string }
```

### `GET /reports/{id}/download`
```
Response 200: File download
Content-Type: application/pdf | application/json | text/html | text/markdown
Content-Disposition: attachment; filename="report-{project}-{date}.{ext}"
Note: Audit log entry created on every download
```

---

## AI Model Configuration

### `GET /ai/models`
```
Response 200: AIModelConfigSchema[] with metrics
```

### `POST /ai/models` [admin role]
```
Request: {
  name: string,
  provider: ai_provider_enum,
  model_ref: string,           // Path or model ID
  config: ModelConfigSchema,
  ollama_host?: string,
  vllm_base_url?: string,
  api_key?: string             // Encrypted at rest
}
Response 201: AIModelConfigSchema
```

### `PATCH /ai/models/{id}` [super_admin]
```
Request: Partial AIModelConfigSchema
Response 200: AIModelConfigSchema
```

### `POST /ai/models/{id}/activate` [super_admin]
```
Response 200: { message: "Model activated. Workers will hot-swap on next inference." }
```

### `POST /ai/models/test`
```
Request: { model_id: UUID, prompt: string }
Response 200: { response: string, elapsed_ms: int, tokens_used: int }
Timeout: 30 seconds
```

---

## Plugins

### `GET /plugins`
```
Response 200: PluginSchema[]
```

### `POST /plugins` [admin role]
```
Request: multipart/form-data { plugin_zip: File }
Response 201: { plugin_id: UUID, status: "validating" }
Note: Async validation — WebSocket event on completion
```

### `POST /plugins/{id}/enable` [admin role]
```
Response 200: PluginSchema { enabled: true }
```

### `POST /plugins/{id}/disable` [admin role]
```
Response 200: PluginSchema { enabled: false }
```

---

## Users

### `GET /users/me`
```
Response 200: UserSchema with project memberships
```

### `PATCH /users/me`
```
Request: { full_name?: string, password?: { current: string, new: string } }
Response 200: UserSchema
```

### `GET /users` [admin role]
```
Response 200: UserSchema[]
```

### `PATCH /users/{id}/role` [super_admin]
```
Request: { role: system_role_enum }
Response 200: UserSchema
```

---

## Audit Logs

### `GET /audit/logs` [super_admin]
```
Query: actor_id=, action=, resource_type=, from=ISO, to=ISO, page=1, limit=100
Response 200: { items: AuditLogSchema[], total: int }
```

### `GET /projects/{id}/audit` [project_owner]
```
Query: action=, from=, to=, page=1, limit=100
Response 200: AuditLogSchema[] filtered to this project
```

---

## WebSocket Events

### `WS /ws/projects/{id}/scan`
**Connection:** Auth via `?token=<jwt>` query param (WS doesn't support headers)

**Server → Client events:**

```typescript
// scan.started
{ type: "scan.started", scan_id: string, started_at: string }

// scan.progress
{ type: "scan.progress", scan_id: string, phase: string, 
  phase_progress: number, overall_progress: number, stats: ScanStats }

// scan.phase_changed
{ type: "scan.phase_changed", scan_id: string,
  previous_phase: string, current_phase: string, timestamp: string }

// scan.paused
{ type: "scan.paused", scan_id: string, checkpoint_phase: string }

// scan.resumed
{ type: "scan.resumed", scan_id: string, resumed_from: string }

// scan.completed
{ type: "scan.completed", scan_id: string, duration_ms: number, 
  findings_summary: { severity: string, count: number }[] }

// scan.failed
{ type: "scan.failed", scan_id: string, error: string, phase: string }

// finding.new
{ type: "finding.new", finding: FindingSummarySchema }

// finding.updated
{ type: "finding.updated", finding_id: string, changes: object }

// agent.status
{ type: "agent.status", agent: string, status: "running" | "idle" | "error",
  task: string, progress: number }

// log.line
{ type: "log.line", level: "DEBUG" | "INFO" | "WARN" | "ERROR",
  agent: string, message: string, timestamp: string }

// http.transaction
{ type: "http.transaction", method: string, url: string,
  status: number, elapsed_ms: number, size: number }

// heartbeat
{ type: "heartbeat", server_time: string }
```

**Client → Server events:**

```typescript
// Subscribe to specific scan
{ type: "subscribe", scan_id: string }

// Unsubscribe
{ type: "unsubscribe", scan_id: string }

// Ping
{ type: "ping" }
```

**Reconnection strategy:**
- Client uses exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s max
- On reconnect, client sends last seen event timestamp → server replays missed events from Redis Stream
- Redis Stream `scan:log:{scan_id}` retains events for 24 hours

---

## Error Response Format

All errors return a consistent schema:

```json
{
  "error": {
    "code": "SCAN_NOT_FOUND",
    "message": "No scan with ID abc123 exists in this project",
    "details": { "scan_id": "abc123", "project_id": "xyz789" },
    "request_id": "req_abcdef123456"
  }
}
```

**Standard error codes:**

| HTTP Status | Code | Meaning |
|-------------|------|---------|
| 400 | `VALIDATION_ERROR` | Request body fails Pydantic validation |
| 401 | `UNAUTHORIZED` | Missing or invalid token |
| 403 | `FORBIDDEN` | Valid token, insufficient role |
| 404 | `NOT_FOUND` | Resource does not exist |
| 409 | `CONFLICT` | State conflict (e.g., pausing a completed scan) |
| 422 | `SCOPE_VIOLATION` | Target URL is outside project scope |
| 429 | `RATE_LIMITED` | Too many requests |
| 500 | `INTERNAL_ERROR` | Unexpected server error |
| 503 | `SERVICE_UNAVAILABLE` | AI model not available |
