---
task: Design complete AI-powered DAST/SAST security platform
slug: 20260513-000001_dast-sast-ai-security-platform
effort: comprehensive
phase: execute
progress: 14/147
mode: interactive
started: 2026-05-13T14:21:28Z
updated: 2026-05-13T14:23:00Z
---

## Context

### What Was Requested

A complete, near-production-ready design for an AI-powered DAST/SAST security platform ("AI Security Testing Suite") with:

- Modern Web UI (React/Next.js + Tailwind + shadcn/ui)
- Local .gguf model as the primary AI reasoning engine (llama.cpp, Ollama, vLLM)
- Multi-project case management
- Full DAST engine with crawler, fuzzer, Playwright integration, payload mutation
- Full SAST engine with code analysis, secret scanning, dependency vulnerability analysis, IaC scanning
- Multi-agent architecture (Recon, Auth, API, Exploit, CodeReview, Correlation, Report agents)
- SAST+DAST correlation engine that unifies findings across pipelines
- Integrations: Nuclei, Semgrep, CodeQL, OWASP ZAP, ffuf, katana, trufflehog, Burp Suite, Playwright
- Report generation: HTML, PDF, JSON, Markdown with CVSS/CWE/CVE mapping
- Authentication handling: OAuth, JWT, cookies, MFA, SSO, API keys, mTLS, custom headers
- Sandbox/isolation per scan (Docker, Firejail, namespaces)
- RBAC, multi-user, distributed workers, plugin architecture, audit logging
- Air-gapped/offline operation support
- Incremental scanning, pause/resume
- 25 specific deliverables at near-production-ready depth

### What Was NOT Requested

- Cloud-only AI dependencies — must work fully offline
- Actual code implementation (design and architecture spec is the deliverable)
- SaaS/managed deployment — this is a self-hosted tool

### Why This Matters

This platform represents a comprehensive autonomous security testing tool for authorized penetration testing, combining AI reasoning with industry-standard tools to reduce manual effort and improve finding quality. The .gguf local model is central — it enables operation in air-gapped environments (enterprise, government, classified).

### Constraints and Dependencies

- Must run on a single machine with GPU for AI (NVIDIA/AMD via llama.cpp)
- Must support Docker for sandbox isolation
- Must not require external API calls for core functionality
- Must enforce scope validation to prevent unauthorized testing
- All credentials and evidence must be encrypted at rest

### Risks

- LLM hallucination in exploit generation could produce invalid PoCs
- Sandbox escape risk if Docker not properly configured
- Rate limiting and WAF detection could block DAST scans mid-flight
- Correlation accuracy between SAST and DAST depends on quality of code instrumentation
- Multi-worker concurrency could lead to duplicate findings without deduplication
- .gguf model context window limits could truncate large codebases for SAST

## Criteria

### Architecture & System Design
- [ ] ISC-1: Overall system architecture diagram defined with all components labeled
- [ ] ISC-2: Frontend folder structure defined (Next.js app dir, components, pages)
- [ ] ISC-3: Backend folder structure defined (api, agents, workers, plugins, storage)
- [ ] ISC-4: Agents folder structure defined (one module per agent type)
- [ ] ISC-5: Plugins folder structure defined (interface, registry, examples)
- [ ] ISC-6: Docker Compose topology defined (services, networks, volumes)
- [ ] ISC-7: Service communication diagram defined (REST, WebSocket, queues)
- [ ] ISC-8: Plugin interface contract defined (hooks, capabilities, manifest)
- [ ] ISC-9: Worker communication protocol defined (job schema, events)
- [ ] ISC-10: Message queue job types enumerated (DAST, SAST, report, AI)

### Database Schema Design
- [ ] ISC-11: Projects table schema defined with all required columns
- [ ] ISC-12: Scans table schema defined with status enum and config JSONB
- [ ] ISC-13: Findings table schema defined with severity, CWE, CVSS fields
- [ ] ISC-14: Evidence table schema defined (requests, responses, payloads, screenshots)
- [ ] ISC-15: Users table schema defined with roles and permissions fields
- [ ] ISC-16: AI model configurations table schema defined
- [ ] ISC-17: Audit log table schema defined with actor, action, resource, timestamp
- [ ] ISC-18: Plugin registry table schema defined
- [ ] ISC-19: Redis data structures defined (job queues, scan state, session cache)
- [ ] ISC-20: Database migration strategy documented (tool, versioning, rollback)

### Frontend Design
- [ ] ISC-21: Projects list page layout documented (create button, status badges, filters)
- [ ] ISC-22: Project creation wizard step 1 documented (target type selection)
- [ ] ISC-23: Project creation wizard step 2 documented (adaptive target configuration)
- [ ] ISC-24: Project creation wizard step 3 documented (authentication configuration)
- [ ] ISC-25: Project creation wizard step 4 documented (analysis scope selection)
- [ ] ISC-26: Project dashboard layout documented (attack surface map, stats, timeline)
- [ ] ISC-27: Live scan console layout documented (log stream, agent status, progress)
- [ ] ISC-28: Findings browser layout documented (severity filter, CWE map, evidence)
- [ ] ISC-29: Request/response viewer layout documented (replay, diff, highlight)
- [ ] ISC-30: Report export UI documented (format selector, preview, download)
- [ ] ISC-31: Settings/config page documented (model selection, tool toggles, limits)
- [ ] ISC-32: RBAC user management UI documented (roles, invite, permissions matrix)
- [ ] ISC-33: shadcn/ui component mapping documented for each UI section
- [ ] ISC-34: WebSocket connection strategy documented (reconnect, event routing)
- [ ] ISC-35: Authentication session management documented (JWT in httpOnly cookies)

### Backend API Design
- [ ] ISC-36: Projects CRUD API routes defined (GET, POST, PUT, DELETE /projects)
- [ ] ISC-37: Scans lifecycle API routes defined (start, pause, resume, cancel, status)
- [ ] ISC-38: Findings API routes defined (list, get, update, bulk export)
- [ ] ISC-39: Reports API routes defined (generate, status, download, list)
- [ ] ISC-40: AI model config API routes defined (list models, set active, test)
- [ ] ISC-41: Plugin API routes defined (list, install, enable, disable, configure)
- [ ] ISC-42: Users/RBAC API routes defined (CRUD, invite, role assignment)
- [ ] ISC-43: Audit log API routes defined (query, export, retention policy)
- [ ] ISC-44: WebSocket event schema defined (scan progress, finding, agent status, log)
- [ ] ISC-45: Error response format standardized (code, message, details, requestId)

### AI/LLM Integration
- [ ] ISC-46: llama.cpp backend interface design documented (model load, inference API)
- [ ] ISC-47: Ollama integration design documented (API client, model management)
- [ ] ISC-48: vLLM integration design documented (OpenAI-compatible endpoint)
- [ ] ISC-49: Model abstraction layer design documented (provider-agnostic interface)
- [ ] ISC-50: Model configuration schema defined (temp, ctx size, GPU layers, threads)
- [ ] ISC-51: Hot-swap model mechanism design documented (zero-downtime switch)
- [ ] ISC-52: Prompt template system design documented (versioned, per-agent templates)
- [ ] ISC-53: RAG system design documented (vector store, embedding, retrieval)
- [ ] ISC-54: Embedding strategy defined (vulnerability KB, CVE corpus, findings)
- [ ] ISC-55: AI agent base class interface defined (context, tools, memory, execute)

### Multi-Agent System
- [ ] ISC-56: Recon Agent design documented (fingerprint, crawl, enumerate scope)
- [ ] ISC-57: Auth Agent design documented (resolve OAuth/JWT/cookies/MFA flows)
- [ ] ISC-58: API Agent design documented (OpenAPI/GraphQL/Postman analysis)
- [ ] ISC-59: Exploit Agent design documented (payload generation, PoC creation)
- [ ] ISC-60: Code Review Agent design documented (SAST contextual analysis via LLM)
- [ ] ISC-61: Correlation Agent design documented (SAST+DAST finding unification)
- [ ] ISC-62: Report Agent design documented (technical + executive generation)
- [ ] ISC-63: Agent Orchestrator design documented (delegation, state, lifecycle)
- [ ] ISC-64: Inter-agent communication protocol defined (message schema, channels)
- [ ] ISC-65: Agent failure and retry logic documented (backoff, fallback, alerting)
- [ ] ISC-66: Agent execution context design defined (memory, tool bindings, permissions)

### DAST Pipeline
- [ ] ISC-67: DAST crawling strategy documented (JS-aware, SPA, authenticated flows)
- [ ] ISC-68: DAST parameter discovery design documented (hidden params, path fuzzing)
- [ ] ISC-69: DAST fuzzing engine design documented (mutation strategies, wordlists)
- [ ] ISC-70: DAST authentication flow design documented (multi-step login, session)
- [ ] ISC-71: DAST payload library structure documented (XSS, SQLi, SSRF, SSTI, XXE)
- [ ] ISC-72: DAST Playwright integration design documented (browser pool, intercept)
- [ ] ISC-73: DAST request replay design documented (modify, replay, diff response)
- [ ] ISC-74: DAST WAF detection strategy documented (fingerprinting, evasion)
- [ ] ISC-75: DAST scope validation design documented (whitelist enforcement per scan)
- [ ] ISC-76: DAST finding classification logic documented (severity assignment, CWE)
- [ ] ISC-77: DAST pause/resume state machine documented (checkpointing, queue drain)
- [ ] ISC-78: DAST WebSocket testing design documented (message fuzzing, injection)
- [ ] ISC-79: DAST GraphQL abuse testing design documented (introspection, batching)
- [ ] ISC-80: DAST JWT attack design documented (alg:none, key confusion, weak secret)
- [ ] ISC-81: DAST CORS misconfiguration detection design documented

### SAST Pipeline
- [ ] ISC-82: SAST repo cloning strategy documented (GitHub, GitLab, SSH, local)
- [ ] ISC-83: SAST language detection design documented (polyglot, framework detection)
- [ ] ISC-84: SAST build/install strategy documented (per-language dependency install)
- [ ] ISC-85: SAST sink detection design documented (taint tracking, data flow)
- [ ] ISC-86: SAST secret scanning integration documented (trufflehog, patterns)
- [ ] ISC-87: SAST dependency vulnerability analysis documented (npm audit, snyk-style)
- [ ] ISC-88: SAST IaC analysis documented (Terraform, Dockerfile, K8s manifests)
- [ ] ISC-89: SAST CI/CD workflow analysis documented (GitHub Actions, GitLab CI)
- [ ] ISC-90: SAST finding output format defined (severity, file, line, snippet, fix)
- [ ] ISC-91: SAST-to-DAST bridge design documented (finding handoff protocol)
- [ ] ISC-92: Semgrep integration design documented (rulesets, custom rules, output)
- [ ] ISC-93: CodeQL integration design documented (query packs, database build)

### Tool Orchestration
- [ ] ISC-94: Nuclei integration design documented (template selection, output parsing)
- [ ] ISC-95: OWASP ZAP integration design documented (proxy mode, REST API)
- [ ] ISC-96: ffuf integration design documented (wordlists, parameter fuzzing config)
- [ ] ISC-97: katana integration design documented (crawling, JS endpoint discovery)
- [ ] ISC-98: Burp Suite integration design documented (extension/REST API bridge)
- [ ] ISC-99: Tool output normalization schema defined (finding, severity, evidence)
- [ ] ISC-100: Tool orchestrator design documented (parallel execution, resource limits)

### Security & Infrastructure
- [ ] ISC-101: Docker sandbox design documented (per-scan isolation, network policies)
- [ ] ISC-102: Firejail integration design documented (process-level isolation profile)
- [ ] ISC-103: Rate limiting design documented (per-target, configurable, backoff)
- [ ] ISC-104: RBAC permission model defined (roles: admin, analyst, viewer; resources)
- [ ] ISC-105: Audit log format defined (actor, action, resource, timestamp, result)
- [ ] ISC-106: Encryption strategy documented (secrets at rest AES-256, transit TLS)
- [ ] ISC-107: Air-gapped operation design documented (offline model, no external calls)
- [ ] ISC-108: Platform threat model documented (injection, auth, sandbox escape risks)
- [ ] ISC-109: Threat mitigations documented for each identified threat category

### Reporting Engine
- [ ] ISC-110: Report data model defined (sections, findings list, evidence refs, exec summary)
- [ ] ISC-111: HTML report template design documented (responsive, styled, printable)
- [ ] ISC-112: PDF generation strategy documented (headless Chrome or Puppeteer)
- [ ] ISC-113: CVSS v3.1 score calculation design documented (vector string, base score)
- [ ] ISC-114: CWE/CVE mapping strategy documented (local DB, NVD integration)
- [ ] ISC-115: Executive summary AI prompt template defined (risk narrative, metrics)

### Observability & Roadmap
- [ ] ISC-116: Logging strategy documented (structured JSON, log levels, rotation)
- [ ] ISC-117: Metrics collection design documented (scan stats, model latency, findings)
- [ ] ISC-118: Health check endpoints defined (/health, /ready, /metrics)
- [ ] ISC-119: Scan progress tracking design documented (percentage, phase, findings count)
- [ ] ISC-120: Phase 1 MVP milestones defined with deliverables and acceptance criteria
- [ ] ISC-121: Phase 2 core features milestones defined with deliverables
- [ ] ISC-122: Phase 3 advanced features milestones defined with deliverables
- [ ] ISC-123: Phase 4 enterprise features milestones defined with deliverables

### IterativeDepth Additions (4-Lens Analysis)
- [ ] ISC-129: Agent context versioning prevents stale context propagation between agents
- [ ] ISC-130: LLM token budget calculation guards context overflow before every inference call
- [ ] ISC-131: Correlation confidence threshold gates false-positive findings from unification
- [ ] ISC-132: Agent system prompt contains role, goal, and backstory for LLM behavior priming
- [ ] ISC-133: DAST response analysis feeds back as mutation signal to Exploit Agent payload loop
- [ ] ISC-134: Prompt templates are versioned and model-swappable (not hardcoded per class)
- [ ] ISC-135: SAST chunking strategy gracefully degrades when context window exceeds codebase size
- [ ] ISC-136: High-severity findings require evidence validation step before storage
- [ ] ISC-A-8: No two agents write the same finding without deduplication hash check
- [ ] ISC-A-9: Agent inference does not block the main API thread (all async)

### THINK Phase Additions (Premortem-Driven)
- [ ] ISC-124: Playwright browser pool lifecycle design documented (reuse, limits, cleanup)
- [ ] ISC-125: Finding deduplication logic documented (hash-based, semantic similarity)
- [ ] ISC-126: LLM context chunking strategy documented for large monorepo codebases
- [ ] ISC-127: Plugin sandboxed execution design documented (no host filesystem access)
- [ ] ISC-128: Scan heartbeat/stall detection design documented (timeout, alerting)

### Anti-Criteria
- [ ] ISC-A-1: Platform does not require any external API calls for core functionality
- [ ] ISC-A-2: Out-of-scope targets cannot be scanned (scope validation enforced)
- [ ] ISC-A-3: Credentials and API keys are never stored in plaintext
- [ ] ISC-A-4: Single worker failure does not cause complete scan failure
- [ ] ISC-A-5: No AI-generated payloads execute outside sandboxed environment
- [ ] ISC-A-6: Evidence viewer does not execute target JavaScript in analyst browser
- [ ] ISC-A-7: RBAC enforces per-project isolation (no cross-project finding access)

## Decisions

- 2026-05-13 14:23: Selected Comprehensive effort tier — 25 deliverables, no time constraint, production-ready depth required. ISC count: 135 (above 64 floor).
- 2026-05-13 14:23: Parallel agent strategy — 5 background agents cover architecture/DB/frontend/security/threat-model; Thinking skill + main context handle DAST/SAST/AI/agents/report/observability synthesis.
- 2026-05-13 14:25: Output format — 14 focused design docs in docs/ + scaffolded folder structure. Organized by user's 25-item deliverable list.
- 2026-05-13 14:25: Tech stack confirmed — Next.js 14 (App Router), FastAPI (Python), PostgreSQL 15, Redis 7, BullMQ, llama-cpp-python, Playwright, Docker Compose.
- 2026-05-13 14:25: Chose FastAPI over Node.js for backend — better Python ecosystem for AI/ML integration (langchain, llama-cpp-python, semgrep, trufflehog all have Python-native bindings).

### Plan

**Phase structure:**
1. BUILD: Launch 6 parallel capabilities (5 agents + 1 Thinking skill invocation)
2. EXECUTE: Collect results, write 14 design docs, scaffold directory tree, mark ISC criteria
3. VERIFY: Check each ISC criterion against written documents

**Tech stack final decisions:**
- Frontend: Next.js 14 (App Router), Tailwind CSS, shadcn/ui, Zustand, React Query, xterm.js
- Backend: FastAPI + Python 3.12, Celery workers, BullMQ (Redis-backed), SQLAlchemy 2.0
- Database: PostgreSQL 15 (pgvector for embeddings), Redis 7.2
- AI: llama-cpp-python (llama.cpp backend), Ollama client, vLLM OpenAI-compatible client
- DAST: Playwright 1.42+, custom fuzzer, requests/httpx
- SAST: Semgrep, CodeQL CLI, ast-grep, trufflehog
- Tools: Nuclei, ffuf, katana, ZAP REST API, Burp Suite REST API
- Sandbox: Docker SDK, Firejail, Linux namespaces
- Reports: WeasyPrint (PDF), Jinja2 (HTML templates), markdown-it
