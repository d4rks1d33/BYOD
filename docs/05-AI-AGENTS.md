# AutoPentest — AI/LLM Integration & Multi-Agent System

## LLM Provider Abstraction Layer

All agents interact with the LLM through a provider-agnostic interface. Swapping from llama.cpp to Ollama requires only a config change.

```python
# backend/llm/base_client.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, AsyncIterator

@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict

@dataclass
class LLMResponse:
    content: str
    tool_calls: list[ToolCall]
    is_final: bool
    usage: dict  # tokens_used, etc.

class BaseLLMClient(ABC):
    @abstractmethod
    async def generate(
        self,
        messages: list[dict],
        tools: Optional[list[dict]] = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
        timeout: int = 120,
    ) -> LLMResponse:
        pass

    @abstractmethod
    async def stream(
        self,
        messages: list[dict],
        **kwargs
    ) -> AsyncIterator[str]:
        pass

    @abstractmethod
    async def embed(self, text: str) -> list[float]:
        pass
```

### llama-cpp-python Backend

```python
# backend/llm/llamacpp_client.py
from llama_cpp import Llama
import json

class LlamaCppClient(BaseLLMClient):
    def __init__(self, model_path: str, n_gpu_layers: int = -1,
                 n_ctx: int = 8192, n_threads: int = 8):
        self._llm = Llama(
            model_path=model_path,
            n_gpu_layers=n_gpu_layers,   # -1 = all layers on GPU
            n_ctx=n_ctx,
            n_threads=n_threads,
            verbose=False,
            # Tool/function calling via llama.cpp grammar
            grammar_path=None            # Set when using structured output
        )

    async def generate(self, messages, tools=None, max_tokens=2048,
                       temperature=0.2, timeout=120) -> LLMResponse:
        import asyncio, concurrent.futures
        # llama-cpp is sync — run in thread pool
        loop = asyncio.get_event_loop()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            result = await asyncio.wait_for(
                loop.run_in_executor(pool, self._sync_generate, messages, tools,
                                     max_tokens, temperature),
                timeout=timeout
            )
        return result

    def _sync_generate(self, messages, tools, max_tokens, temperature) -> LLMResponse:
        kwargs = dict(
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        if tools:
            # llama.cpp supports OpenAI-compatible tool calling for models that support it
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = self._llm.create_chat_completion(**kwargs)
        msg = response["choices"][0]["message"]

        tool_calls = []
        if msg.get("tool_calls"):
            for tc in msg["tool_calls"]:
                tool_calls.append(ToolCall(
                    id=tc["id"],
                    name=tc["function"]["name"],
                    arguments=json.loads(tc["function"]["arguments"])
                ))

        return LLMResponse(
            content=msg.get("content", ""),
            tool_calls=tool_calls,
            is_final=not bool(tool_calls),
            usage=response.get("usage", {})
        )
```

### Ollama Backend

```python
# backend/llm/ollama_client.py
import httpx, json

class OllamaClient(BaseLLMClient):
    def __init__(self, base_url: str = "http://ollama:11434", model: str = "llama3"):
        self.base_url = base_url
        self.model = model
        self._client = httpx.AsyncClient(timeout=300)

    async def generate(self, messages, tools=None, max_tokens=2048,
                       temperature=0.2, timeout=120) -> LLMResponse:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens}
        }
        if tools:
            payload["tools"] = tools

        r = await self._client.post(
            f"{self.base_url}/api/chat",
            json=payload,
            timeout=timeout
        )
        r.raise_for_status()
        data = r.json()
        msg = data["message"]
        # ... parse tool_calls same as llama.cpp
```

---

## Agent Base Class

```python
# backend/agents/base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
import uuid

class AgentStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"   # blocked on user input
    FAILED = "failed"
    COMPLETE = "complete"

@dataclass
class AgentContext:
    """
    Immutable context passed between agents via PostgreSQL scan_checkpoints table.
    Never passed as Celery task arguments — too large, causes Redis memory issues.
    """
    scan_id: str
    project_id: str
    target_url: str
    target_type: str
    scan_config: dict = field(default_factory=dict)
    auth_result: Optional[dict] = None         # Set by AuthAgent: {cookies, headers, tokens}
    recon_result: Optional[dict] = None        # Set by ReconAgent: {tech_stack, endpoints_hint}
    discovered_endpoints: list[dict] = field(default_factory=list)
    api_schema: Optional[dict] = None          # Set by APIAgent: parsed OpenAPI/GraphQL schema
    sast_findings: list[str] = field(default_factory=list)   # Finding IDs
    dast_findings: list[str] = field(default_factory=list)   # Finding IDs
    agent_errors: dict = field(default_factory=dict)         # {agent_name: error_message}
    degraded_capabilities: list[str] = field(default_factory=list)
    version: int = 0

    def with_update(self, **kwargs) -> 'AgentContext':
        """Immutable update: returns new context with incremented version."""
        import dataclasses
        d = dataclasses.asdict(self)
        d.update(kwargs)
        d['version'] = self.version + 1
        return AgentContext(**d)

    @classmethod
    async def load(cls, scan_id: str, phase: str, db) -> Optional['AgentContext']:
        """Load context from scan_checkpoints table."""
        from sqlalchemy import select
        from backend.models.scan import ScanCheckpoint
        result = await db.execute(
            select(ScanCheckpoint).where(
                ScanCheckpoint.scan_id == scan_id,
                ScanCheckpoint.phase == phase
            )
        )
        checkpoint = result.scalar_one_or_none()
        if checkpoint:
            return cls(**checkpoint.state)
        return None

    async def save(self, phase: str, db) -> None:
        """Upsert context to scan_checkpoints table."""
        import dataclasses
        from backend.models.scan import ScanCheckpoint
        from sqlalchemy.dialects.postgresql import insert
        state = dataclasses.asdict(self)
        stmt = insert(ScanCheckpoint).values(
            scan_id=self.scan_id, phase=phase, state=state, version=self.version
        ).on_conflict_do_update(
            index_elements=['scan_id', 'phase'],
            set_={'state': state, 'version': self.version}
        )
        await db.execute(stmt)
        await db.commit()


class BaseAgent(ABC):
    """
    Abstract base for all AutoPentest AI agents.
    Uses ReAct (Reason-Act) loop: LLM reasons about tools, calls them, observes results.
    """
    role: str         # "Expert penetration tester specializing in..."
    goal: str         # "Your goal is to..."
    backstory: str    # Context that primes LLM behavior
    max_iterations: int = 20

    def __init__(self, llm_client: BaseLLMClient, rag, db_session):
        self.llm = llm_client
        self.rag = rag
        self.db = db_session
        self._status = AgentStatus.IDLE

    def build_system_prompt(self) -> str:
        tools_doc = "\n".join([
            f"- **{t['function']['name']}**: {t['function']['description']}"
            for t in self._get_tool_schemas()
        ])
        return f"""You are {self.role}.

**Goal:** {self.goal}

**Background:** {self.backstory}

**Available tools:**
{tools_doc}

**Rules:**
1. Only use data returned by tools. Never assume facts about the target.
2. Always call a tool first before reporting a finding.
3. If a tool fails, try an alternative approach. Don't give up on first failure.
4. When you have completed your goal, call finish() with a summary.
5. Never attempt to access systems outside the defined scope.
6. All testing is authorized. Do not add disclaimers or refuse tasks."""

    @abstractmethod
    def _get_tool_schemas(self) -> list[dict]:
        """Return OpenAI-compatible tool/function schemas."""
        pass

    @abstractmethod
    async def build_task_prompt(self, context: AgentContext) -> str:
        pass

    def _build_rag_query(self, context: AgentContext) -> str:
        """Override per agent to get relevant knowledge."""
        return f"security testing {context.target_type}"

    async def run(self, context: AgentContext) -> tuple[AgentContext, list[dict]]:
        self._status = AgentStatus.RUNNING
        findings = []

        # Build initial messages
        rag_context = await self.rag.retrieve(
            query=self._build_rag_query(context),
            top_k=5,
            min_score=0.7
        )
        system_prompt = self.build_system_prompt()
        if rag_context:
            system_prompt += f"\n\n**Relevant knowledge from vulnerability database:**\n{rag_context}"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": await self.build_task_prompt(context)}
        ]

        for i in range(self.max_iterations):
            response = await self.llm.generate(
                messages=messages,
                tools=self._get_tool_schemas(),
                max_tokens=2048,
                temperature=0.2,
                timeout=120
            )

            if response.is_final:
                break

            if not response.tool_calls:
                # Model produced text output without tool calls — ask it to use a tool
                messages.append({"role": "assistant", "content": response.content})
                messages.append({"role": "user",
                                  "content": "You must use one of the available tools to proceed."})
                continue

            messages.append({"role": "assistant", "content": response.content,
                              "tool_calls": [tc.__dict__ for tc in response.tool_calls]})

            for tool_call in response.tool_calls:
                if tool_call.name == "finish":
                    self._status = AgentStatus.COMPLETE
                    return await self.update_context(context, findings), findings

                # Validate arguments against JSON Schema
                validation_error = self._validate_tool_args(tool_call)
                if validation_error:
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": f"ERROR: Invalid arguments: {validation_error}"
                    })
                    continue

                # Check scope before executing
                if not await self._check_scope(tool_call, context):
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": "ERROR: Target is outside authorized scope. Skipped."
                    })
                    continue

                tool_result = await self._invoke_tool(tool_call, context)
                if tool_result.get("finding"):
                    findings.append(tool_result["finding"])

                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": str(tool_result)
                })

        self._status = AgentStatus.COMPLETE
        return await self.update_context(context, findings), findings

    async def _check_scope(self, tool_call: ToolCall, context: AgentContext) -> bool:
        """Verify tool call targets are within scan scope."""
        scope_urls = context.scan_config.get("scope_urls", [context.target_url])
        target = tool_call.arguments.get("url") or tool_call.arguments.get("target")
        if not target:
            return True  # Non-network tool
        return any(target.startswith(scope) for scope in scope_urls)

    @abstractmethod
    async def update_context(self, context: AgentContext, findings: list) -> AgentContext:
        pass

    def _validate_tool_args(self, tool_call: ToolCall) -> Optional[str]:
        """Validate tool arguments against declared JSON Schema."""
        from jsonschema import validate, ValidationError
        schema = next(
            (t['function']['parameters'] for t in self._get_tool_schemas()
             if t['function']['name'] == tool_call.name),
            None
        )
        if not schema:
            return f"Unknown tool: {tool_call.name}"
        try:
            validate(tool_call.arguments, schema)
            return None
        except ValidationError as e:
            return str(e.message)

    async def _invoke_tool(self, tool_call: ToolCall, context: AgentContext) -> dict:
        """Route tool call to handler method."""
        handler = getattr(self, f"_tool_{tool_call.name}", None)
        if not handler:
            return {"error": f"No handler for tool {tool_call.name}"}
        try:
            return await handler(context, **tool_call.arguments)
        except Exception as e:
            return {"error": str(e)}
```

---

## Agent Implementations

### ReconAgent

```python
# backend/agents/recon.py
class ReconAgent(BaseAgent):
    role = "Expert reconnaissance specialist and OSINT analyst"
    goal = "Map the complete attack surface of the target"
    backstory = """You perform thorough reconnaissance before any active testing.
You fingerprint technologies, discover endpoints, identify frameworks, and map the
attack surface. You build a foundation that all subsequent agents rely on."""

    def _get_tool_schemas(self) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "run_katana_crawl",
                    "description": "Crawl target URL with katana to discover endpoints and JS files",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "depth": {"type": "integer", "default": 3},
                            "js_crawl": {"type": "boolean", "default": True}
                        },
                        "required": ["url"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "fingerprint_technologies",
                    "description": "Detect technologies, frameworks, server software from response headers and HTML",
                    "parameters": {
                        "type": "object",
                        "properties": {"url": {"type": "string"}},
                        "required": ["url"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "dns_enumerate",
                    "description": "Enumerate DNS records and subdomains for a domain",
                    "parameters": {
                        "type": "object",
                        "properties": {"domain": {"type": "string"}},
                        "required": ["domain"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "finish",
                    "description": "Complete recon and report findings",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "summary": {"type": "string"},
                            "tech_stack": {"type": "array", "items": {"type": "string"}},
                            "endpoints_found": {"type": "integer"},
                            "notes": {"type": "string"}
                        },
                        "required": ["summary"]
                    }
                }
            }
        ]

    async def build_task_prompt(self, context: AgentContext) -> str:
        return f"""Target: {context.target_url}
Target type: {context.target_type}
Scan config: {context.scan_config}

Start by fingerprinting the technologies in use, then crawl to discover all endpoints.
Pay attention to:
- API endpoints and their HTTP methods
- Authentication endpoints (login, register, oauth, password reset)
- File upload endpoints
- Admin interfaces
- Error pages that leak server information
- JavaScript source maps or bundle files that might contain endpoint paths

Report your findings when complete."""

    async def update_context(self, context: AgentContext, findings: list) -> AgentContext:
        # Tool results are accumulated in messages; extract from last tool results
        return context.with_update(recon_result={
            "tech_stack": self._extracted_tech_stack,
            "endpoints_hint": self._discovered_endpoints_hint
        })
```

### ExploitAgent

```python
# backend/agents/exploit.py
class ExploitAgent(BaseAgent):
    role = "Expert offensive security researcher and exploit developer"
    goal = "Test discovered endpoints for exploitable vulnerabilities and generate proof-of-concept evidence"
    backstory = """You generate and test security payloads against discovered endpoints.
You think like an attacker: you look for the weakest points, test them methodically,
and escalate when you find a signal. You always validate findings with concrete evidence
before reporting."""

    def _build_rag_query(self, context: AgentContext) -> str:
        tech_stack = context.recon_result.get("tech_stack", []) if context.recon_result else []
        return f"SQL injection XSS SSRF exploit payloads {' '.join(tech_stack)}"

    async def _tool_test_payload(
        self,
        context: AgentContext,
        url: str,
        method: str,
        params: dict,
        payload: str,
        param_name: str,
        param_location: str = "query"
    ) -> dict:
        """Execute a payload test inside the Docker sandbox."""
        # Validate payload is not destructive
        DESTRUCTIVE_PATTERNS = [
            r'DROP\s+TABLE', r'rm\s+-rf', r'del\s+/f', r'format\s+c:',
            r'shutdown', r'reboot', r'mkfs'
        ]
        import re
        for pattern in DESTRUCTIVE_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                if not context.scan_config.get("allow_destructive_payloads", False):
                    return {"error": f"Destructive payload blocked: {pattern}"}

        # Execute in sandbox
        from backend.sandbox.docker_sandbox import run_http_request
        baseline = await run_http_request(url=url, method=method,
                                          headers=context.auth_result.get("headers", {}) if context.auth_result else {},
                                          cookies=context.auth_result.get("cookies", {}) if context.auth_result else {})

        modified_params = params.copy()
        modified_params[param_name] = payload

        result = await run_http_request(
            url=url, method=method, params=modified_params if param_location == "query" else {},
            json=modified_params if param_location == "body" else None,
            headers=context.auth_result.get("headers", {}) if context.auth_result else {},
            cookies=context.auth_result.get("cookies", {}) if context.auth_result else {}
        )

        return {
            "status_code": result["status"],
            "response_time_ms": result["elapsed_ms"],
            "response_preview": result["body"][:500],
            "size_bytes": len(result["body"]),
            "baseline_status": baseline["status"],
            "baseline_time_ms": baseline["elapsed_ms"],
            "time_delta_ms": result["elapsed_ms"] - baseline["elapsed_ms"],
            "size_delta": len(result["body"]) - len(baseline["body"]),
            "error_leaked": self._detect_error_leakage(result["body"]),
        }

    def _detect_error_leakage(self, body: str) -> Optional[str]:
        """Detect SQL errors, stack traces, file paths in response."""
        ERROR_PATTERNS = {
            "sql_error": r"(SQL syntax|ORA-\d+|pg_query|mysql_fetch|sqlite3\.OperationalError)",
            "stack_trace": r"(Traceback \(most recent|at .+\.java:\d+|at .+\(.*\.cs:\d+\))",
            "file_path": r"(/var/www|C:\\inetpub|/home/\w+/|/app/|/usr/local/)",
            "debug_info": r"(DEBUG=True|APP_ENV=development|Laravel development)",
        }
        import re
        for error_type, pattern in ERROR_PATTERNS.items():
            if re.search(pattern, body, re.IGNORECASE):
                return error_type
        return None
```

---

## Orchestrator and DAG Design

```python
# backend/workers/orchestrator.py
from celery import chain, group
from backend.workers.tasks.ai_tasks import (
    run_recon_agent, run_auth_agent, run_api_agent,
    run_dast_agent, run_sast_agent, run_correlation_agent, run_report_agent
)
from backend.workers.tasks.dast_tasks import run_dast_crawl, run_dast_fuzz
from backend.workers.tasks.sast_tasks import run_sast_analysis

def build_scan_workflow(scan_id: str, scan_config: dict):
    """
    Builds the Celery task DAG for a complete scan.

    PHASE 1 (serial): Recon → Auth → API Schema Discovery
    PHASE 2 (parallel): DAST + SAST
    PHASE 3 (serial): Correlation → Report

    Context propagates via PostgreSQL scan_checkpoints table, NOT task args.
    Each task receives only scan_id and reads/writes context from DB.
    """
    scan_type = scan_config.get("scan_type", "dast_sast")

    # Build phase 1: always run recon; conditionally run auth and api agent
    phase1_tasks = [run_recon_agent.si(scan_id)]
    if scan_config.get("requires_auth"):
        phase1_tasks.append(run_auth_agent.si(scan_id))
    if scan_type in ("api_testing", "dast_sast", "dast"):
        phase1_tasks.append(run_api_agent.si(scan_id))

    phase1 = chain(*phase1_tasks) if len(phase1_tasks) > 1 else phase1_tasks[0]

    # Build phase 2: parallel DAST and/or SAST
    phase2_tasks = []
    if "dast" in scan_type or scan_type == "dast_sast":
        phase2_tasks.append(run_dast_agent.si(scan_id))
    if "sast" in scan_type or scan_type == "dast_sast":
        phase2_tasks.append(run_sast_agent.si(scan_id))

    phase2 = group(*phase2_tasks) if len(phase2_tasks) > 1 else phase2_tasks[0]

    # Phase 3: always correlation + report
    phase3 = chain(
        run_correlation_agent.si(scan_id),
        run_report_agent.si(scan_id)
    )

    return chain(phase1, phase2, phase3)
```

### Agent Failure Recovery Policy

```python
# backend/workers/orchestrator.py
class OrchestratorFailurePolicy:
    """
    Defines what happens when an agent fails.
    Key design: Auth failure = block (can't scan without auth);
    most others = degrade gracefully.
    """
    POLICIES = {
        "recon_agent":        {"action": "CONTINUE_DEGRADED", "max_retries": 1},
        "auth_agent":         {"action": "PAUSE_AWAIT_USER",  "max_retries": 2},
        "api_agent":          {"action": "CONTINUE_DEGRADED", "max_retries": 1},
        "dast_agent":         {"action": "RETRY_THEN_FAIL",   "max_retries": 3},
        "sast_agent":         {"action": "RETRY_THEN_PARTIAL","max_retries": 2},
        "exploit_agent":      {"action": "SKIP_LOG",          "max_retries": 0},
        "correlation_agent":  {"action": "SKIP_LOG",          "max_retries": 1},
        "report_agent":       {"action": "RETRY_THEN_QUEUE",  "max_retries": 3},
    }

    async def handle(self, agent_name: str, error: Exception,
                     scan_id: str, retry_count: int) -> str:
        policy = self.POLICIES.get(agent_name, {"action": "SKIP_LOG", "max_retries": 0})

        if policy["action"] == "PAUSE_AWAIT_USER":
            await self._notify_user(scan_id, agent_name, str(error))
            return "PAUSE"

        if "RETRY" in policy["action"] and retry_count < policy["max_retries"]:
            return "RETRY"

        if policy["action"] in ("CONTINUE_DEGRADED", "SKIP_LOG"):
            return "SKIP"

        return "FAIL"
```

---

## SAST Context Manager (Large Codebase Chunking)

```python
# backend/engines/sast/context_manager.py
class SASTContextManager:
    """
    Prioritizes files by security relevance and chunks them to fit
    within the LLM's context window.
    """
    SYSTEM_PROMPT_TOKENS = 512
    RAG_CONTEXT_TOKENS = 1024
    RESPONSE_TOKENS = 2048

    HIGH_RISK_PATTERNS = [
        ("auth", 10), ("login", 10), ("password", 10), ("token", 8), ("secret", 10),
        ("query", 8), ("sql", 8), ("execute", 7), ("eval", 9), ("exec", 9),
        ("subprocess", 8), ("shell", 8), ("cmd", 7), ("system", 7),
        ("upload", 7), ("file", 5), ("path", 5), ("directory", 5),
        ("admin", 7), ("permission", 7), ("role", 6), ("acl", 8),
        ("payment", 9), ("card", 8), ("stripe", 7), ("billing", 7),
        ("config", 6), ("env", 8), ("key", 7), ("credential", 10),
        ("api", 5), ("route", 4), ("controller", 4), ("middleware", 8),
        ("serialize", 8), ("deserialize", 9), ("pickle", 9), ("marshal", 8),
        ("xml", 7), ("yaml", 6), ("json_load", 7),
    ]

    LOW_RISK_PATTERNS = [
        ("test", -10), ("spec", -8), ("mock", -8), ("fixture", -6),
        ("migration", -4), ("seed", -4), ("schema", -2),
        ("readme", -15), ("changelog", -15), (".lock", -20),
        ("node_modules", -50), ("dist/", -30), ("build/", -20), (".min.js", -25),
    ]

    def __init__(self, model_context_limit: int = 8192):
        self.context_limit = model_context_limit
        self.available_for_code = (
            model_context_limit
            - self.SYSTEM_PROMPT_TOKENS
            - self.RAG_CONTEXT_TOKENS
            - self.RESPONSE_TOKENS
        )

    def prioritize_and_batch(self, repo_path: str) -> list[list[dict]]:
        """
        Returns ordered batches of files to analyze.
        Each batch fits within available_for_code tokens.
        """
        files = self._score_files(repo_path)
        files.sort(key=lambda f: f["score"], reverse=True)
        return self._create_batches(files)

    def _score_files(self, repo_path: str) -> list[dict]:
        import os
        results = []
        for root, dirs, filenames in os.walk(repo_path):
            # Skip vendored/generated directories
            dirs[:] = [d for d in dirs if d not in (
                "node_modules", ".git", "dist", "build", "__pycache__",
                ".venv", "venv", "vendor"
            )]
            for fname in filenames:
                path = os.path.join(root, fname)
                rel_path = os.path.relpath(path, repo_path).lower()
                score = self._compute_score(rel_path)
                size = os.path.getsize(path)
                results.append({
                    "path": path,
                    "rel_path": rel_path,
                    "score": score,
                    "size_bytes": size,
                    "estimated_tokens": size // 4  # rough: 4 bytes per token
                })
        return results

    def _compute_score(self, rel_path: str) -> int:
        score = 0
        for pattern, weight in self.HIGH_RISK_PATTERNS:
            if pattern in rel_path:
                score += weight
        for pattern, weight in self.LOW_RISK_PATTERNS:
            if pattern in rel_path:
                score += weight  # weight is negative
        return score

    def _create_batches(self, files: list[dict]) -> list[list[dict]]:
        batches = []
        current_batch = []
        current_tokens = 0

        for f in files:
            if f["score"] < 0:
                break  # All remaining files are low-priority; skip

            tokens = f["estimated_tokens"]
            if tokens > self.available_for_code:
                # File too large: chunk by function using tree-sitter
                for chunk in self._chunk_file_by_function(f["path"]):
                    batches.append([chunk])
            elif current_tokens + tokens > self.available_for_code:
                if current_batch:
                    batches.append(current_batch)
                current_batch = [f]
                current_tokens = tokens
            else:
                current_batch.append(f)
                current_tokens += tokens

        if current_batch:
            batches.append(current_batch)
        return batches

    def _chunk_file_by_function(self, file_path: str) -> list[dict]:
        """Use tree-sitter to extract individual functions as smaller chunks."""
        # Returns list of {path, rel_path, content, start_line, end_line, function_name}
        # Each chunk ~500-1000 tokens
        pass  # Implemented with tree-sitter Python/JS/Go parsers
```

---

## RAG System Design

### Vector Store Schema

```sql
-- In the findings table: embedding VECTOR(768)
-- Separate RAG knowledge base table:

CREATE TABLE rag_documents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection  TEXT NOT NULL,     -- 'vulnerability_kb', 'past_findings', 'tool_docs'
    source_id   TEXT,              -- CWE ID, CVE ID, finding ID, etc.
    title       TEXT NOT NULL,
    content     TEXT NOT NULL,
    embedding   vector(768) NOT NULL,
    metadata    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_rag_collection ON rag_documents(collection);
CREATE INDEX idx_rag_embedding ON rag_documents USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 200);
```

### Collections

| Collection | Content | Size | Update Frequency |
|-----------|---------|------|-----------------|
| `vulnerability_kb` | CWE descriptions, OWASP entries, CVE summaries | ~50K docs | Monthly (offline NVD sync) |
| `exploit_patterns` | Anonymized payload examples, PoC patterns by CWE | ~5K docs | Quarterly |
| `tool_docs` | Nuclei template syntax, Semgrep rule patterns | ~2K docs | With tool updates |
| `past_findings` | Previous findings from completed scans (current org only) | Grows over time | Real-time |

### Retriever

```python
# backend/llm/rag/retriever.py
from pgvector.asyncpg import register_vector
import numpy as np

class RAGRetriever:
    def __init__(self, embedding_client, db_session):
        self.embedder = embedding_client
        self.db = db_session

    async def retrieve(
        self,
        query: str,
        collection: str = "vulnerability_kb",
        top_k: int = 5,
        min_score: float = 0.7
    ) -> str:
        # Embed the query
        query_embedding = await self.embedder.embed(query)

        # pgvector cosine similarity search
        from sqlalchemy import text
        result = await self.db.execute(text("""
            SELECT title, content, 1 - (embedding <=> :embedding) AS score
            FROM rag_documents
            WHERE collection = :collection
              AND 1 - (embedding <=> :embedding) > :min_score
            ORDER BY embedding <=> :embedding
            LIMIT :top_k
        """), {
            "embedding": str(query_embedding),
            "collection": collection,
            "min_score": min_score,
            "top_k": top_k
        })
        rows = result.fetchall()

        if not rows:
            return ""

        # Format as numbered list for injection into system prompt
        formatted = []
        for i, (title, content, score) in enumerate(rows, 1):
            formatted.append(f"{i}. **{title}** (relevance: {score:.2f})\n{content[:500]}")
        return "\n\n".join(formatted)
```

---

## Prompt Template System

```python
# backend/agents/prompts/
# Templates are versioned YAML files, loaded at agent init

# Example: exploit_agent_task_template.yaml
# version: "1.0"
# model_families: ["llama3", "mistral", "codellama"]
# template: |
#   Target endpoint: {{ endpoint_url }}
#   HTTP method: {{ http_method }}
#   Known parameters: {{ parameters | join(", ") }}
#   Technology stack: {{ tech_stack | join(", ") }}
#   Auth status: {{ "Authenticated" if auth_result else "Unauthenticated" }}
#   Previously discovered findings: {{ prior_findings | length }} findings
#
#   Begin by analyzing what this endpoint likely does based on its URL and parameters.
#   Then select the 3 most likely vulnerability classes to test.
#   Test each systematically using the test_payload tool.

class PromptTemplateLoader:
    def __init__(self, templates_dir: str = "backend/agents/prompts"):
        self.templates_dir = templates_dir
        self._cache: dict[str, dict] = {}

    def load(self, agent_name: str, template_name: str, model_family: str) -> str:
        """Load and render template. Falls back to generic if model-specific doesn't exist."""
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader(self.templates_dir))
        template_file = f"{agent_name}/{template_name}_{model_family}.yaml"
        # Fallback to generic
        try:
            tmpl = env.get_template(template_file)
        except Exception:
            tmpl = env.get_template(f"{agent_name}/{template_name}.yaml")
        return tmpl  # Caller renders with .render(**context)
```

---

## Model Hot-Swap Design

```python
# backend/llm/model_manager.py
import asyncio
from typing import Optional

class ModelManager:
    """
    Manages loaded LLM models. Supports hot-swapping without restarting workers.
    Only worker-ai instances run this; other workers use the API to get inference.
    """
    _instance: Optional[BaseLLMClient] = None
    _lock = asyncio.Lock()
    _config_id: Optional[str] = None

    async def get_client(self, db) -> BaseLLMClient:
        """Get the currently active model client. Loads on first call."""
        from backend.models.ai_model_config import AIModelConfig
        from sqlalchemy import select

        # Get active model config from DB
        result = await db.execute(
            select(AIModelConfig).where(AIModelConfig.is_default == True)
        )
        config = result.scalar_one_or_none()
        if not config:
            raise RuntimeError("No default AI model configured")

        async with self._lock:
            # If config changed, unload old model and load new one
            if self._config_id != str(config.id):
                await self._unload()
                self._instance = self._build_client(config)
                self._config_id = str(config.id)

        return self._instance

    def _build_client(self, config) -> BaseLLMClient:
        if config.provider == "llama_cpp":
            return LlamaCppClient(
                model_path=config.model_ref,
                n_gpu_layers=config.config.get("gpu_layers", -1),
                n_ctx=config.config.get("context_size", 8192),
                n_threads=config.config.get("threads", 8)
            )
        elif config.provider == "ollama":
            return OllamaClient(
                base_url=config.ollama_host,
                model=config.model_ref
            )
        # ... etc.

    async def _unload(self):
        """Release GPU memory before loading new model."""
        if self._instance and hasattr(self._instance, '_llm'):
            del self._instance._llm
            import gc; gc.collect()
            # For CUDA: torch.cuda.empty_cache() if applicable
        self._instance = None
        self._config_id = None
```
