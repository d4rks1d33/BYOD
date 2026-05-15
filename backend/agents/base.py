from __future__ import annotations
import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


class BaseLLMClient(ABC):
    @abstractmethod
    async def generate(self, messages: list[dict], tools: Optional[list] = None,
                       max_tokens: int = 2048, temperature: float = 0.1) -> dict: ...

    @abstractmethod
    async def embed(self, text: str) -> list[float]: ...


class OllamaClient(BaseLLMClient):
    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3.2:3b") -> None:
        self.host = host.rstrip("/")
        self.model = model

    async def generate(self, messages: list[dict], tools: Optional[list] = None,
                       max_tokens: int = 2048, temperature: float = 0.1) -> dict:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"num_predict": max_tokens, "temperature": temperature},
        }
        if tools:
            payload["tools"] = tools

        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(f"{self.host}/api/chat", json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("message", {})

    async def embed(self, text: str) -> list[float]:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                f"{self.host}/api/embeddings",
                json={"model": "nomic-embed-text", "prompt": text},
            )
            response.raise_for_status()
            return response.json().get("embedding", [])


class LlamaCppClient(BaseLLMClient):
    def __init__(self, model_path: str, n_ctx: int = 4096) -> None:
        self._model_path = model_path
        self._n_ctx = n_ctx
        self._llm = None

    def _get_llm(self):
        if self._llm is None:
            from llama_cpp import Llama
            self._llm = Llama(
                model_path=self._model_path,
                n_ctx=self._n_ctx,
                n_gpu_layers=-1,
                verbose=False,
            )
        return self._llm

    async def generate(self, messages: list[dict], tools: Optional[list] = None,
                       max_tokens: int = 2048, temperature: float = 0.1) -> dict:
        llm = self._get_llm()
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: llm.create_chat_completion(
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                tools=tools,
            )
        )
        return result["choices"][0]["message"]

    async def embed(self, text: str) -> list[float]:
        llm = self._get_llm()
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, lambda: llm.create_embedding(text))
        return result["data"][0]["embedding"]


class AnthropicClient(BaseLLMClient):
    """Claude via Anthropic API."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6") -> None:
        self.api_key = api_key
        self.model = model

    async def generate(self, messages: list[dict], tools: Optional[list] = None,
                       max_tokens: int = 2048, temperature: float = 0.1) -> dict:
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=self.api_key)

        # Separate system from conversation messages
        system_content = ""
        conv_messages = []
        for m in messages:
            if m["role"] == "system":
                system_content = m["content"]
            else:
                conv_messages.append({"role": m["role"], "content": m.get("content", "")})

        kwargs: dict[str, Any] = dict(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=conv_messages,
        )
        if system_content:
            kwargs["system"] = system_content
        if tools:
            # Convert OpenAI-style tool schemas to Anthropic format
            kwargs["tools"] = [
                {
                    "name": t["function"]["name"],
                    "description": t["function"].get("description", ""),
                    "input_schema": t["function"].get("parameters", {}),
                }
                for t in tools
            ]

        response = await client.messages.create(**kwargs)
        text = ""
        tool_calls = []
        for block in response.content:
            if block.type == "text":
                text = block.text
            elif block.type == "tool_use":
                tool_calls.append({
                    "function": {
                        "name": block.name,
                        "arguments": json.dumps(block.input),
                    }
                })
        return {"role": "assistant", "content": text, "tool_calls": tool_calls}

    async def embed(self, text: str) -> list[float]:
        # Anthropic has no embedding API — fall back to a simple hash-based stub
        # In production, use a dedicated embedding model via Ollama
        logger.warning("AnthropicClient.embed() not supported — returning zero vector")
        return [0.0] * 768


class OpenAIClient(BaseLLMClient):
    """GPT via OpenAI API."""

    def __init__(self, api_key: str, model: str = "gpt-4o") -> None:
        self.api_key = api_key
        self.model = model

    async def generate(self, messages: list[dict], tools: Optional[list] = None,
                       max_tokens: int = 2048, temperature: float = 0.1) -> dict:
        import openai
        client = openai.AsyncOpenAI(api_key=self.api_key)

        kwargs: dict[str, Any] = dict(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = await client.chat.completions.create(**kwargs)
        choice = response.choices[0].message
        tool_calls = []
        if choice.tool_calls:
            tool_calls = [
                {
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    }
                }
                for tc in choice.tool_calls
            ]
        return {
            "role": "assistant",
            "content": choice.content or "",
            "tool_calls": tool_calls,
        }

    async def embed(self, text: str) -> list[float]:
        import openai
        client = openai.AsyncOpenAI(api_key=self.api_key)
        response = await client.embeddings.create(
            model="text-embedding-3-small",
            input=text,
        )
        return response.data[0].embedding


class GeminiClient(BaseLLMClient):
    """Gemini via Google Generative AI API."""

    def __init__(self, api_key: str, model: str = "gemini-2.0-flash") -> None:
        self.api_key = api_key
        self.model = model

    async def generate(self, messages: list[dict], tools: Optional[list] = None,
                       max_tokens: int = 2048, temperature: float = 0.1) -> dict:
        import google.generativeai as genai
        genai.configure(api_key=self.api_key)

        # Gemini uses a different message format
        system_text = ""
        history = []
        last_user = ""
        for m in messages:
            if m["role"] == "system":
                system_text = m["content"]
            elif m["role"] == "user":
                last_user = m["content"]
                if history:
                    history.append({"role": "user", "parts": [m["content"]]})
            elif m["role"] == "assistant":
                history.append({"role": "model", "parts": [m.get("content", "")]})

        model = genai.GenerativeModel(
            model_name=self.model,
            system_instruction=system_text or None,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=temperature,
            ),
        )

        loop = asyncio.get_event_loop()
        if history:
            chat = model.start_chat(history=history[:-1])
            response = await loop.run_in_executor(None, lambda: chat.send_message(last_user))
        else:
            response = await loop.run_in_executor(None, lambda: model.generate_content(last_user))

        text = response.text if hasattr(response, "text") else ""
        return {"role": "assistant", "content": text, "tool_calls": []}

    async def embed(self, text: str) -> list[float]:
        import google.generativeai as genai
        genai.configure(api_key=self.api_key)
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: genai.embed_content(
                model="models/text-embedding-004",
                content=text,
            ),
        )
        return result["embedding"]


def build_llm_client(provider: str, model_ref: str, config: dict | None = None,
                     ollama_host: str | None = None) -> BaseLLMClient:
    """Factory: create the right LLM client from provider name + credentials."""
    from core.config import get_settings
    settings = get_settings()
    cfg = config or {}

    if provider == "anthropic":
        key = cfg.get("api_key") or settings.ANTHROPIC_API_KEY
        if not key:
            raise ValueError("ANTHROPIC_API_KEY not set")
        return AnthropicClient(api_key=key, model=model_ref or settings.ANTHROPIC_DEFAULT_MODEL)

    if provider == "openai":
        key = cfg.get("api_key") or settings.OPENAI_API_KEY
        if not key:
            raise ValueError("OPENAI_API_KEY not set")
        return OpenAIClient(api_key=key, model=model_ref or settings.OPENAI_DEFAULT_MODEL)

    if provider == "gemini":
        key = cfg.get("api_key") or settings.GEMINI_API_KEY
        if not key:
            raise ValueError("GEMINI_API_KEY not set")
        return GeminiClient(api_key=key, model=model_ref or settings.GEMINI_DEFAULT_MODEL)

    if provider == "ollama":
        host = ollama_host or cfg.get("host") or settings.OLLAMA_HOST
        return OllamaClient(host=host, model=model_ref)

    # Default: llama.cpp with local .gguf
    n_ctx = cfg.get("n_ctx", 4096)
    return LlamaCppClient(model_path=model_ref, n_ctx=n_ctx)


@dataclass
class AgentContext:
    scan_id: str = ""
    project_id: str = ""
    target_url: str = ""
    target_type: str = "web_application"
    scope_urls: list[str] = field(default_factory=list)
    auth_result: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    endpoints_discovered: list[str] = field(default_factory=list)
    scan_config: dict = field(default_factory=dict)
    phase: str = "init"
    iteration: int = 0

    def with_update(self, **kwargs) -> "AgentContext":
        data = asdict(self)
        data.update(kwargs)
        return AgentContext(**data)

    @classmethod
    async def load(cls, scan_id: str, phase: str, db) -> Optional["AgentContext"]:
        try:
            from sqlalchemy import select
            from models.scan import ScanCheckpoint
            result = db.execute(
                select(ScanCheckpoint).where(
                    ScanCheckpoint.scan_id == scan_id,
                    ScanCheckpoint.phase == phase,
                )
            ).scalar_one_or_none()
            if result and result.context_data:
                return cls(**result.context_data)
        except Exception:
            pass
        return None

    async def save(self, phase: str, db) -> None:
        from datetime import datetime, timezone
        from models.scan import ScanCheckpoint
        from sqlalchemy import select
        existing = db.execute(
            select(ScanCheckpoint).where(
                ScanCheckpoint.scan_id == self.scan_id,
                ScanCheckpoint.phase == phase,
            )
        ).scalar_one_or_none()

        data = asdict(self)
        if existing:
            existing.context_data = data
            existing.saved_at = datetime.now(timezone.utc)
        else:
            import uuid
            cp = ScanCheckpoint(
                id=uuid.uuid4(),
                scan_id=self.scan_id,
                phase=phase,
                context_data=data,
                saved_at=datetime.now(timezone.utc),
            )
            db.add(cp)
        db.flush()


_DYNAMIC_TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "write_and_run",
            "description": (
                "Write a Python script and execute it immediately. "
                "Use this to craft custom exploits, PoC scripts, scanners, or any "
                "tool you need that isn't available. The script runs in a fresh venv. "
                "Declare pip requirements in a comment on line 1: `# requires: requests beautifulsoup4`"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "One-sentence description of what this script does and why",
                    },
                    "code": {
                        "type": "string",
                        "description": "Complete, runnable Python script. Include `# requires: pkg` on line 1 if needed.",
                    },
                    "env": {
                        "type": "object",
                        "description": "Optional dict of environment variables to pass to the script (e.g. target URL)",
                        "additionalProperties": {"type": "string"},
                    },
                },
                "required": ["description", "code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "save_poc",
            "description": (
                "Save a proof-of-concept script or artifact to the report. "
                "Call this after write_and_run confirms a vulnerability — it attaches "
                "the script and output as evidence linked to a finding."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "code": {"type": "string", "description": "The PoC script content"},
                    "output": {"type": "string", "description": "Script output proving the vulnerability"},
                    "finding_type": {"type": "string", "description": "e.g. sqli, rce, ssrf, lfi, xss"},
                    "endpoint": {"type": "string"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                },
                "required": ["title", "code", "output", "finding_type", "severity"],
            },
        },
    },
]


class BaseAgent(ABC):
    MAX_ITERATIONS = 20

    def __init__(self, llm_client: BaseLLMClient, context: AgentContext,
                 redis_client=None, db=None) -> None:
        self.llm = llm_client
        self.context = context
        self.redis = redis_client
        self.db = db
        self._pocs: list[dict] = []

    @abstractmethod
    def get_tools(self) -> list[dict]: ...

    @abstractmethod
    def get_system_prompt(self) -> str: ...

    def _all_tools(self) -> list[dict]:
        """Merge agent-specific tools with the universal dynamic-tool set."""
        return self.get_tools() + _DYNAMIC_TOOLS_SCHEMA

    async def run(self) -> AgentContext:
        messages = [
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": self._build_initial_user_message()},
        ]
        tools = self._all_tools()

        for i in range(self.MAX_ITERATIONS):
            self.context = self.context.with_update(iteration=i)

            try:
                response = await self.llm.generate(messages=messages, tools=tools)
            except Exception as e:
                logger.error("LLM generation failed at iteration %d: %s", i, e)
                break

            messages.append({"role": "assistant", "content": response.get("content", "")})

            tool_calls = response.get("tool_calls", [])
            if not tool_calls:
                # No tool call = done
                break

            for tc in tool_calls:
                fn = tc.get("function", {})
                tool_name = fn.get("name", "")
                try:
                    tool_args = json.loads(fn.get("arguments", "{}"))
                except json.JSONDecodeError:
                    tool_args = {}

                if tool_name == "finish":
                    return self.context

                tool_result = await self._call_tool(tool_name, tool_args)
                messages.append({
                    "role": "tool",
                    "content": str(tool_result),
                    "name": tool_name,
                })

        return self.context

    async def _call_tool(self, tool_name: str, tool_args: dict) -> str:
        method = getattr(self, f"_tool_{tool_name}", None)
        if not method:
            return f"Error: unknown tool '{tool_name}'"
        try:
            result = await method(**tool_args)
            return json.dumps(result) if isinstance(result, (dict, list)) else str(result)
        except Exception as e:
            logger.error("Tool %s failed: %s", tool_name, e)
            return f"Error: {e}"

    def _validate_scope(self, url: str) -> bool:
        if not self.context.scope_urls:
            return True
        return any(url.startswith(s) for s in self.context.scope_urls)

    def _build_initial_user_message(self) -> str:
        return (
            f"Target: {self.context.target_url}\n"
            f"Scope: {', '.join(self.context.scope_urls) or 'same as target'}\n"
            f"Scan config: {json.dumps(self.context.scan_config, indent=2)}\n"
            f"Begin analysis."
        )

    async def _tool_finish(self, summary: str = "", **kwargs) -> dict:
        return {"done": True, "summary": summary}

    async def _tool_write_and_run(
        self,
        description: str,
        code: str,
        env: dict | None = None,
        **kwargs,
    ) -> dict:
        from agents.dynamic_tools import DynamicToolExecutor
        executor = DynamicToolExecutor(timeout=60)

        logger.info(
            "Dynamic tool: %s | scan=%s | hash=%s",
            description, self.context.scan_id,
            __import__("hashlib").sha256(code.encode()).hexdigest()[:8],
        )

        # Log to Redis scan stream
        if self.redis:
            try:
                key = f"scan:{self.context.scan_id}:logs"
                self.redis.xadd(key, {"level": "INFO", "msg": f"[tool] {description}"}, maxlen=10000, approximate=True)
            except Exception:
                pass

        result = await executor.execute(code, env_vars=env or {})

        output_preview = result.stdout[:2000] if result.stdout else result.stderr[:2000]

        return {
            "description": description,
            "success": result.success,
            "exit_code": result.exit_code,
            "stdout": result.stdout[:4000],
            "stderr": result.stderr[:2000],
            "elapsed_seconds": round(result.elapsed_seconds, 2),
            "requirements_installed": result.requirements_installed,
        }

    async def _tool_save_poc(
        self,
        title: str,
        code: str,
        output: str,
        finding_type: str,
        severity: str,
        endpoint: str = "",
        **kwargs,
    ) -> dict:
        poc = {
            "title": title,
            "code": code,
            "output": output,
            "finding_type": finding_type,
            "severity": severity,
            "endpoint": endpoint,
        }
        self._pocs.append(poc)

        # Add as a confirmed finding in context
        finding = {
            "type": finding_type,
            "title": title,
            "endpoint": endpoint,
            "severity": severity,
            "poc_code": code,
            "confirmed": True,
            "evidence": output[:1000],
        }
        self.context = self.context.with_update(
            findings=self.context.findings + [finding]
        )

        logger.info("PoC saved: %s | severity=%s | endpoint=%s", title, severity, endpoint)

        return {"saved": True, "title": title, "poc_index": len(self._pocs) - 1}

    @property
    def pocs(self) -> list[dict]:
        return self._pocs
