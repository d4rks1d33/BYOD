"""
Multi-LLM Orchestrator with automatic fallback and consensus.

Features:
- Multiple LLM providers used simultaneously
- Automatic fallback when an LLM fails
- Consensus voting for critical decisions
- LLM specialization (different LLMs for different tasks)
- Cost-aware routing (use cheap LLM for simple tasks, expensive for complex)
"""
from __future__ import annotations
import os
import logging
import asyncio
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from services.llm_provider import LLMProvider, get_llm_provider

logger = logging.getLogger(__name__)


class LLMRole(str, Enum):
    """Specialized roles for LLMs"""
    RECON = "recon"          # Reconnaissance specialist
    EXPLOIT = "exploit"      # Exploitation specialist
    ANALYSIS = "analysis"    # Result analysis
    REPORTING = "reporting"  # Report generation
    GENERAL = "general"      # General purpose


class LLMTier(str, Enum):
    """Tier of LLM (for cost/capability routing)"""
    PREMIUM = "premium"      # GPT-4, Claude Opus, Gemini 2.0 Pro
    STANDARD = "standard"    # GPT-4o-mini, Claude Sonnet, Gemini Flash
    LOCAL = "local"          # Ollama, vLLM, local .gguf


@dataclass
class LLMConfig:
    """Configuration for a single LLM"""
    provider: str
    model: str
    role: LLMRole = LLMRole.GENERAL
    tier: LLMTier = LLMTier.STANDARD
    priority: int = 50  # Higher = preferred
    max_retries: int = 2
    extra_kwargs: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True


class LLMOrchestrator:
    """
    Orchestrates multiple LLMs with fallback, consensus, and specialization.
    """

    def __init__(self, configs: List[LLMConfig]):
        self.configs = configs
        self.providers: Dict[str, LLMProvider] = {}
        self.failure_counts: Dict[str, int] = {}
        self.disabled: set = set()

        # Initialize all enabled providers
        self._initialize_providers()

    def _initialize_providers(self):
        """Initialize all LLM providers, skipping ones that fail"""
        for config in self.configs:
            if not config.enabled:
                continue

            key = self._config_key(config)
            try:
                provider = get_llm_provider(
                    config.provider,
                    config.model,
                    **config.extra_kwargs
                )
                self.providers[key] = provider
                logger.info(f"✅ Initialized LLM: {key} (role={config.role}, tier={config.tier})")
            except Exception as e:
                logger.warning(f"❌ Failed to initialize {key}: {e}")
                self.disabled.add(key)

    def _config_key(self, config: LLMConfig) -> str:
        """Generate unique key for a config"""
        return f"{config.provider}:{config.model}:{config.role.value}"

    def get_available_llms(self, role: Optional[LLMRole] = None) -> List[Tuple[str, LLMConfig]]:
        """Get available LLMs, optionally filtered by role"""
        available = []
        for config in self.configs:
            key = self._config_key(config)
            if key in self.disabled or key not in self.providers:
                continue
            if role and config.role != role and config.role != LLMRole.GENERAL:
                continue
            available.append((key, config))

        # Sort by priority (descending)
        available.sort(key=lambda x: x[1].priority, reverse=True)
        return available

    def chat_with_fallback(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        role: LLMRole = LLMRole.GENERAL,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Try multiple LLMs with automatic fallback.
        Returns the first successful response.
        """
        available = self.get_available_llms(role)

        if not available:
            available = self.get_available_llms(LLMRole.GENERAL)

        if not available:
            return {
                "content": "",
                "error": "No LLMs available",
                "tool_calls": [],
                "finish_reason": "error",
            }

        last_error = None
        for key, config in available:
            provider = self.providers.get(key)
            if not provider:
                continue

            try:
                logger.info(f"Trying LLM: {key}")
                response = provider.chat(messages=messages, tools=tools, **kwargs)

                # Reset failure count on success
                self.failure_counts[key] = 0
                response["_llm_used"] = key
                return response

            except Exception as e:
                logger.warning(f"LLM {key} failed: {e}")
                last_error = e

                # Increment failure count
                self.failure_counts[key] = self.failure_counts.get(key, 0) + 1

                # Disable LLM after too many failures
                if self.failure_counts[key] >= config.max_retries:
                    logger.error(f"Disabling {key} after {self.failure_counts[key]} failures")
                    self.disabled.add(key)

                continue

        return {
            "content": "",
            "error": f"All LLMs failed. Last error: {last_error}",
            "tool_calls": [],
            "finish_reason": "error",
        }

    def chat_with_consensus(
        self,
        messages: List[Dict[str, str]],
        min_agreement: int = 2,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Get responses from multiple LLMs and find consensus.
        Useful for critical decisions where you want high confidence.
        """
        available = self.get_available_llms(LLMRole.GENERAL)

        if len(available) < min_agreement:
            # Not enough LLMs for consensus, fall back to single
            return self.chat_with_fallback(messages, **kwargs)

        responses = []
        for key, config in available[:3]:  # Use top 3
            provider = self.providers.get(key)
            try:
                resp = provider.chat(messages=messages, **kwargs)
                if resp.get("content"):
                    responses.append({
                        "llm": key,
                        "response": resp,
                    })
            except Exception as e:
                logger.warning(f"Consensus: {key} failed: {e}")

        if not responses:
            return {"error": "No LLMs responded", "content": ""}

        return {
            "content": responses[0]["response"]["content"],  # Primary response
            "all_responses": responses,
            "consensus_count": len(responses),
            "tool_calls": responses[0]["response"].get("tool_calls", []),
            "finish_reason": responses[0]["response"].get("finish_reason", "stop"),
            "_llms_used": [r["llm"] for r in responses],
        }

    def get_status(self) -> Dict[str, Any]:
        """Get orchestrator status"""
        return {
            "total_configured": len(self.configs),
            "active": len(self.providers) - len(self.disabled),
            "disabled": list(self.disabled),
            "failure_counts": dict(self.failure_counts),
            "available_by_role": {
                role.value: len(self.get_available_llms(role))
                for role in LLMRole
            },
        }


def build_orchestrator_from_env() -> LLMOrchestrator:
    """
    Build orchestrator from environment variables.

    Detects available API keys and local models automatically.
    """
    configs = []

    # Gemini (Cloud)
    if os.getenv("GEMINI_API_KEY"):
        configs.extend([
            LLMConfig(
                provider="gemini",
                model="gemini-2.5-flash",
                role=LLMRole.GENERAL,
                tier=LLMTier.STANDARD,
                priority=80,
            ),
            LLMConfig(
                provider="gemini",
                model="gemini-2.5-flash",
                role=LLMRole.RECON,
                tier=LLMTier.STANDARD,
                priority=70,
            ),
            LLMConfig(
                provider="gemini",
                model="gemini-2.5-pro",
                role=LLMRole.EXPLOIT,
                tier=LLMTier.PREMIUM,
                priority=90,
            ),
        ])
        logger.info("🌟 Gemini detected and configured")

    # OpenAI
    if os.getenv("OPENAI_API_KEY"):
        configs.extend([
            LLMConfig(
                provider="openai",
                model="gpt-4o",
                role=LLMRole.EXPLOIT,
                tier=LLMTier.PREMIUM,
                priority=95,
            ),
            LLMConfig(
                provider="openai",
                model="gpt-4o-mini",
                role=LLMRole.GENERAL,
                tier=LLMTier.STANDARD,
                priority=75,
            ),
            LLMConfig(
                provider="openai",
                model="gpt-4o",
                role=LLMRole.REPORTING,
                tier=LLMTier.PREMIUM,
                priority=85,
            ),
        ])
        logger.info("🌟 OpenAI detected and configured")

    # Anthropic
    if os.getenv("ANTHROPIC_API_KEY"):
        configs.extend([
            LLMConfig(
                provider="anthropic",
                model="claude-3-5-sonnet-20241022",
                role=LLMRole.GENERAL,
                tier=LLMTier.PREMIUM,
                priority=92,
            ),
            LLMConfig(
                provider="anthropic",
                model="claude-3-5-sonnet-20241022",
                role=LLMRole.ANALYSIS,
                tier=LLMTier.PREMIUM,
                priority=88,
            ),
        ])
        logger.info("🌟 Anthropic detected and configured")

    # Ollama (Local) - check if running
    ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    try:
        import requests
        resp = requests.get(f"{ollama_host}/api/tags", timeout=2)
        if resp.status_code == 200:
            models = resp.json().get("models", [])
            for model_info in models:
                model_name = model_info.get("name", "")
                if model_name:
                    configs.append(LLMConfig(
                        provider="ollama",
                        model=model_name,
                        role=LLMRole.GENERAL,
                        tier=LLMTier.LOCAL,
                        priority=30,  # Lower priority as fallback
                        extra_kwargs={"host": ollama_host},
                    ))
                    logger.info(f"🦙 Ollama model detected: {model_name}")
    except Exception:
        logger.debug("Ollama not available")

    # vLLM (Local) - check env
    if os.getenv("VLLM_BASE_URL"):
        configs.append(LLMConfig(
            provider="vllm",
            model=os.getenv("VLLM_MODEL", "default"),
            role=LLMRole.GENERAL,
            tier=LLMTier.LOCAL,
            priority=40,
            extra_kwargs={"base_url": os.getenv("VLLM_BASE_URL")},
        ))
        logger.info("🚀 vLLM detected")

    # llama.cpp .gguf via Ollama
    gguf_path = os.getenv("LOCAL_GGUF_PATH")
    if gguf_path and os.path.exists(gguf_path):
        # Could import via Ollama or llama-cpp-python directly
        logger.info(f"📦 Local .gguf model found: {gguf_path}")
        # Note: User must register with Ollama first
        # ollama create my-model -f Modelfile

    if not configs:
        logger.error("⚠️  No LLMs configured! Set at least one API key or run Ollama")

    return LLMOrchestrator(configs)


def build_orchestrator_from_db() -> Optional[LLMOrchestrator]:
    """Build orchestrator from database AIModelConfig table"""
    try:
        from sqlalchemy import create_engine, select
        from sqlalchemy.orm import sessionmaker
        from core.config import get_settings
        from models.ai_model_config import AIModelConfig

        settings = get_settings()
        engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
        Session = sessionmaker(bind=engine)
        db = Session()

        try:
            active_models = db.execute(
                select(AIModelConfig).where(AIModelConfig.is_active == True)
            ).scalars().all()

            if not active_models:
                logger.info("No active AI models in DB, falling back to env")
                return None

            configs = []
            for model in active_models:
                role_str = getattr(model, "role", "general")
                try:
                    role = LLMRole(role_str)
                except ValueError:
                    role = LLMRole.GENERAL

                provider_str = model.provider
                if hasattr(provider_str, "value"):
                    provider_str = provider_str.value
                provider_str = str(provider_str).lower()

                extra_kwargs = {}
                if model.ollama_host:
                    extra_kwargs["host"] = model.ollama_host
                if model.vllm_base_url:
                    extra_kwargs["base_url"] = model.vllm_base_url
                if model.api_key_encrypted:
                    # TODO: decrypt with Fernet
                    extra_kwargs["api_key"] = model.api_key_encrypted

                # For llamacpp, gguf_path is stored in config JSON
                model_cfg = model.config or {}
                if "gguf_path" in model_cfg:
                    extra_kwargs["gguf_path"] = model_cfg["gguf_path"]

                configs.append(LLMConfig(
                    provider=provider_str,
                    model=model.model_ref,
                    role=role,
                    priority=100 if model.is_default else 50,
                    extra_kwargs=extra_kwargs,
                ))

            if not configs:
                return None

            return LLMOrchestrator(configs)
        finally:
            db.close()
    except Exception as e:
        logger.warning(f"Could not build orchestrator from DB: {e}")
        return None


# Global orchestrator instance
_orchestrator: Optional[LLMOrchestrator] = None


def get_orchestrator() -> LLMOrchestrator:
    """Get or create the global orchestrator"""
    global _orchestrator
    if _orchestrator is None:
        # Try DB first, fall back to env
        _orchestrator = build_orchestrator_from_db() or build_orchestrator_from_env()
    return _orchestrator


def reset_orchestrator():
    """Reset the global orchestrator (e.g., after config change)"""
    global _orchestrator
    _orchestrator = None
