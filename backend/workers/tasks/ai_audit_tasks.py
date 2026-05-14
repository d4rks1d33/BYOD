"""
AI-driven autonomous audit tasks.
The LLM is the pentester, not just an analyzer.
"""
from __future__ import annotations
import logging
from typing import Dict, Any

from core.celery_app import celery_app
from services.llm_provider import get_llm_provider
from services.llm_orchestrator import get_orchestrator, reset_orchestrator
from services.ai_auditor import AIAuditor
from services.multi_agent_system import MultiAgentOrchestrator
from models.scan import Scan
from models.finding import Finding
from models.project import Project
from sqlalchemy import select

logger = logging.getLogger(__name__)


def _get_sync_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from core.config import get_settings
    settings = get_settings()
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    return sessionmaker(bind=engine)()


def _get_llm_config():
    """Get LLM configuration from database or env"""
    from core.config import get_settings
    settings = get_settings()

    db = _get_sync_db()

    try:
        # Try to get from database (ai_model_configs table)
        from models.ai_model_config import AIModelConfig
        active_model = db.execute(
            select(AIModelConfig)
            .where(AIModelConfig.is_active == True)
            .order_by(AIModelConfig.is_default.desc())
        ).scalar_one_or_none()

        if active_model:
            provider_map = {
                "gemini": "gemini",
                "openai": "openai",
                "anthropic": "anthropic",
                "ollama": "ollama",
                "vllm": "vllm",
            }

            provider = provider_map.get(active_model.provider.lower(), "gemini")

            kwargs = {}
            if active_model.ollama_host:
                kwargs["host"] = active_model.ollama_host
            elif active_model.vllm_base_url:
                kwargs["base_url"] = active_model.vllm_base_url

            return provider, active_model.model_ref, kwargs
    except Exception as e:
        logger.warning(f"Could not load AI model from DB: {e}")

    # Fallback to environment
    if settings.GEMINI_API_KEY:
        return "gemini", "gemini-2.5-flash", {}
    elif settings.OPENAI_API_KEY:
        return "openai", "gpt-4o", {}
    elif settings.ANTHROPIC_API_KEY:
        return "anthropic", "claude-3-5-sonnet-20241022", {}
    else:
        return "ollama", "llama3.1:8b", {"host": "http://localhost:11434"}


def _do_multi_agent_audit(scan_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pure function that runs the multi-agent audit.
    Can be called directly from another task (no Celery overhead).
    """
    from services.scan_logger import scan_logger_context

    db = _get_sync_db()

    try:
        scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        project = db.execute(select(Project).where(Project.id == scan.project_id)).scalar_one_or_none()
        if not project:
            raise ValueError(f"Project {scan.project_id} not found")

        target_url = config.get("target_url") or project.target_url

        # Set up scan logger context - all LLM calls and agents will log here
        with scan_logger_context(scan_id=scan_id, project_id=str(project.id)) as scan_log:
            scan_log.info("orchestrator", f"Starting MULTI-AGENT audit for {target_url}")

            scan.status = "running"
            db.commit()

            # Reset orchestrator to pick up latest config (DB or env)
            reset_orchestrator()
            llm_orchestrator = get_orchestrator()

            status = llm_orchestrator.get_status()
            scan_log.info("orchestrator", f"LLM Orchestrator status: active={status['active']}, by_role={status['available_by_role']}")
            logger.info(f"LLM Orchestrator: {status}")

            if status["active"] == 0:
                error_msg = (
                    "No LLMs available! Configure a model in the dashboard "
                    "(Settings → AI Models) or set GEMINI_API_KEY/OPENAI_API_KEY/ANTHROPIC_API_KEY "
                    "or run Ollama locally"
                )
                scan_log.error("orchestrator", error_msg)
                raise ValueError(error_msg)

            # Create multi-agent orchestrator with scan logger
            def _log_cb(level: str, msg: str):
                # Parse "[AGENT] msg" prefix if present
                if msg.startswith("[") and "]" in msg:
                    end = msg.index("]")
                    agent = msg[1:end]
                    body = msg[end+1:].strip()
                    scan_log.log(level, agent, body)
                else:
                    scan_log.log(level, "orchestrator", msg)

            agent_orchestrator = MultiAgentOrchestrator(
                target_url=target_url,
                llm_orchestrator=llm_orchestrator,
                log_callback=_log_cb,
            )

            # Run the full audit
            result = agent_orchestrator.run_full_audit()

        # Save findings to database
        findings_created = 0
        import hashlib
        for finding_data in result["findings"]:
            title = finding_data.get("title", "Unknown finding")
            # Create dedup hash
            dedup_input = f"{project.id}:{title}:{finding_data.get('severity', 'medium')}"
            dedup_hash = hashlib.sha256(dedup_input.encode()).hexdigest()

            finding = Finding(
                project_id=project.id,
                scan_id=scan.id,
                title=title,
                description=finding_data.get("description", ""),
                severity=finding_data.get("severity", "medium").lower(),
                status="new",
                finding_type="ai_multi_agent",
                tool="multi_agent_ai",
                cvss_score=finding_data.get("cvss_score"),
                cwe_id=finding_data.get("cwe_id"),
                notes=finding_data.get("recommendation", "") or finding_data.get("raw_context", ""),
                dedup_hash=dedup_hash,
            )
            db.add(finding)
            findings_created += 1

        # Update scan
        scan.status = "completed" if result["status"] == "completed" else "failed"
        scan.statistics = {
            "agent_statistics": result["statistics"],
            "findings_total": findings_created,
            "llm_status": result.get("llm_status", {}),
            "report_generated": bool(result.get("report")),
            "report": result.get("report", "")[:50000] if result.get("report") else "",
        }

        if result.get("error"):
            scan.error = str(result["error"])[:1000]

        db.commit()

        logger.info(f"Multi-agent audit completed: {findings_created} findings")

        return {
            "status": result["status"],
            "findings_count": findings_created,
            "statistics": result["statistics"],
            "report_available": bool(result.get("report")),
        }

    except Exception as e:
        logger.error(f"Multi-agent audit failed: {e}", exc_info=True)
        try:
            scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
            if scan:
                scan.status = "failed"
                scan.error = str(e)[:1000]
                db.commit()
        except:
            pass

        return {
            "status": "error",
            "error": str(e),
            "findings_count": 0,
        }
    finally:
        db.close()


@celery_app.task(
    bind=True,
    queue="ai",
    max_retries=1,
    time_limit=10800,  # 3 hours max
    name="ai_audit_tasks.run_multi_agent_audit"
)
def run_multi_agent_audit(self, scan_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Celery task wrapper - delegates to pure function."""
    return _do_multi_agent_audit(scan_id, config)


def _do_ai_audit(scan_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pure function: Run AI-driven autonomous security audit.
    The LLM acts as the pentester, deciding what to test and how.
    """
    db = _get_sync_db()

    try:
        # Get scan
        scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        # Get project for target URL
        project = db.execute(select(Project).where(Project.id == scan.project_id)).scalar_one_or_none()
        if not project:
            raise ValueError(f"Project {scan.project_id} not found")

        target_url = config.get("target_url") or project.target_url

        logger.info(f"Starting AI audit for {target_url}")

        # Update scan status
        scan.status = "running"
        db.commit()

        # Get LLM configuration
        provider_name, model_name, provider_kwargs = _get_llm_config()

        logger.info(f"Using LLM: {provider_name}/{model_name}")

        # Create LLM provider
        llm_provider = get_llm_provider(provider_name, model_name, **provider_kwargs)

        # Create AI auditor
        auditor = AIAuditor(
            llm_provider=llm_provider,
            target_url=target_url,
            max_iterations=config.get("max_iterations", 50),
            log_callback=lambda level, msg: logger.log(
                getattr(logging, level.upper()),
                f"[{scan_id[:8]}] {msg}"
            )
        )

        # Run the audit
        result = auditor.run_audit()

        # Save findings to database
        findings_created = 0
        import hashlib
        for finding_data in result["findings"]:
            title = finding_data["title"]
            dedup_input = f"{project.id}:{title}:{finding_data.get('severity', 'medium')}"
            dedup_hash = hashlib.sha256(dedup_input.encode()).hexdigest()

            finding = Finding(
                project_id=project.id,
                scan_id=scan.id,
                title=title,
                description=finding_data["description"],
                severity=finding_data["severity"],
                status="new",
                finding_type="ai_discovered",
                tool="ai_auditor",
                cvss_score=finding_data.get("cvss_score"),
                cwe_id=finding_data.get("cwe_id"),
                notes=finding_data.get("evidence", ""),
                dedup_hash=dedup_hash,
            )
            db.add(finding)
            findings_created += 1

        # Update scan with results
        scan.status = "completed" if result["status"] == "completed" else "failed"
        scan.statistics = {
            "ai_iterations": result["statistics"]["iterations"],
            "tools_used": result["statistics"]["tools_used"],
            "findings_total": findings_created,
            "time_elapsed": result["statistics"]["time_elapsed_seconds"],
        }

        if result.get("error"):
            scan.error = str(result["error"])[:1000]

        db.commit()

        logger.info(f"AI audit completed: {findings_created} findings in {result['statistics']['iterations']} iterations")

        return {
            "status": result["status"],
            "findings_count": findings_created,
            "statistics": result["statistics"],
        }

    except Exception as e:
        logger.error(f"AI audit failed: {e}", exc_info=True)

        # Update scan status
        try:
            scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
            if scan:
                scan.status = "failed"
                scan.error = str(e)[:1000]
                db.commit()
        except:
            pass

        return {
            "status": "error",
            "error": str(e),
            "findings_count": 0,
        }

    finally:
        db.close()


@celery_app.task(
    bind=True,
    queue="ai",
    max_retries=1,
    time_limit=7200,
    name="ai_audit_tasks.run_ai_audit"
)
def run_ai_audit(self, scan_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Celery task wrapper - delegates to pure function."""
    return _do_ai_audit(scan_id, config)
