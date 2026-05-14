from __future__ import annotations
import asyncio
import logging

from core.celery_app import celery_app

logger = logging.getLogger(__name__)


def _get_sync_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from core.config import get_settings
    engine = create_engine(get_settings().DATABASE_URL_SYNC, pool_pre_ping=True)
    return sessionmaker(bind=engine)()


def _get_sync_redis():
    import redis as redis_sync
    from core.config import get_settings
    return redis_sync.from_url(get_settings().REDIS_URL, decode_responses=True)


@celery_app.task(bind=True, queue="ai", max_retries=2, time_limit=600, name="ai_tasks.run_ai_analysis")
def run_ai_analysis(self, scan_id: str, agent_name: str, context_data: dict) -> dict:
    from services.scan_progress import ScanProgressTracker

    db = _get_sync_db()
    redis = _get_sync_redis()

    async def _run():
        tracker = ScanProgressTracker(scan_id, redis)
        await tracker.append_log("INFO", agent_name, f"Agent {agent_name} starting")
        await tracker.refresh_heartbeat()

        try:
            from agents.base import AgentContext, build_llm_client
            from sqlalchemy import select
            from models.ai_model_config import AIModelConfig

            # Load the active AI model config from DB
            active = db.execute(
                select(AIModelConfig).where(AIModelConfig.is_active == True)
            ).scalar_one_or_none()

            if active:
                llm = build_llm_client(
                    provider=str(active.provider.value if hasattr(active.provider, "value") else active.provider),
                    model_ref=active.model_ref,
                    config=active.config or {},
                    ollama_host=active.ollama_host,
                )
            else:
                # Fallback: try Ollama, then llama.cpp
                from core.config import get_settings
                from agents.base import OllamaClient
                settings = get_settings()
                llm = OllamaClient(host=settings.OLLAMA_HOST)

            ctx = AgentContext(
                scan_id=scan_id,
                target_url=context_data.get("target_url", ""),
                scan_config=context_data,
            )

            if agent_name == "recon_agent":
                from agents.recon import ReconAgent
                agent = ReconAgent(llm_client=llm, context=ctx, redis_client=redis, db=db)
            elif agent_name == "exploit_agent":
                from agents.exploit import ExploitAgent
                agent = ExploitAgent(llm_client=llm, context=ctx, redis_client=redis, db=db)
            else:
                await tracker.append_log("WARN", agent_name, f"Agent {agent_name} not yet implemented")
                return {"status": "skipped", "agent": agent_name}

            new_ctx = await agent.run()
            findings_count = len(getattr(new_ctx, "findings", []))

            # Persist PoC findings to DB
            pocs = getattr(agent, "pocs", [])
            if pocs:
                import hashlib
                import uuid as uuid_lib
                from sqlalchemy.exc import IntegrityError
                from models.finding import Finding
                from models.scan import Scan
                from models.enums import SeverityEnum, FindingStatusEnum

                scan_record = db.execute(
                    select(Scan).where(Scan.id == scan_id)
                ).scalar_one_or_none()
                project_id = scan_record.project_id if scan_record else None

                saved = 0
                for poc in pocs:
                    raw = f"{poc['title']}:{poc.get('endpoint', '')}:{poc['code'][:64]}"
                    dedup = hashlib.sha256(raw.encode()).hexdigest()[:64]

                    if db.execute(select(Finding).where(Finding.dedup_hash == dedup)).scalar_one_or_none():
                        continue

                    sev_str = poc.get("severity", "medium").lower()
                    try:
                        sev_enum = SeverityEnum(sev_str)
                    except ValueError:
                        sev_enum = SeverityEnum.medium

                    f = Finding(
                        id=uuid_lib.uuid4(),
                        project_id=project_id,
                        scan_id=scan_id,
                        title=poc["title"],
                        description=(poc.get("output") or "")[:2000],
                        finding_type=poc.get("finding_type", "custom"),
                        severity=sev_enum,
                        status=FindingStatusEnum.confirmed,
                        endpoint=poc.get("endpoint") or None,
                        poc_code=poc["code"],
                        tool="ai_agent",
                        confidence=0.9,
                        dedup_hash=dedup,
                    )
                    db.add(f)
                    saved += 1

                if saved:
                    try:
                        db.commit()
                        await tracker.append_log("INFO", agent_name, f"Persisted {saved} PoC findings")
                    except IntegrityError:
                        db.rollback()
                        await tracker.append_log("WARN", agent_name, "PoC persist skipped (duplicate race)")

            await tracker.append_log("INFO", agent_name, f"Agent {agent_name} complete: {findings_count} findings")
            return {"status": "completed", "findings_count": findings_count, "pocs_saved": len(pocs)}

        except ImportError as e:
            await tracker.append_log("WARN", agent_name, f"Agent {agent_name} not available: {e}")
            return {"status": "skipped", "reason": str(e)}
        except Exception as e:
            await tracker.append_log("ERROR", agent_name, f"Agent {agent_name} failed: {e}")
            raise

    try:
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(_run())
        loop.close()
        return result
    except Exception as exc:
        logger.exception("run_ai_analysis failed: agent=%s scan=%s", agent_name, scan_id)
        try:
            self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            pass
        raise
    finally:
        db.close()


@celery_app.task(bind=True, queue="ai", max_retries=1, time_limit=300, name="ai_tasks.run_correlation_analysis")
def run_correlation_analysis(self, scan_id: str) -> dict:
    db = _get_sync_db()
    redis = _get_sync_redis()

    async def _run():
        from services.scan_progress import ScanProgressTracker
        tracker = ScanProgressTracker(scan_id, redis)
        await tracker.append_log("INFO", "correlation", "Starting correlation analysis")

        try:
            from correlation.engine import CorrelationEngine
            engine = CorrelationEngine(db=db)
            correlated = await engine.correlate(scan_id)
            count = len(correlated)
        except ImportError:
            count = 0

        await tracker.append_log("INFO", "correlation", f"Correlation complete: {count} correlations")
        return {"status": "completed", "correlated_count": count}

    try:
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(_run())
        loop.close()
        return result
    except Exception as exc:
        logger.exception("run_correlation_analysis failed for %s", scan_id)
        return {"status": "error", "error": str(exc)}
    finally:
        db.close()
