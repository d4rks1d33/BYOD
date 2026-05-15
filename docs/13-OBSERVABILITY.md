# AutoPentest — Observability & Logging

## Logging Strategy

### Structured JSON Logging

All application and worker logs are emitted as structured JSON. Never use unstructured log lines.

```python
# backend/core/logging.py
import logging, json, sys
from datetime import datetime

class JSONFormatter(logging.Formatter):
    SENSITIVE_KEYS = {"password", "token", "secret", "api_key", "authorization",
                      "cookie", "auth_result", "hashed_password"}

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": "autopentest-api",
            "request_id": getattr(record, "request_id", None),
            "scan_id": getattr(record, "scan_id", None),
            "user_id": getattr(record, "user_id", None),
            "agent": getattr(record, "agent", None),
        }
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Strip sensitive fields
        return json.dumps(self._sanitize(log_data))

    def _sanitize(self, data: dict) -> dict:
        """Recursively remove sensitive keys from log data."""
        if isinstance(data, dict):
            return {
                k: "[REDACTED]" if k.lower() in self.SENSITIVE_KEYS else self._sanitize(v)
                for k, v in data.items()
                if v is not None
            }
        return data

def setup_logging(level: str = "INFO"):
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper()))
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    root.addHandler(handler)
```

### Log Levels by Component

| Component | Level (Production) | Level (Development) |
|-----------|-------------------|---------------------|
| FastAPI HTTP requests | INFO | DEBUG |
| Authentication events | INFO (success), WARN (failure) | DEBUG |
| DAST requests sent | DEBUG | DEBUG |
| SAST file analysis | INFO | DEBUG |
| AI inference | INFO (latency only) | DEBUG (prompt truncated) |
| Tool execution | INFO (start/complete) | DEBUG (full args) |
| Finding storage | INFO | DEBUG |
| Database queries | WARN (slow > 1s) | DEBUG |
| Redis operations | WARN (slow > 100ms) | DEBUG |

### Log Rotation and Retention

```yaml
# docker-compose.yml logging config for each service
logging:
  driver: "json-file"
  options:
    max-size: "100m"
    max-file: "10"
    labels: "service,scan_id"
```

For production deployments with centralized logging (Grafana Loki, ELK):
```python
# Add Loki handler if LOKI_URL configured
LOKI_URL = os.environ.get("LOKI_URL")
if LOKI_URL:
    from logging_loki import LokiHandler
    handler = LokiHandler(url=f"{LOKI_URL}/loki/api/v1/push",
                          tags={"service": "autopentest"},
                          version="1")
    root.addHandler(handler)
```

---

## Metrics Collection

### Key Metrics to Expose

```python
# backend/api/routers/metrics.py
from prometheus_client import Counter, Histogram, Gauge, generate_latest
import time

# Scan metrics
SCANS_STARTED = Counter("autopentest_scans_started_total",
                         "Total scans started", ["scan_type"])
SCANS_COMPLETED = Counter("autopentest_scans_completed_total",
                           "Total scans completed", ["scan_type", "status"])
SCAN_DURATION = Histogram("autopentest_scan_duration_seconds",
                           "Scan duration in seconds",
                           buckets=[60, 300, 600, 1800, 3600, 7200])
ACTIVE_SCANS = Gauge("autopentest_active_scans",
                      "Currently running scans", ["scan_type"])

# Finding metrics
FINDINGS_TOTAL = Counter("autopentest_findings_total",
                          "Total findings stored", ["severity", "finding_type", "tool"])
CORRELATED_FINDINGS = Counter("autopentest_correlated_findings_total",
                                "Findings with SAST+DAST correlation",
                                ["correlation_method"])

# AI/LLM metrics
LLM_INFERENCE_DURATION = Histogram("autopentest_llm_inference_seconds",
                                     "LLM inference time in seconds",
                                     ["agent", "model"],
                                     buckets=[1, 5, 15, 30, 60, 120])
LLM_TOKENS_USED = Counter("autopentest_llm_tokens_total",
                            "Total tokens consumed", ["agent", "model"])
LLM_INFERENCE_ERRORS = Counter("autopentest_llm_errors_total",
                                "LLM inference errors", ["agent", "error_type"])

# Tool metrics
TOOL_EXECUTION_DURATION = Histogram("autopentest_tool_duration_seconds",
                                     "External tool execution time",
                                     ["tool"], buckets=[5, 30, 60, 300, 600])
TOOL_ERRORS = Counter("autopentest_tool_errors_total",
                        "Tool execution errors", ["tool"])

# Queue metrics
QUEUE_DEPTH = Gauge("autopentest_queue_depth",
                     "Current job queue depth", ["queue"])

# Expose endpoint
@router.get("/metrics", include_in_schema=False)
async def metrics():
    """Prometheus metrics endpoint. Protected — only accessible from localhost."""
    from fastapi import Request
    return Response(generate_latest(), media_type="text/plain")
```

### Queue Depth Monitoring

```python
# Celery beat task running every 30s
@celery_app.task
def update_queue_metrics():
    r = redis_client
    for queue in ["dast", "sast", "ai", "report", "default"]:
        depth = r.llen(f"celery:{queue}")
        QUEUE_DEPTH.labels(queue=queue).set(depth)
```

---

## Health Check Endpoints

```python
# backend/api/routers/health.py

@router.get("/health")
async def health():
    """Basic liveness check — returns 200 if API is running."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

@router.get("/ready")
async def readiness(db: AsyncSession = Depends(get_db),
                    redis: Redis = Depends(get_redis)):
    """Readiness check — returns 200 only if all dependencies are reachable."""
    checks = {}

    # Database check
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {str(e)[:100]}"

    # Redis check
    try:
        await redis.ping()
        checks["redis"] = "ok"
    except Exception as e:
        checks["redis"] = f"error: {str(e)[:100]}"

    # AI model check (worker-ai must be reachable)
    try:
        ai_status = await check_ai_worker_health()
        checks["ai_worker"] = "ok" if ai_status else "no_workers"
    except Exception as e:
        checks["ai_worker"] = f"error: {str(e)[:100]}"

    all_ok = all(v == "ok" for v in checks.values())
    return JSONResponse(
        content={"status": "ready" if all_ok else "degraded", "checks": checks},
        status_code=200 if all_ok else 503
    )

@router.get("/health/workers")
async def worker_health():
    """Check Celery worker status across all queues."""
    inspect = celery_app.control.inspect(timeout=5)
    active = inspect.active() or {}
    stats = inspect.stats() or {}

    worker_status = {}
    for worker_name, worker_stats in stats.items():
        worker_status[worker_name] = {
            "status": "ok",
            "active_tasks": len(active.get(worker_name, [])),
            "uptime": worker_stats.get("uptime"),
            "pool": worker_stats.get("pool", {}).get("implementation")
        }

    return {
        "total_workers": len(worker_status),
        "workers": worker_status,
        "queues": await get_queue_depths()
    }
```

---

## Scan Progress Tracking

```python
# backend/services/scan_progress.py
class ScanProgressTracker:
    """
    Maintains real-time scan progress in Redis.
    Workers update this; API reads it for WebSocket broadcasts and polling.
    """

    def __init__(self, scan_id: str, redis_client):
        self.scan_id = scan_id
        self.redis = redis_client
        self._key = f"scan:state:{scan_id}"

    async def update(self, **kwargs):
        """Update scan state fields atomically using HSET."""
        if kwargs:
            await self.redis.hset(self._key, mapping={k: str(v) for k, v in kwargs.items()})
            await self.redis.expire(self._key, 86400)  # 24h TTL

        # Publish update to WebSocket pub/sub channel
        await self.redis.publish(
            f"ws:pubsub:project:{await self._get_project_id()}",
            json.dumps({
                "type": "scan.progress",
                "scan_id": self.scan_id,
                **kwargs
            })
        )

    async def get(self) -> dict:
        return await self.redis.hgetall(self._key)

    async def append_log(self, level: str, agent: str, message: str):
        """Append a log line to the scan's Redis Stream."""
        entry = {
            "level": level,
            "agent": agent,
            "message": message[:1000],  # Cap log line length
            "timestamp": datetime.utcnow().isoformat()
        }
        # XADD with maxlen 10000 (auto-trim old entries)
        await self.redis.xadd(f"scan:log:{self.scan_id}", entry, maxlen=10000)

    async def refresh_heartbeat(self):
        """Keep alive signal — expires in 90s. Stall detection watches this."""
        await self.redis.setex(f"scan:heartbeat:{self.scan_id}", 90,
                               datetime.utcnow().isoformat())
```

### Stall Detection

```python
# backend/workers/tasks/monitor_tasks.py
@celery_app.task
def check_for_stalled_scans():
    """Celery beat task — runs every 2 minutes."""
    # Find scans in 'running' state with no heartbeat
    running_scans = db.execute(
        select(Scan).where(Scan.status == "running")
    ).scalars().all()

    for scan in running_scans:
        heartbeat = redis.get(f"scan:heartbeat:{scan.id}")
        if not heartbeat:
            # Heartbeat expired — scan is stalled
            logger.warning(f"Stalled scan detected: {scan.id}")
            db.execute(
                update(Scan).where(Scan.id == scan.id)
                .values(status="failed", error="Scan stalled — worker lost connection")
            )
            # Notify via WebSocket
            redis.publish(f"ws:pubsub:project:{scan.project_id}", json.dumps({
                "type": "scan.failed",
                "scan_id": str(scan.id),
                "error": "Scan stalled — worker may have crashed. Check logs."
            }))
    db.commit()
```

---

## Grafana Dashboard Panels (Recommended)

| Panel | Query | Alert Threshold |
|-------|-------|-----------------|
| Active scans | `autopentest_active_scans` | > MAX_CONCURRENT_SCANS |
| Scan failure rate | `rate(autopentest_scans_completed_total{status="failed"}[5m])` | > 0.1 |
| AI inference P95 | `histogram_quantile(0.95, autopentest_llm_inference_seconds)` | > 60s |
| Queue depth (ai) | `autopentest_queue_depth{queue="ai"}` | > 50 |
| Critical findings/hour | `rate(autopentest_findings_total{severity="critical"}[1h])` | Alert (informational) |
| DB query P99 | `pg_stat_statements latency P99` | > 1s |

---

## Audit Log Retention

```python
# backend/workers/tasks/maintenance_tasks.py
@celery_app.task
def rotate_audit_logs():
    """
    Monthly: export old audit log partitions to compressed JSON files.
    Retention: 90 days in DB, 7 years in compressed filesystem storage.
    """
    import gzip, json
    cutoff_date = datetime.utcnow() - timedelta(days=90)

    # Export old records
    old_records = db.execute(
        select(AuditLog).where(AuditLog.created_at < cutoff_date)
    ).scalars().all()

    if old_records:
        filename = f"audit-{cutoff_date.strftime('%Y%m')}.jsonl.gz"
        filepath = f"/data/audit-archive/{filename}"
        with gzip.open(filepath, "wt") as f:
            for record in old_records:
                f.write(json.dumps(record.to_dict()) + "\n")

        # Verify export before deleting
        # (Count lines in file == count of old_records)
        with gzip.open(filepath, "rt") as f:
            line_count = sum(1 for _ in f)

        if line_count == len(old_records):
            # Drop old partition (PostgreSQL range partition)
            db.execute(text(f"DROP TABLE IF EXISTS audit_logs_{cutoff_date.strftime('%Y_%m')}"))
            db.commit()
            logger.info(f"Audit log rotation: archived {line_count} entries to {filename}")
```
