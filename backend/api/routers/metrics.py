from __future__ import annotations
from fastapi import APIRouter, Request
from fastapi.responses import Response
from prometheus_client import (
    Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
)

router = APIRouter()

SCANS_STARTED = Counter("autopentest_scans_started_total", "Total scans started", ["scan_type"])
SCANS_COMPLETED = Counter("autopentest_scans_completed_total", "Total scans completed", ["scan_type", "status"])
SCAN_DURATION = Histogram("autopentest_scan_duration_seconds", "Scan duration", buckets=[60, 300, 600, 1800, 3600])
ACTIVE_SCANS = Gauge("autopentest_active_scans", "Currently running scans", ["scan_type"])
FINDINGS_TOTAL = Counter("autopentest_findings_total", "Total findings", ["severity", "finding_type", "tool"])
LLM_INFERENCE_DURATION = Histogram("autopentest_llm_inference_seconds", "LLM inference time", ["agent", "model"], buckets=[1, 5, 15, 30, 60, 120])
LLM_TOKENS_USED = Counter("autopentest_llm_tokens_total", "Total tokens consumed", ["agent", "model"])
TOOL_EXECUTION_DURATION = Histogram("autopentest_tool_duration_seconds", "Tool execution time", ["tool"], buckets=[5, 30, 60, 300, 600])
TOOL_ERRORS = Counter("autopentest_tool_errors_total", "Tool execution errors", ["tool"])
QUEUE_DEPTH = Gauge("autopentest_queue_depth", "Queue depth", ["queue"])


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request):
    if request.client and request.client.host not in ("127.0.0.1", "::1", "localhost"):
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Metrics only accessible from localhost")
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
