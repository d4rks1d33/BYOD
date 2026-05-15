from __future__ import annotations
from celery import Celery
from .config import get_settings

settings = get_settings()

celery_app = Celery(
    "autopentest",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "workers.tasks.scan_tasks",
        "workers.tasks.dast_tasks",
        "workers.tasks.sast_tasks",
        "workers.tasks.ai_tasks",
        "workers.tasks.report_tasks",
        "workers.tasks.monitor_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_routes={
        "workers.tasks.dast_tasks.*": {"queue": "dast"},
        "workers.tasks.sast_tasks.*": {"queue": "sast"},
        "workers.tasks.ai_tasks.*": {"queue": "ai"},
        "workers.tasks.report_tasks.*": {"queue": "report"},
        "workers.tasks.scan_tasks.*": {"queue": "dast"},
        "workers.tasks.monitor_tasks.*": {"queue": "default"},
    },
    beat_schedule={
        "check-stalled-scans": {
            "task": "workers.tasks.monitor_tasks.check_for_stalled_scans",
            "schedule": 120.0,
        },
        "update-queue-metrics": {
            "task": "workers.tasks.monitor_tasks.update_queue_metrics",
            "schedule": 30.0,
        },
    },
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)
