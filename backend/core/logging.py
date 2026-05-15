from __future__ import annotations
import json
import logging
import os
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    SENSITIVE_KEYS = {
        "password", "token", "secret", "api_key", "authorization",
        "cookie", "auth_result", "hashed_password", "access_token",
        "refresh_token", "private_key", "client_secret",
    }

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
        return json.dumps(self._sanitize(log_data))

    def _sanitize(self, data: object) -> object:
        if isinstance(data, dict):
            return {
                k: "[REDACTED]" if k.lower() in self.SENSITIVE_KEYS else self._sanitize(v)
                for k, v in data.items()
                if v is not None
            }
        if isinstance(data, list):
            return [self._sanitize(item) for item in data]
        return data


def setup_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    if root.handlers:
        root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    root.addHandler(handler)

    loki_url = os.environ.get("LOKI_URL")
    if loki_url:
        try:
            from logging_loki import LokiHandler  # type: ignore
            loki_handler = LokiHandler(
                url=f"{loki_url}/loki/api/v1/push",
                tags={"service": "autopentest"},
                version="1",
            )
            root.addHandler(loki_handler)
        except ImportError:
            pass
