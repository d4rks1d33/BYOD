"""
Centralized scan logger for verbose AI debugging.

Persists logs to Redis stream so the frontend can replay them.
"""
from __future__ import annotations
import json
import logging
import threading
from datetime import datetime, timezone
from typing import Optional, Any

logger = logging.getLogger(__name__)


class ScanLogger:
    """
    Persistent scan logger that writes to Redis Stream + stdlib logging.

    Thread-local context allows agents to log without passing scan_id everywhere.
    Logs are persisted under `scan:log:{scan_id}` Redis stream.
    """

    _local = threading.local()

    def __init__(self, scan_id: str, redis_client=None):
        self.scan_id = scan_id
        self._redis = redis_client
        self._log_key = f"scan:log:{scan_id}"
        self._project_id: Optional[str] = None

    @classmethod
    def get_current(cls) -> Optional["ScanLogger"]:
        """Get the active ScanLogger from thread-local context."""
        return getattr(cls._local, "logger", None)

    @classmethod
    def set_current(cls, scan_logger: Optional["ScanLogger"]) -> None:
        """Set the active ScanLogger for the current thread."""
        if scan_logger is None:
            if hasattr(cls._local, "logger"):
                del cls._local.logger
        else:
            cls._local.logger = scan_logger

    def _get_redis(self):
        if self._redis is not None:
            return self._redis
        # Lazy import to avoid circular deps
        try:
            import redis as redis_sync
            from core.config import get_settings
            settings = get_settings()
            self._redis = redis_sync.from_url(settings.REDIS_URL, decode_responses=True)
        except Exception as e:
            logger.warning(f"Could not init Redis for scan logger: {e}")
            return None
        return self._redis

    def _publish_progress(self, level: str, agent: str, message: str) -> None:
        """Publish to pubsub so WebSocket consumers see it live."""
        if not self._project_id:
            return
        try:
            r = self._get_redis()
            if r is None:
                return
            channel = f"ws:pubsub:project:{self._project_id}"
            payload = json.dumps({
                "type": "scan.log",
                "scan_id": self.scan_id,
                "level": level,
                "agent": agent,
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            r.publish(channel, payload)
        except Exception as e:
            logger.debug(f"Failed to publish scan log: {e}")

    def set_project_id(self, project_id: str) -> None:
        self._project_id = project_id

    def log(self, level: str, agent: str, message: str) -> None:
        """Persist a log entry to Redis stream + stdlib logging."""
        # Truncate very long messages
        msg_str = str(message)
        if len(msg_str) > 4000:
            msg_str = msg_str[:4000] + f"... [truncated, {len(message)} total chars]"

        entry = {
            "level": level.upper(),
            "agent": agent,
            "message": msg_str,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Persist to Redis stream
        r = self._get_redis()
        if r is not None:
            try:
                r.xadd(self._log_key, entry, maxlen=20000, approximate=True)
            except Exception as e:
                logger.debug(f"Failed to xadd scan log: {e}")

        # Live publish
        self._publish_progress(level, agent, msg_str)

        # Also log to stdlib
        logger.log(
            getattr(logging, level.upper(), logging.INFO),
            f"[{self.scan_id[:8]}][{agent}] {msg_str[:500]}"
        )

    # Convenience methods
    def info(self, agent: str, message: str) -> None:
        self.log("INFO", agent, message)

    def warn(self, agent: str, message: str) -> None:
        self.log("WARN", agent, message)

    def error(self, agent: str, message: str) -> None:
        self.log("ERROR", agent, message)

    def debug(self, agent: str, message: str) -> None:
        self.log("DEBUG", agent, message)

    # LLM-specific verbose helpers
    def llm_request(self, agent: str, model: str, messages: list, tools: Optional[list] = None) -> None:
        """Log an LLM request with full context."""
        try:
            last_msg = messages[-1] if messages else {}
            preview = str(last_msg.get("content", ""))[:500] if isinstance(last_msg, dict) else str(last_msg)[:500]
            tool_count = len(tools) if tools else 0
            self.log("DEBUG", agent,
                f"LLM REQUEST → {model} | {len(messages)} msgs | {tool_count} tools | last: {preview}"
            )
        except Exception as e:
            self.debug(agent, f"llm_request log failed: {e}")

    def llm_response(self, agent: str, model: str, content: str, tool_calls: Optional[list] = None) -> None:
        """Log an LLM response with content + tool calls."""
        try:
            content_preview = (content or "")[:800]
            tc_summary = ""
            if tool_calls:
                tc_names = [tc.get("name", "?") for tc in tool_calls]
                tc_summary = f" | tools: {', '.join(tc_names)}"
            self.log("INFO", agent,
                f"LLM RESPONSE ← {model}{tc_summary}\n{content_preview}"
            )
        except Exception as e:
            self.debug(agent, f"llm_response log failed: {e}")

    def tool_call(self, agent: str, tool_name: str, args: Any) -> None:
        """Log a tool invocation."""
        try:
            args_str = json.dumps(args, default=str)[:500]
            self.log("INFO", agent, f"TOOL CALL → {tool_name}({args_str})")
        except Exception as e:
            self.debug(agent, f"tool_call log failed: {e}")

    def tool_result(self, agent: str, tool_name: str, result: Any, error: Optional[str] = None) -> None:
        """Log a tool result."""
        try:
            if error:
                self.log("ERROR", agent, f"TOOL ERROR ← {tool_name}: {error}")
            else:
                result_str = json.dumps(result, default=str)[:800] if not isinstance(result, str) else result[:800]
                self.log("INFO", agent, f"TOOL RESULT ← {tool_name}\n{result_str}")
        except Exception as e:
            self.debug(agent, f"tool_result log failed: {e}")

    def finding(self, agent: str, severity: str, title: str, description: str = "") -> None:
        """Log a discovered finding."""
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}.get(severity.upper(), "🔵")
        self.log("INFO", agent, f"{emoji} FINDING [{severity}] {title} - {description[:200]}")


# Context manager for cleaner usage
class scan_logger_context:
    def __init__(self, scan_id: str, project_id: Optional[str] = None, redis_client=None):
        self.scan_logger = ScanLogger(scan_id, redis_client)
        if project_id:
            self.scan_logger.set_project_id(project_id)

    def __enter__(self) -> ScanLogger:
        ScanLogger.set_current(self.scan_logger)
        return self.scan_logger

    def __exit__(self, *args):
        ScanLogger.set_current(None)
