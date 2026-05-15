from __future__ import annotations
import json
import logging
import inspect
from datetime import datetime, timezone
from typing import Optional, Union

logger = logging.getLogger(__name__)

_HEARTBEAT_TTL = 90
_STATE_TTL = 86400


class ScanProgressTracker:
    def __init__(self, scan_id: str, redis_client) -> None:
        self.scan_id = scan_id
        self.redis = redis_client
        self._key = f"scan:state:{scan_id}"
        self._log_key = f"scan:log:{scan_id}"
        self._hb_key = f"scan:heartbeat:{scan_id}"
        self._project_id_cache: Optional[str] = None
        # Detect if redis client is async or sync
        self._is_async = inspect.iscoroutinefunction(getattr(redis_client, 'hset', None)) if hasattr(redis_client, 'hset') else False

    async def update(self, **kwargs) -> None:
        if not kwargs:
            return
        if self._is_async:
            await self.redis.hset(self._key, mapping={k: str(v) for k, v in kwargs.items()})
            await self.redis.expire(self._key, _STATE_TTL)
        else:
            self.redis.hset(self._key, mapping={k: str(v) for k, v in kwargs.items()})
            self.redis.expire(self._key, _STATE_TTL)

        project_id = await self._get_project_id() if self._is_async else self._get_project_id_sync()
        channel = f"ws:pubsub:project:{project_id}"
        payload = json.dumps({
            "type": "scan.progress",
            "scan_id": self.scan_id,
            **{k: str(v) for k, v in kwargs.items()},
        })
        try:
            if self._is_async:
                await self.redis.publish(channel, payload)
            else:
                self.redis.publish(channel, payload)
        except Exception:
            logger.warning("Failed to publish scan.progress", exc_info=True)

    async def get(self) -> dict:
        if self._is_async:
            raw = await self.redis.hgetall(self._key)
        else:
            raw = self.redis.hgetall(self._key)
        return {
            (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
            for k, v in (raw or {}).items()
        }

    async def append_log(self, level: str, agent: str, message: str) -> None:
        entry = {
            "level": level,
            "agent": agent,
            "message": message[:1000],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if self._is_async:
            await self.redis.xadd(self._log_key, entry, maxlen=10000, approximate=True)
        else:
            self.redis.xadd(self._log_key, entry, maxlen=10000, approximate=True)

    async def refresh_heartbeat(self) -> None:
        if self._is_async:
            await self.redis.setex(self._hb_key, _HEARTBEAT_TTL, datetime.now(timezone.utc).isoformat())
        else:
            self.redis.setex(self._hb_key, _HEARTBEAT_TTL, datetime.now(timezone.utc).isoformat())

    async def _get_project_id(self) -> str:
        if self._project_id_cache:
            return self._project_id_cache
        try:
            state = await self.redis.hget(self._key, "project_id")
            if state:
                pid = state.decode() if isinstance(state, bytes) else state
                self._project_id_cache = pid
                return pid
        except Exception:
            pass
        return "unknown"

    def _get_project_id_sync(self) -> str:
        if self._project_id_cache:
            return self._project_id_cache
        try:
            state = self.redis.hget(self._key, "project_id")
            if state:
                pid = state.decode() if isinstance(state, bytes) else state
                self._project_id_cache = pid
                return pid
        except Exception:
            pass
        return "unknown"
