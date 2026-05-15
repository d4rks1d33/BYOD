from __future__ import annotations
import asyncio
import json
import logging
import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from core.security import decode_token

logger = logging.getLogger(__name__)

router = APIRouter()


@router.websocket("/ws/projects/{project_id}/scan")
async def scan_websocket(
    websocket: WebSocket,
    project_id: uuid.UUID,
    token: str | None = Query(default=None),
):
    """Real-time scan progress stream. Authenticate via ?token= query param or first JSON message."""
    await websocket.accept()

    # Authenticate
    if not token:
        try:
            first_msg = await asyncio.wait_for(websocket.receive_text(), timeout=10.0)
            data = json.loads(first_msg)
            token = data.get("token")
        except (asyncio.TimeoutError, json.JSONDecodeError, KeyError):
            await websocket.close(code=4001)
            return

    payload = decode_token(token or "")
    if not payload:
        await websocket.close(code=4001)
        return

    user_id = payload.get("sub")
    if not user_id:
        await websocket.close(code=4001)
        return

    channel = f"ws:pubsub:project:{project_id}"

    import redis.asyncio as aioredis
    from core.config import get_settings
    settings = get_settings()

    redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(channel)

    await websocket.send_json({"type": "connected", "project_id": str(project_id)})
    logger.info("WS connected: user=%s project=%s", user_id, project_id)

    try:
        async def listen_redis():
            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        await websocket.send_text(message["data"])
                    except Exception:
                        return

        async def listen_client():
            while True:
                try:
                    msg = await websocket.receive_text()
                    data = json.loads(msg)
                    if data.get("type") == "ping":
                        await websocket.send_json({"type": "pong"})
                except WebSocketDisconnect:
                    return
                except Exception:
                    return

        await asyncio.gather(
            listen_redis(),
            listen_client(),
            return_exceptions=True,
        )
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()
        await redis_client.aclose()
        logger.info("WS disconnected: user=%s project=%s", user_id, project_id)
