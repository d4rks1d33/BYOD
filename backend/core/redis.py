from __future__ import annotations
from typing import AsyncGenerator, Optional
import redis.asyncio as aioredis
from .config import get_settings

_redis_client: Optional[aioredis.Redis] = None


def create_redis_pool() -> aioredis.Redis:
    settings = get_settings()
    url = settings.REDIS_URL
    return aioredis.from_url(url, encoding="utf-8", decode_responses=True)


async def get_redis_client() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = create_redis_pool()
    return _redis_client


async def get_redis() -> AsyncGenerator[aioredis.Redis, None]:
    client = await get_redis_client()
    yield client


async def close_redis() -> None:
    global _redis_client
    if _redis_client:
        await _redis_client.aclose()
        _redis_client = None
