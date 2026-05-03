"""
api/redis_client.py — optional shared Redis connection for API hot paths.

Redis is used when REDIS_URL is set. Local development and tests can omit it;
the API will fall back to the in-process cache/rate limiter.
"""

from __future__ import annotations

from typing import Any

import structlog

from indexer.config import settings

try:
    import redis.asyncio as redis_async
    from redis.exceptions import RedisError
except Exception:  # pragma: no cover - exercised only when dependency is absent
    redis_async = None

    class RedisError(Exception):
        pass


log = structlog.get_logger(__name__)
_redis: Any | None = None


def redis_configured() -> bool:
    return bool(settings.redis_url)


def redis_available() -> bool:
    return _redis is not None


def redis_key(*parts: str) -> str:
    clean_parts = [part.strip(":") for part in parts if part]
    return ":".join([settings.redis_prefix.strip(":"), *clean_parts])


def get_redis() -> Any | None:
    return _redis


async def init_redis() -> Any | None:
    global _redis
    if not settings.redis_url:
        log.info("redis_disabled")
        return None

    if redis_async is None:
        raise RuntimeError("REDIS_URL is set but the redis package is not installed")

    if _redis is not None:
        return _redis

    client = redis_async.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
    )
    await client.ping()
    _redis = client
    log.info("redis_ready", prefix=settings.redis_prefix)
    return _redis


async def close_redis() -> None:
    global _redis
    if _redis is None:
        return
    await _redis.aclose()
    _redis = None
    log.info("redis_closed")
