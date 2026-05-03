"""
api/rate_limit.py — per-IP token-bucket rate limiter.

Token bucket: each IP has a bucket holding up to `capacity` tokens. Each
request costs 1 token. Tokens refill at `refill_rate` per second. If the
bucket is empty, the request is rejected with 429.

Default: 100 tokens/min (capacity=100, refill=100/60≈1.67/s) — generous
enough for normal use, blocks runaway scripts.

Uses Redis when REDIS_URL is configured so limits are shared across API
replicas. Falls back to the local in-memory bucket if Redis is unavailable.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import structlog
from fastapi import HTTPException, Request, status

from api.redis_client import RedisError, get_redis, redis_key
from indexer.config import settings

log = structlog.get_logger(__name__)


_TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local refill_per_ms = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local ttl_ms = tonumber(ARGV[5])

local bucket = redis.call("HMGET", key, "tokens", "last_ms")
local tokens = tonumber(bucket[1])
local last_ms = tonumber(bucket[2])

if tokens == nil or last_ms == nil then
  tokens = capacity
  last_ms = now_ms
else
  local elapsed = math.max(0, now_ms - last_ms)
  tokens = math.min(capacity, tokens + (elapsed * refill_per_ms))
  last_ms = now_ms
end

local allowed = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
end

redis.call("HSET", key, "tokens", tokens, "last_ms", last_ms)
redis.call("PEXPIRE", key, ttl_ms)
return allowed
"""


@dataclass
class _Bucket:
    tokens:  float
    last_ts: float


class RateLimiter:
    def __init__(
        self,
        capacity: float = settings.rate_limit_capacity,
        refill_per_second: float = settings.rate_limit_refill_per_second,
    ):
        self.capacity     = capacity
        self.refill_rate  = refill_per_second
        self._buckets: dict[str, _Bucket] = {}

    def _bucket(self, key: str) -> _Bucket:
        now = time.time()
        b = self._buckets.get(key)
        if b is None:
            self._buckets[key] = _Bucket(tokens=self.capacity, last_ts=now)
            return self._buckets[key]

        elapsed = now - b.last_ts
        b.tokens = min(self.capacity, b.tokens + elapsed * self.refill_rate)
        b.last_ts = now
        return b

    def consume(self, key: str, cost: float = 1.0) -> bool:
        b = self._bucket(key)
        if b.tokens >= cost:
            b.tokens -= cost
            return True
        return False

    def gc(self, max_age_seconds: float = 3600.0) -> int:
        """Drop unused buckets so memory doesn't grow forever."""
        cutoff = time.time() - max_age_seconds
        stale = [k for k, b in self._buckets.items() if b.last_ts < cutoff]
        for k in stale:
            del self._buckets[k]
        return len(stale)

    def reset(self) -> None:
        """Clear all tracked buckets. Mainly useful for test isolation."""
        self._buckets.clear()


_limiter = RateLimiter()


async def _consume_redis(client_ip: str, cost: float = 1.0) -> bool | None:
    client = get_redis()
    if client is None:
        return None

    ttl_seconds = max(
        60,
        int((settings.rate_limit_capacity / settings.rate_limit_refill_per_second) * 2),
    )
    try:
        allowed = await client.eval(
            _TOKEN_BUCKET_LUA,
            1,
            redis_key("rate", client_ip),
            int(time.time() * 1000),
            settings.rate_limit_capacity,
            settings.rate_limit_refill_per_second / 1000,
            cost,
            ttl_seconds * 1000,
        )
        return bool(int(allowed))
    except RedisError as exc:
        log.warning("redis_rate_limit_failed", error=str(exc))
        return None


async def rate_limit_dep(request: Request) -> None:
    """FastAPI dependency: 429 if the caller's IP is over its budget."""
    peer_ip = request.client.host if request.client else "unknown"

    # Honour X-Forwarded-For only when the immediate peer is a trusted proxy.
    forwarded = request.headers.get("x-forwarded-for")
    if (
        forwarded
        and settings.trust_x_forwarded_for
        and peer_ip in settings.trusted_proxy_ip_set
    ):
        client_ip = forwarded.split(",")[0].strip()
    else:
        client_ip = peer_ip

    allowed = await _consume_redis(client_ip)
    if allowed is None:
        allowed = _limiter.consume(client_ip)

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": "Rate limit exceeded", "code": "RATE_LIMITED"},
            headers={"Retry-After": "60"},
        )


def gc_buckets() -> int:
    return _limiter.gc()


def reset_rate_limiter() -> None:
    _limiter.reset()
