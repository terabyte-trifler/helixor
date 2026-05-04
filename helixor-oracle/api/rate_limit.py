"""
api/rate_limit.py — per-IP token-bucket rate limiter.

Token bucket: anonymous callers are limited by IP. Valid operator API keys
are limited by key hash and tier, so quota follows the customer across API
replicas instead of the source IP.

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

from api.auth import extract_bearer_token, hash_api_key, looks_like_operator_key
from api.redis_client import RedisError, get_redis, redis_key
from indexer import db
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


_limiters: dict[str, RateLimiter] = {}


def _local_limiter(name: str, capacity: int, refill_per_second: float) -> RateLimiter:
    limiter = _limiters.get(name)
    if limiter is None:
        limiter = RateLimiter(capacity=capacity, refill_per_second=refill_per_second)
        _limiters[name] = limiter
    return limiter


def _quota_for_tier(tier: str | None) -> tuple[int, float]:
    if tier == "team":
        capacity = settings.rate_limit_team_capacity
    elif tier == "partner":
        capacity = settings.rate_limit_partner_capacity
    elif tier == "free":
        capacity = settings.rate_limit_free_capacity
    else:
        capacity = settings.rate_limit_capacity
    return capacity, capacity / 60


async def _operator_tier_from_cache(api_key_hash: str) -> str | None:
    client = get_redis()
    if client is None:
        return None
    try:
        return await client.get(redis_key("operator_tier", api_key_hash))
    except RedisError as exc:
        log.warning("redis_operator_tier_get_failed", error=str(exc))
        return None


async def _cache_operator_tier(api_key_hash: str, tier: str) -> None:
    client = get_redis()
    if client is None:
        return
    try:
        await client.setex(
            redis_key("operator_tier", api_key_hash),
            settings.api_key_tier_cache_seconds,
            tier,
        )
    except RedisError as exc:
        log.warning("redis_operator_tier_set_failed", error=str(exc))


async def _resolve_api_key_tier(api_key: str | None) -> tuple[str | None, str | None]:
    if not looks_like_operator_key(api_key):
        return None, None

    assert api_key is not None
    api_key_hash = hash_api_key(api_key)
    cached_tier = await _operator_tier_from_cache(api_key_hash)
    if cached_tier:
        return api_key_hash, cached_tier

    try:
        pool = await db.get_pool()
        async with pool.acquire() as conn:
            tier = await conn.fetchval(
                """
                SELECT tier
                FROM operators
                WHERE api_key_hash = $1 AND enabled = TRUE
                """,
                api_key_hash,
            )
    except Exception as exc:
        log.warning("api_key_tier_lookup_failed", error=str(exc))
        return None, None

    if not tier:
        return None, None

    await _cache_operator_tier(api_key_hash, tier)
    return api_key_hash, tier


async def _consume_redis(
    limiter_key: str,
    *,
    capacity: int,
    refill_per_second: float,
    cost: float = 1.0,
) -> bool | None:
    client = get_redis()
    if client is None:
        return None

    ttl_seconds = max(
        60,
        int((capacity / refill_per_second) * 2),
    )
    try:
        allowed = await client.eval(
            _TOKEN_BUCKET_LUA,
            1,
            redis_key("rate", limiter_key),
            int(time.time() * 1000),
            capacity,
            refill_per_second / 1000,
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

    api_key_hash, tier = await _resolve_api_key_tier(
        extract_bearer_token(request.headers.get("authorization"))
    )
    if api_key_hash:
        limiter_key = f"api_key:{api_key_hash}"
    else:
        limiter_key = f"ip:{client_ip}"

    capacity, refill_per_second = _quota_for_tier(tier)
    allowed = await _consume_redis(
        limiter_key,
        capacity=capacity,
        refill_per_second=refill_per_second,
    )
    if allowed is None:
        allowed = _local_limiter(tier or "anonymous", capacity, refill_per_second).consume(
            limiter_key
        )

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "Rate limit exceeded",
                "code": "RATE_LIMITED",
                "tier": tier or "anonymous",
            },
            headers={"Retry-After": "60"},
        )


def gc_buckets() -> int:
    return sum(limiter.gc() for limiter in _limiters.values())


def reset_rate_limiter() -> None:
    for limiter in _limiters.values():
        limiter.reset()
