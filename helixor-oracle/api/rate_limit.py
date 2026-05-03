"""
api/rate_limit.py — simple per-IP token-bucket rate limiter.

Token bucket: each IP has a bucket holding up to `capacity` tokens. Each
request costs 1 token. Tokens refill at `refill_rate` per second. If the
bucket is empty, the request is rejected with 429.

Default: 100 tokens/min (capacity=100, refill=100/60≈1.67/s) — generous
enough for normal use, blocks runaway scripts.

In-memory only. For multi-container scale, swap for Redis later.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from fastapi import HTTPException, Request, status

from indexer.config import settings


@dataclass
class _Bucket:
    tokens:  float
    last_ts: float


class RateLimiter:
    def __init__(self, capacity: float = 100, refill_per_second: float = 100 / 60):
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


def rate_limit_dep(request: Request) -> None:
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

    if not _limiter.consume(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": "Rate limit exceeded", "code": "RATE_LIMITED"},
            headers={"Retry-After": "60"},
        )


def gc_buckets() -> int:
    return _limiter.gc()


def reset_rate_limiter() -> None:
    _limiter.reset()
