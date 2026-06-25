"""
api/rate_limit.py — VULN-09 sliding-window rate limiter.

WHY
---
The audit raised four attack patterns that all reduce to the same fix:
the API answered every request at zero cost.

  1. Score-surveillance enumeration — polling every agent continuously.
  2. Oracle behavioural fingerprinting — polling /health/cluster + the
     Byzantine endpoints to map cluster topology and timing.
  3. DDoS — exhausting DB connections / worker threads.
  4. Score-transition front-running — racing tier downgrades.

A per-IP and per-key rate limit is the floor that mitigates all four.

DESIGN
------
Two buckets, exactly one of which charges each request:

  - PER-IP — default 100/min. Charges anonymous traffic.
  - PER-KEY — default 1000/min, configurable per-key. Charges
    authenticated traffic. Promotes the request out of the IP bucket.

IP extraction policy:
  - Default: `request.client.host` only. The connecting socket.
  - PHYLANX_TRUST_PROXY=1: also honour the LEFTMOST `X-Forwarded-For`
    entry. Only safe when we are behind a reverse proxy that sanitises
    that header.

PER-WORKER STATE
----------------
The limiter is process-local. Multi-worker uvicorn deployments converge
to N * limit overall (one bucket per worker). The audit-mandated real
fix is a Redis-backed limiter at the edge; THIS in-process limiter is
the defence-in-depth floor that always runs regardless of upstream
config, plus it is what makes the dev-mode single-worker process
self-protecting out of the box.

A 429 response carries a `Retry-After` header in seconds — the time
until the oldest entry in the bucket expires.
"""

from __future__ import annotations

import logging
import os
import time
from collections import deque
from dataclasses import dataclass
from threading import Lock
from typing import Deque

from fastapi import Request


logger = logging.getLogger("phylanx.api.rate_limit")


# =============================================================================
# Defaults
# =============================================================================

# Audit-mandated 60-second window.
WINDOW_SECONDS: float = 60.0

# Audit-mandated per-IP cap.
DEFAULT_PUBLIC_RATE_LIMIT_PER_MIN: int = 100


# =============================================================================
# Decision record
# =============================================================================

@dataclass(frozen=True)
class RateDecision:
    """Outcome of `SlidingWindowLimiter.check`.

    `bucket` is an opaque identifier ("ip:..." or "key:...") suitable for
    structured logging. `limit` is the cap that was applied; `remaining`
    is the leftover quota in the current window AFTER charging this
    request (zero on rejection).
    """
    allowed:       bool
    bucket:        str
    limit:         int
    remaining:     int
    retry_after_s: float


# =============================================================================
# The limiter
# =============================================================================

class SlidingWindowLimiter:
    """Per-bucket sliding-window limiter. Pure in-memory.

    `check(bucket, limit)` drops timestamps outside the window, then
    either records the hit and returns `allowed=True`, or returns
    `allowed=False` with a retry-after hint and DOES NOT record the hit.

    Thread-safe via a single coarse `Lock`. The critical section is
    microseconds; per-bucket fine-grained locking would buy nothing.
    """

    def __init__(self, *, window_seconds: float = WINDOW_SECONDS) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self._window: float = window_seconds
        self._buckets: dict[str, Deque[float]] = {}
        self._lock = Lock()

    def check(self, bucket: str, limit: int) -> RateDecision:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            q = self._buckets.get(bucket)
            if q is None:
                q = deque()
                self._buckets[bucket] = q
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= limit:
                # Retry when the oldest in-window entry expires.
                retry_after = max(0.0, q[0] - cutoff)
                return RateDecision(
                    allowed=False, bucket=bucket, limit=limit,
                    remaining=0, retry_after_s=retry_after,
                )
            q.append(now)
            return RateDecision(
                allowed=True, bucket=bucket, limit=limit,
                remaining=limit - len(q), retry_after_s=0.0,
            )

    def reset(self) -> None:
        """Test-only — clear every bucket."""
        with self._lock:
            self._buckets.clear()


# =============================================================================
# IP extraction
# =============================================================================

def client_ip(request: Request, *, trust_proxy: bool) -> str:
    """Return the IP we will attribute the request to.

    `trust_proxy=True` + an `X-Forwarded-For` header => leftmost entry
    (the original client behind a trusted reverse proxy). Otherwise the
    direct TCP peer.

    DEFAULT IS `trust_proxy=False`. Honouring `X-Forwarded-For`
    unconditionally would let any caller spoof an arbitrary IP and
    bypass the per-IP cap — only the operator who owns the reverse
    proxy can attest that the header is sanitised.
    """
    if trust_proxy:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            first = xff.split(",", 1)[0].strip()
            if first:
                return first
    client = request.client
    return client.host if client is not None else "unknown"


# =============================================================================
# Env helpers
# =============================================================================

def load_trust_proxy_from_env(
    env_var: str = "PHYLANX_TRUST_PROXY",
) -> bool:
    return os.environ.get(env_var, "").strip().lower() in {"1", "true", "yes"}


def load_public_limit_from_env(
    env_var: str = "PHYLANX_PUBLIC_RATE_LIMIT_PER_MIN",
) -> int:
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return DEFAULT_PUBLIC_RATE_LIMIT_PER_MIN
    limit = int(raw)
    if limit < 1:
        raise ValueError(f"{env_var} must be >= 1")
    return limit
