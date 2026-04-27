"""
api/cache.py — minimal in-memory TTL cache.

Why in-memory and not Redis: Day 4 explicitly cut Redis. For a single
container serving 100s of requests/second, an `OrderedDict` LRU is fine.
When you need horizontal scaling (multiple API containers), revisit.

Why cache at all: scores change at most every 24h (Day 7 cooldown). Without
caching, every API call does an RPC `getAccountInfo`. With caching, only
the first request per agent per TTL window does so.

TTL design:
  - Score data is valid for 60s in cache (long enough to absorb burst traffic,
    short enough that admin pause + recompute is reflected within ~1 minute).
  - Negative cache (agent not found) is 30s — shorter so newly registered
    agents become queryable quickly.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class CacheEntry(Generic[T]):
    value:      T
    expires_at: float


class TTLCache(Generic[T]):
    """Bounded LRU cache with per-entry TTL."""

    def __init__(self, maxsize: int = 10_000, default_ttl: float = 60.0):
        self._store: OrderedDict[str, CacheEntry[T]] = OrderedDict()
        self._maxsize = maxsize
        self._default_ttl = default_ttl
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> T | None:
        """Return cached value if present + not expired, else None."""
        entry = self._store.get(key)
        if entry is None:
            self._misses += 1
            return None

        if entry.expires_at < time.time():
            # Expired — evict
            self._store.pop(key, None)
            self._misses += 1
            return None

        # Mark as recently used
        self._store.move_to_end(key)
        self._hits += 1
        return entry.value

    def set(self, key: str, value: T, *, ttl: float | None = None) -> None:
        """Store a value with optional per-call TTL override."""
        ttl = ttl if ttl is not None else self._default_ttl
        self._store[key] = CacheEntry(value=value, expires_at=time.time() + ttl)
        self._store.move_to_end(key)
        # Evict oldest if over capacity
        while len(self._store) > self._maxsize:
            self._store.popitem(last=False)

    def invalidate(self, key: str) -> None:
        self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()

    @property
    def size(self) -> int:
        return len(self._store)

    @property
    def hit_rate(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    def stats(self) -> dict:
        return {
            "size":     self.size,
            "maxsize":  self._maxsize,
            "hits":     self._hits,
            "misses":   self._misses,
            "hit_rate": round(self.hit_rate, 4),
        }
