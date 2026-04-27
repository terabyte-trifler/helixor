"""
api/service.py — the data layer for the API.

Read order (cheapest → most expensive):
  1. In-memory cache (60s TTL)
  2. PostgreSQL agent_scores (Day 6)
  3. Solana RPC TrustCertificate PDA (fallback if DB doesn't have it)

Why DB first, not RPC: Day 6 stores every score with full breakdown.
The on-chain cert is a strict subset. Hitting Postgres for cached scores
is ~1ms; hitting Solana RPC is ~200ms.
"""

from __future__ import annotations

import time
from datetime import timezone

import asyncpg
import structlog

from api.cache import TTLCache
from api.schemas import AgentSummary, ScoreBreakdown, ScoreResponse

log = structlog.get_logger(__name__)

# Cache hits ~60s. Score data is valid 24h on-chain so 60s is conservative.
SCORE_CACHE_TTL_SECONDS    = 60.0
NEGATIVE_CACHE_TTL_SECONDS = 30.0   # for "not found" — shorter so new agents appear fast


class ScoreService:
    """Stateless service object (just holds the cache)."""

    def __init__(self, cache_size: int = 10_000):
        self._cache: TTLCache[ScoreResponse | None] = TTLCache(
            maxsize=cache_size,
            default_ttl=SCORE_CACHE_TTL_SECONDS,
        )

    @property
    def cache_size(self) -> int:
        return self._cache.size

    def cache_stats(self) -> dict:
        return self._cache.stats()

    def invalidate(self, agent_wallet: str) -> None:
        self._cache.invalidate(agent_wallet)

    # ─────────────────────────────────────────────────────────────────────────
    # Primary read path
    # ─────────────────────────────────────────────────────────────────────────

    async def get_score(
        self,
        conn:         asyncpg.Connection,
        agent_wallet: str,
        *,
        force_refresh: bool = False,
    ) -> ScoreResponse | None:
        """
        Return a fully-populated ScoreResponse, or None if agent is unknown
        and unregistered. None means HTTP 404.
        """
        # ── 1. Cache ─────────────────────────────────────────────────────────
        if not force_refresh:
            cached = self._cache.get(agent_wallet)
            if cached is not None:
                # Mark as cached and return
                return cached.model_copy(update={"cached": True, "served_at": int(time.time())})
            # Note: we use sentinel: cache value of None means "verified missing"
            # but TTLCache returns None for both miss and missing. So a true
            # negative cache requires explicit handling — see _cache_negative.

        # ── 2. Local DB (preferred) ──────────────────────────────────────────
        row = await conn.fetchrow(
            """
            SELECT s.*, ra.active AS agent_active
            FROM   agent_scores s
            JOIN   registered_agents ra USING (agent_wallet)
            WHERE  s.agent_wallet = $1
            """,
            agent_wallet,
        )

        if row is None:
            # Maybe the agent IS registered but not yet scored (provisional)
            reg = await conn.fetchrow(
                "SELECT active FROM registered_agents WHERE agent_wallet = $1",
                agent_wallet,
            )
            if reg is None:
                # Truly unknown — let the caller return 404
                return None

            # Provisional response: registered, no score yet
            return self._provisional_response(agent_wallet, active=reg["active"])

        # ── 3. Build response from DB row ────────────────────────────────────
        response = self._row_to_response(row)
        self._cache.set(agent_wallet, response)

        # Return with cached=False (this call computed it)
        return response.model_copy(update={"cached": False, "served_at": int(time.time())})

    # ─────────────────────────────────────────────────────────────────────────
    # Listing
    # ─────────────────────────────────────────────────────────────────────────

    async def list_agents(
        self,
        conn:    asyncpg.Connection,
        *,
        limit:   int = 50,
        offset:  int = 0,
    ) -> tuple[list[AgentSummary], int]:
        """Return (items, total). total is across the entire registered_agents table."""
        items = await conn.fetch(
            """
            SELECT
                ra.agent_wallet,
                s.score, s.alert,
                s.computed_at,
                CASE WHEN s.computed_at IS NULL THEN NULL
                     ELSE s.computed_at > NOW() - INTERVAL '48 hours'
                END AS is_fresh
            FROM   registered_agents ra
            LEFT JOIN agent_scores s USING (agent_wallet)
            WHERE  ra.active = TRUE
            ORDER BY ra.registered_at DESC
            LIMIT $1 OFFSET $2
            """,
            limit, offset,
        )
        total = await conn.fetchval(
            "SELECT COUNT(*) FROM registered_agents WHERE active = TRUE"
        )

        results = [
            AgentSummary(
                agent_wallet = r["agent_wallet"],
                score        = r["score"],
                alert        = r["alert"],
                is_fresh     = r["is_fresh"],
                updated_at   = int(r["computed_at"].timestamp()) if r["computed_at"] else None,
            )
            for r in items
        ]
        return results, total or 0

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _row_to_response(self, row) -> ScoreResponse:
        # If agent is deactivated, override response
        if not row["agent_active"]:
            return ScoreResponse(
                agent_wallet  = row["agent_wallet"],
                score         = 0,
                alert         = "RED",
                source        = "deactivated",
                success_rate  = 0.0,
                anomaly_flag  = True,
                updated_at    = int(row["computed_at"].timestamp()),
                is_fresh      = True,
                breakdown     = None,
                served_at     = int(time.time()),
                cached        = False,
            )

        computed_at_ts = int(row["computed_at"].timestamp())
        age_seconds    = int(time.time()) - computed_at_ts
        is_fresh       = age_seconds < 172_800  # 48h
        source         = "live" if is_fresh else "stale"

        success_rate_pct = float(row["window_success_rate"]) * 100.0

        breakdown = ScoreBreakdown(
            success_rate_score = row["success_rate_score"],
            consistency_score  = row["consistency_score"],
            stability_score    = row["stability_score"],
            raw_score          = row["raw_score"],
            guard_rail_applied = row["guard_rail_applied"],
        )

        return ScoreResponse(
            agent_wallet         = row["agent_wallet"],
            score                = row["score"],
            alert                = row["alert"],
            source               = source,
            success_rate         = round(success_rate_pct, 2),
            anomaly_flag         = row["anomaly_flag"],
            updated_at           = computed_at_ts,
            is_fresh             = is_fresh,
            breakdown            = breakdown,
            scoring_algo_version = row["scoring_algo_version"],
            weights_version      = row["weights_version"],
            baseline_hash_prefix = row["baseline_hash"][:32] if row["baseline_hash"] else None,
            served_at            = int(time.time()),
            cached               = False,
        )

    def _provisional_response(self, agent_wallet: str, *, active: bool) -> ScoreResponse:
        if not active:
            return ScoreResponse(
                agent_wallet = agent_wallet,
                score        = 0,
                alert        = "RED",
                source       = "deactivated",
                success_rate = 0.0,
                anomaly_flag = True,
                updated_at   = int(time.time()),
                is_fresh     = True,
                breakdown    = None,
                served_at    = int(time.time()),
                cached       = False,
            )
        return ScoreResponse(
            agent_wallet = agent_wallet,
            score        = 500,
            alert        = "YELLOW",
            source       = "provisional",
            success_rate = 100.0,
            anomaly_flag = False,
            updated_at   = 0,
            is_fresh     = False,
            breakdown    = None,
            served_at    = int(time.time()),
            cached       = False,
        )


# Module-level singleton — one cache shared by all requests
score_service = ScoreService()
