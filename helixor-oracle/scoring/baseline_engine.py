"""
scoring/baseline_engine.py — orchestrator combining DB + pure signal compute.

This is what Day 7's epoch_runner imports. It:
  1. Fetches transactions for an agent's window from the DB
  2. Calls the pure signal computation
  3. Persists the result + appends to history

Public API:
  await compute_and_store(conn, agent_wallet)
  await get_or_compute(conn, agent_wallet)        # cached
  await batch_recompute(conn, agent_wallets)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import asyncpg
import structlog

from scoring import repo
from scoring.signals import (
    BaselineError,
    BaselineResult,
    InsufficientActiveDays,
    InsufficientData,
    compute_signals,
    DEFAULT_MIN_ACTIVE_DAYS,
    DEFAULT_MIN_TX_COUNT,
    DEFAULT_WINDOW_DAYS,
)

log = structlog.get_logger(__name__)


# =============================================================================
# Cache TTL
# =============================================================================
# How long a computed baseline is considered fresh before recompute is triggered.
# 24h matches the scoring epoch — baseline is recomputed once per epoch per
# agent, then reused for that epoch's score.
DEFAULT_BASELINE_TTL_SECONDS = 24 * 60 * 60


# =============================================================================
# Compute + store
# =============================================================================

async def compute_and_store(
    conn:             asyncpg.Connection,
    agent_wallet:     str,
    *,
    window_days:      int  = DEFAULT_WINDOW_DAYS,
    min_tx_count:     int  = DEFAULT_MIN_TX_COUNT,
    min_active_days:  int  = DEFAULT_MIN_ACTIVE_DAYS,
    valid_for_seconds: int = DEFAULT_BASELINE_TTL_SECONDS,
) -> BaselineResult:
    """
    Recompute the baseline from scratch and persist.

    Raises InsufficientData / InsufficientActiveDays — the agent stays
    without a baseline. Caller decides what to do.
    """
    window_end   = datetime.now(tz=timezone.utc)
    window_start = window_end - timedelta(days=window_days)

    txs = await repo.fetch_window_transactions(
        conn, agent_wallet,
        window_start=window_start,
        window_end=window_end,
    )

    bound_log = log.bind(agent=agent_wallet[:12] + "...", tx_count=len(txs))

    try:
        result = compute_signals(
            txs,
            window_start=window_start,
            window_end=window_end,
            min_tx_count=min_tx_count,
            min_active_days=min_active_days,
        )
    except InsufficientData as e:
        bound_log.info("baseline_skipped_insufficient_tx",
                       observed=e.observed, required=e.required)
        raise
    except InsufficientActiveDays as e:
        bound_log.info("baseline_skipped_insufficient_active_days",
                       observed=e.observed, required=e.required)
        raise

    await repo.upsert_baseline(
        conn, agent_wallet, result,
        valid_for_seconds=valid_for_seconds,
    )

    bound_log.info(
        "baseline_computed",
        success_rate=result.signals.success_rate,
        median_daily_tx=result.signals.median_daily_tx,
        sol_volatility_mad=result.signals.sol_volatility_mad,
        active_days=result.active_days,
        hash=result.baseline_hash[:12] + "...",
    )

    return result


# =============================================================================
# Cached read
# =============================================================================

async def get_or_compute(
    conn:         asyncpg.Connection,
    agent_wallet: str,
    **compute_kwargs,
) -> BaselineResult | None:
    """
    Return the stored baseline if fresh, otherwise recompute.

    Returns None only when:
      - the agent has no baseline AND
      - recompute fails with InsufficientData / InsufficientActiveDays.

    Otherwise raises whatever compute raises (DB errors, etc).
    """
    existing = await repo.get_baseline(conn, agent_wallet)

    if existing is not None:
        # Check freshness via the computed_at vs valid_until window
        # which we stored at upsert time. Re-querying to compare against
        # NOW() is one round-trip we can avoid; just check valid_until.
        # (Simpler: trust upsert_baseline's valid_until calculation.)
        # We'll do an explicit DB-side staleness check here.
        is_fresh = await conn.fetchval(
            "SELECT valid_until > NOW() FROM agent_baselines WHERE agent_wallet = $1",
            agent_wallet,
        )
        if is_fresh:
            return existing

    try:
        return await compute_and_store(conn, agent_wallet, **compute_kwargs)
    except (InsufficientData, InsufficientActiveDays):
        return None


# =============================================================================
# Batch recompute (used by scheduler)
# =============================================================================

async def batch_recompute(
    conn:         asyncpg.Connection,
    agent_wallets: list[str],
    **compute_kwargs,
) -> dict[str, str]:
    """
    Recompute baselines for a list of agents.
    Returns a dict mapping agent_wallet → outcome:
      "computed" | "insufficient_tx" | "insufficient_days" | "error"
    """
    outcomes: dict[str, str] = {}

    for agent in agent_wallets:
        try:
            await compute_and_store(conn, agent, **compute_kwargs)
            outcomes[agent] = "computed"
        except InsufficientData:
            outcomes[agent] = "insufficient_tx"
        except InsufficientActiveDays:
            outcomes[agent] = "insufficient_days"
        except Exception as e:
            outcomes[agent] = "error"
            log.error(
                "baseline_recompute_failed",
                agent=agent[:12] + "...",
                error=str(e),
            )

    return outcomes
