"""
baseline/repository.py — persistence for BaselineStats.

WRITE MODEL (the append-only contract)
--------------------------------------
Every baseline computation does TWO writes inside one transaction:

  1. INSERT into `agent_baseline_history` — append-only. This table is NEVER
     updated or deleted. It is the full audit trail of every baseline ever
     computed for every agent.

  2. UPSERT into `agent_baselines` — the "latest baseline per agent" view.
     ON CONFLICT (agent_wallet) DO UPDATE. This is what the scoring engine
     reads.

If either write fails, the transaction rolls back — history and latest never
diverge.

READ MODEL
----------
`load_latest(agent_wallet)` returns the current baseline. It reconstructs a
full BaselineStats and the caller is expected to check
`.is_compatible_with_current_engine()` before using it.

This module is the ONLY place that knows the DB column layout. Everything
else works with BaselineStats objects.
"""

from __future__ import annotations

from datetime import datetime, timezone

import asyncpg

from baseline.types import BaselineStats
from features import TOTAL_FEATURES


# =============================================================================
# Serialization helpers
# =============================================================================

def _to_float_list(seq) -> list[float]:
    """asyncpg wants a plain list for float[] columns."""
    return [float(x) for x in seq]


# =============================================================================
# Write path — append-only history + latest upsert, atomic
# =============================================================================

async def save_baseline(conn: asyncpg.Connection, baseline: BaselineStats) -> None:
    """
    Persist a freshly-computed baseline.

    Performs the history INSERT + latest UPSERT inside a single transaction.
    Idempotent at the (agent_wallet, stats_hash, window_end) level: re-saving
    an identical baseline does not create a duplicate history row.
    """
    async with conn.transaction():
        # 1. Append-only history. ON CONFLICT DO NOTHING makes a re-run of the
        #    same computation idempotent rather than appending a duplicate.
        await conn.execute(
            """
            INSERT INTO agent_baseline_history (
                agent_wallet,
                baseline_algo_version, feature_schema_version,
                feature_schema_fingerprint, scoring_schema_fingerprint,
                window_start, window_end,
                feature_means, feature_stds,
                txtype_distribution, action_entropy, success_rate_30d,
                transaction_count, days_with_activity, is_provisional,
                computed_at, stats_hash
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
            )
            ON CONFLICT (agent_wallet, stats_hash, window_end) DO NOTHING
            """,
            baseline.agent_wallet,
            baseline.baseline_algo_version,
            baseline.feature_schema_version,
            baseline.feature_schema_fingerprint,
            baseline.scoring_schema_fingerprint,
            baseline.window_start,
            baseline.window_end,
            _to_float_list(baseline.feature_means),
            _to_float_list(baseline.feature_stds),
            _to_float_list(baseline.txtype_distribution),
            baseline.action_entropy,
            baseline.success_rate_30d,
            baseline.transaction_count,
            baseline.days_with_activity,
            baseline.is_provisional,
            baseline.computed_at,
            baseline.stats_hash,
        )

        # 2. Latest-per-agent upsert. This is what the scoring engine reads.
        await conn.execute(
            """
            INSERT INTO agent_baselines (
                agent_wallet,
                baseline_algo_version, feature_schema_version,
                feature_schema_fingerprint, scoring_schema_fingerprint,
                window_start, window_end,
                feature_means, feature_stds,
                txtype_distribution, action_entropy, success_rate_30d,
                transaction_count, days_with_activity, is_provisional,
                computed_at, stats_hash
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
            )
            ON CONFLICT (agent_wallet) DO UPDATE SET
                baseline_algo_version      = EXCLUDED.baseline_algo_version,
                feature_schema_version     = EXCLUDED.feature_schema_version,
                feature_schema_fingerprint = EXCLUDED.feature_schema_fingerprint,
                scoring_schema_fingerprint = EXCLUDED.scoring_schema_fingerprint,
                window_start               = EXCLUDED.window_start,
                window_end                 = EXCLUDED.window_end,
                feature_means              = EXCLUDED.feature_means,
                feature_stds               = EXCLUDED.feature_stds,
                txtype_distribution        = EXCLUDED.txtype_distribution,
                action_entropy             = EXCLUDED.action_entropy,
                success_rate_30d           = EXCLUDED.success_rate_30d,
                transaction_count          = EXCLUDED.transaction_count,
                days_with_activity         = EXCLUDED.days_with_activity,
                is_provisional             = EXCLUDED.is_provisional,
                computed_at                = EXCLUDED.computed_at,
                stats_hash                 = EXCLUDED.stats_hash
            """,
            baseline.agent_wallet,
            baseline.baseline_algo_version,
            baseline.feature_schema_version,
            baseline.feature_schema_fingerprint,
            baseline.scoring_schema_fingerprint,
            baseline.window_start,
            baseline.window_end,
            _to_float_list(baseline.feature_means),
            _to_float_list(baseline.feature_stds),
            _to_float_list(baseline.txtype_distribution),
            baseline.action_entropy,
            baseline.success_rate_30d,
            baseline.transaction_count,
            baseline.days_with_activity,
            baseline.is_provisional,
            baseline.computed_at,
            baseline.stats_hash,
        )


# =============================================================================
# Read path
# =============================================================================

def _row_to_baseline(row: asyncpg.Record) -> BaselineStats:
    """Reconstruct a BaselineStats from a DB row. Shared by all read functions."""
    return BaselineStats(
        agent_wallet               = row["agent_wallet"],
        baseline_algo_version      = row["baseline_algo_version"],
        feature_schema_version     = row["feature_schema_version"],
        feature_schema_fingerprint = row["feature_schema_fingerprint"],
        scoring_schema_fingerprint = row["scoring_schema_fingerprint"],
        window_start               = _as_utc(row["window_start"]),
        window_end                 = _as_utc(row["window_end"]),
        feature_means              = tuple(float(x) for x in row["feature_means"]),
        feature_stds               = tuple(float(x) for x in row["feature_stds"]),
        txtype_distribution        = tuple(float(x) for x in row["txtype_distribution"]),
        action_entropy             = float(row["action_entropy"]),
        success_rate_30d           = float(row["success_rate_30d"]),
        transaction_count          = row["transaction_count"],
        days_with_activity         = row["days_with_activity"],
        is_provisional             = row["is_provisional"],
        computed_at                = _as_utc(row["computed_at"]),
        stats_hash                 = row["stats_hash"],
    )


def _as_utc(dt: datetime) -> datetime:
    """asyncpg returns tz-aware datetimes; normalise defensively to UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


async def load_latest(
    conn: asyncpg.Connection,
    agent_wallet: str,
) -> BaselineStats | None:
    """Return the current baseline for an agent, or None if it has none."""
    row = await conn.fetchrow(
        "SELECT * FROM agent_baselines WHERE agent_wallet = $1",
        agent_wallet,
    )
    return _row_to_baseline(row) if row else None


async def load_history(
    conn: asyncpg.Connection,
    agent_wallet: str,
    *,
    limit: int = 50,
) -> list[BaselineStats]:
    """Return an agent's baseline history, newest first."""
    rows = await conn.fetch(
        """
        SELECT * FROM agent_baseline_history
        WHERE agent_wallet = $1
        ORDER BY computed_at DESC
        LIMIT $2
        """,
        agent_wallet, limit,
    )
    return [_row_to_baseline(r) for r in rows]


async def list_agents_needing_v2_baseline(
    conn: asyncpg.Connection,
    *,
    current_algo_version: int,
    current_schema_fingerprint: str,
) -> list[str]:
    """
    Return agent wallets that do NOT have an up-to-date v2 baseline:
      - agents with no baseline row at all, OR
      - agents whose latest baseline is on an old algo version, OR
      - agents whose latest baseline has a stale feature schema fingerprint.

    This is the worklist for the backfill job.
    """
    rows = await conn.fetch(
        """
        SELECT ra.agent_wallet
        FROM registered_agents ra
        LEFT JOIN agent_baselines ab ON ab.agent_wallet = ra.agent_wallet
        WHERE ra.active = TRUE
          AND (
              ab.agent_wallet IS NULL
              OR ab.baseline_algo_version <> $1
              OR ab.feature_schema_fingerprint <> $2
          )
        ORDER BY ra.agent_wallet
        """,
        current_algo_version, current_schema_fingerprint,
    )
    return [r["agent_wallet"] for r in rows]


async def count_v2_baselines(
    conn: asyncpg.Connection,
    *,
    current_algo_version: int,
    current_schema_fingerprint: str,
) -> tuple[int, int]:
    """
    Return (agents_with_current_v2_baseline, total_active_agents).
    Used by the backfill job + monitoring to confirm "all agents have a v2 baseline".
    """
    total = await conn.fetchval(
        "SELECT COUNT(*) FROM registered_agents WHERE active = TRUE"
    )
    current = await conn.fetchval(
        """
        SELECT COUNT(*)
        FROM registered_agents ra
        JOIN agent_baselines ab ON ab.agent_wallet = ra.agent_wallet
        WHERE ra.active = TRUE
          AND ab.baseline_algo_version = $1
          AND ab.feature_schema_fingerprint = $2
        """,
        current_algo_version, current_schema_fingerprint,
    )
    return int(current or 0), int(total or 0)
