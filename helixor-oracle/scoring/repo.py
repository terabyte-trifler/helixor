"""
scoring/repo.py — typed async DB access for baselines.

Reuses the global asyncpg pool established by indexer/db.py. All SQL lives
here. Caller should hold a connection from the pool and pass it in.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import asyncpg
import structlog

from scoring.signals import (
    BaselineResult,
    Signals,
    TransactionRecord,
    ALGO_VERSION,
)

log = structlog.get_logger(__name__)


# =============================================================================
# Read transactions for a window
# =============================================================================

async def fetch_window_transactions(
    conn:         asyncpg.Connection,
    agent_wallet: str,
    *,
    window_start: datetime,
    window_end:   datetime,
) -> list[TransactionRecord]:
    """
    Fetch all transactions for an agent within [window_start, window_end).

    Both bounds are tz-aware UTC. The DB column is TIMESTAMPTZ so PG handles
    the comparison correctly regardless of session timezone.
    """
    rows = await conn.fetch(
        """
        SELECT block_time, success, sol_change, program_ids, fee
        FROM agent_transactions
        WHERE agent_wallet = $1
          AND block_time >= $2
          AND block_time <  $3
        ORDER BY block_time ASC
        """,
        agent_wallet, window_start, window_end,
    )
    return [
        TransactionRecord(
            block_time=row["block_time"],
            success=row["success"],
            sol_change=row["sol_change"],
            program_ids=tuple(row["program_ids"] or ()),
            fee=row["fee"] or 0,
        )
        for row in rows
    ]


# =============================================================================
# Persist baseline
# =============================================================================

async def upsert_baseline(
    conn:           asyncpg.Connection,
    agent_wallet:   str,
    result:         BaselineResult,
    *,
    valid_for_seconds: int,
) -> None:
    """
    Atomically replace the agent's current baseline + append to history.

    Both writes happen in one transaction so the current row and the
    history row never disagree about the latest baseline.
    """
    valid_until = datetime.now(tz=timezone.utc) + timedelta(seconds=valid_for_seconds)

    async with conn.transaction():
        # Upsert current baseline
        await conn.execute(
            """
            INSERT INTO agent_baselines (
                agent_wallet,
                success_rate, median_daily_tx, sol_volatility_mad,
                tx_count, active_days,
                window_start, window_end, window_days,
                baseline_hash, computed_at, valid_until, algo_version
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), $11, $12)
            ON CONFLICT (agent_wallet) DO UPDATE SET
                success_rate       = EXCLUDED.success_rate,
                median_daily_tx    = EXCLUDED.median_daily_tx,
                sol_volatility_mad = EXCLUDED.sol_volatility_mad,
                tx_count           = EXCLUDED.tx_count,
                active_days        = EXCLUDED.active_days,
                window_start       = EXCLUDED.window_start,
                window_end         = EXCLUDED.window_end,
                window_days        = EXCLUDED.window_days,
                baseline_hash      = EXCLUDED.baseline_hash,
                computed_at        = NOW(),
                valid_until        = EXCLUDED.valid_until,
                algo_version       = EXCLUDED.algo_version
            """,
            agent_wallet,
            result.signals.success_rate,
            result.signals.median_daily_tx,
            result.signals.sol_volatility_mad,
            result.tx_count,
            result.active_days,
            result.window_start, result.window_end, result.window_days,
            result.baseline_hash, valid_until, result.algo_version,
        )

        # Append to history (immutable audit trail)
        await conn.execute(
            """
            INSERT INTO agent_baseline_history (
                agent_wallet,
                success_rate, median_daily_tx, sol_volatility_mad,
                tx_count, active_days,
                baseline_hash, algo_version,
                computed_at, window_start, window_end
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), $9, $10)
            """,
            agent_wallet,
            result.signals.success_rate,
            result.signals.median_daily_tx,
            result.signals.sol_volatility_mad,
            result.tx_count,
            result.active_days,
            result.baseline_hash, result.algo_version,
            result.window_start, result.window_end,
        )


# =============================================================================
# Read latest baseline
# =============================================================================

async def get_baseline(
    conn:         asyncpg.Connection,
    agent_wallet: str,
) -> BaselineResult | None:
    """Return the currently stored baseline, or None if never computed."""
    row = await conn.fetchrow(
        """
        SELECT * FROM agent_baselines WHERE agent_wallet = $1
        """,
        agent_wallet,
    )
    if row is None:
        return None

    return BaselineResult(
        signals=Signals(
            success_rate       = float(row["success_rate"]),
            median_daily_tx    = row["median_daily_tx"],
            sol_volatility_mad = row["sol_volatility_mad"],
        ),
        tx_count       = row["tx_count"],
        active_days    = row["active_days"],
        window_start   = row["window_start"],
        window_end     = row["window_end"],
        window_days    = row["window_days"],
        baseline_hash  = row["baseline_hash"],
        algo_version   = row["algo_version"],
    )


# =============================================================================
# Find baselines that need recomputation
# =============================================================================

async def find_stale_baselines(conn: asyncpg.Connection) -> list[str]:
    """
    Returns agent_wallets whose baseline has expired (valid_until < NOW()).
    Used by the scheduler to drive periodic recomputes.
    """
    rows = await conn.fetch(
        """
        SELECT agent_wallet
        FROM agent_baselines
        WHERE valid_until < NOW()
        ORDER BY valid_until ASC
        """,
    )
    return [r["agent_wallet"] for r in rows]


async def find_agents_without_baseline(conn: asyncpg.Connection) -> list[str]:
    """
    Active agents with no baseline yet.
    Driven by registered_agents - agent_baselines.
    """
    rows = await conn.fetch(
        """
        SELECT ra.agent_wallet
        FROM registered_agents ra
        LEFT JOIN agent_baselines ab ON ab.agent_wallet = ra.agent_wallet
        WHERE ra.active = TRUE
          AND ab.agent_wallet IS NULL
        ORDER BY ra.registered_at ASC
        """,
    )
    return [r["agent_wallet"] for r in rows]


# =============================================================================
# Diagnostics
# =============================================================================

async def baseline_summary(conn: asyncpg.Connection) -> dict[str, Any]:
    """Aggregate stats for the /status endpoint."""
    return dict(await conn.fetchrow(
        """
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE valid_until > NOW())  AS fresh,
            COUNT(*) FILTER (WHERE valid_until <= NOW()) AS stale,
            AVG(tx_count)::int                            AS avg_tx_count,
            AVG(active_days)::int                         AS avg_active_days
        FROM agent_baselines
        """,
    ) or {})
