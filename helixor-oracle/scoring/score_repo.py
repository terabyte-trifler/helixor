"""
scoring/score_repo.py — async DB layer for scores.

Same pattern as scoring/repo.py — separates SQL from logic.
Reuses the global asyncpg pool from indexer/db.py.
"""

from __future__ import annotations

from typing import Any

import asyncpg
import structlog

from scoring.engine import ScoreResult

log = structlog.get_logger(__name__)


# =============================================================================
# Read previous score (for guard rail)
# =============================================================================

async def get_current_score(
    conn:         asyncpg.Connection,
    agent_wallet: str,
) -> int | None:
    """Return the agent's current numeric score, or None if never scored."""
    return await conn.fetchval(
        "SELECT score FROM agent_scores WHERE agent_wallet = $1",
        agent_wallet,
    )


async def get_full_current_score(
    conn:         asyncpg.Connection,
    agent_wallet: str,
) -> dict | None:
    """Full row of the current score, for inspection / API responses."""
    row = await conn.fetchrow(
        "SELECT * FROM agent_scores WHERE agent_wallet = $1",
        agent_wallet,
    )
    return dict(row) if row else None


# =============================================================================
# Persist score (atomic upsert + history append)
# =============================================================================

async def upsert_score(
    conn:         asyncpg.Connection,
    agent_wallet: str,
    result:       ScoreResult,
) -> None:
    """
    Atomically replace current score + append to history.

    Both writes happen in one transaction so the current row + history row
    are always consistent.
    """
    async with conn.transaction():
        await conn.execute(
            """
            INSERT INTO agent_scores (
                agent_wallet,
                score, alert,
                success_rate_score, consistency_score, stability_score,
                raw_score, guard_rail_applied,
                window_success_rate, window_tx_count, window_sol_volatility,
                baseline_hash, baseline_algo_version,
                anomaly_flag,
                scoring_algo_version, weights_version,
                computed_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                $12, $13, $14, $15, $16, NOW()
            )
            ON CONFLICT (agent_wallet) DO UPDATE SET
                score                  = EXCLUDED.score,
                alert                  = EXCLUDED.alert,
                success_rate_score     = EXCLUDED.success_rate_score,
                consistency_score      = EXCLUDED.consistency_score,
                stability_score        = EXCLUDED.stability_score,
                raw_score              = EXCLUDED.raw_score,
                guard_rail_applied     = EXCLUDED.guard_rail_applied,
                window_success_rate    = EXCLUDED.window_success_rate,
                window_tx_count        = EXCLUDED.window_tx_count,
                window_sol_volatility  = EXCLUDED.window_sol_volatility,
                baseline_hash          = EXCLUDED.baseline_hash,
                baseline_algo_version  = EXCLUDED.baseline_algo_version,
                anomaly_flag           = EXCLUDED.anomaly_flag,
                scoring_algo_version   = EXCLUDED.scoring_algo_version,
                weights_version        = EXCLUDED.weights_version,
                computed_at            = NOW(),
                written_onchain_at     = NULL
            """,
            agent_wallet,
            result.score, result.alert,
            result.breakdown.success_rate_score,
            result.breakdown.consistency_score,
            result.breakdown.stability_score,
            result.breakdown.raw_score,
            result.breakdown.guard_rail_applied,
            result.window_success_rate, result.window_tx_count,
            result.window_sol_volatility,
            result.baseline_hash, result.baseline_algo_version,
            result.anomaly_flag,
            result.scoring_algo_version, result.weights_version,
        )

        await conn.execute(
            """
            INSERT INTO agent_score_history (
                agent_wallet,
                score, alert,
                success_rate_score, consistency_score, stability_score,
                raw_score, guard_rail_applied,
                window_success_rate, window_tx_count, window_sol_volatility,
                baseline_hash, baseline_algo_version,
                anomaly_flag,
                scoring_algo_version, weights_version
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                $12, $13, $14, $15, $16
            )
            """,
            agent_wallet,
            result.score, result.alert,
            result.breakdown.success_rate_score,
            result.breakdown.consistency_score,
            result.breakdown.stability_score,
            result.breakdown.raw_score,
            result.breakdown.guard_rail_applied,
            result.window_success_rate, result.window_tx_count,
            result.window_sol_volatility,
            result.baseline_hash, result.baseline_algo_version,
            result.anomaly_flag,
            result.scoring_algo_version, result.weights_version,
        )


# =============================================================================
# Day 7 hooks — find scores not yet on-chain, mark them
# =============================================================================

async def find_unsynced_scores(conn: asyncpg.Connection) -> list[str]:
    """Agents whose current score has not yet been written on-chain."""
    rows = await conn.fetch(
        """
        SELECT agent_wallet FROM agent_scores
        WHERE written_onchain_at IS NULL
        ORDER BY computed_at ASC
        """,
    )
    return [r["agent_wallet"] for r in rows]


async def mark_score_onchain(
    conn:           asyncpg.Connection,
    agent_wallet:   str,
    tx_signature:   str,
) -> None:
    """Mark current score as synced on-chain. Called from Day 7."""
    async with conn.transaction():
        await conn.execute(
            "UPDATE agent_scores SET written_onchain_at = NOW() WHERE agent_wallet = $1",
            agent_wallet,
        )
        # Also annotate the latest history row with the on-chain sig
        await conn.execute(
            """
            UPDATE agent_score_history
            SET onchain_tx_signature = $2
            WHERE id = (
                SELECT id FROM agent_score_history
                WHERE agent_wallet = $1
                ORDER BY computed_at DESC
                LIMIT 1
            )
            """,
            agent_wallet, tx_signature,
        )


# =============================================================================
# Diagnostics
# =============================================================================

async def score_summary(conn: asyncpg.Connection) -> dict[str, Any]:
    """Aggregate stats across all current scores."""
    return dict(await conn.fetchrow(
        """
        SELECT
            COUNT(*)                                    AS total,
            COUNT(*) FILTER (WHERE alert = 'GREEN')     AS green,
            COUNT(*) FILTER (WHERE alert = 'YELLOW')    AS yellow,
            COUNT(*) FILTER (WHERE alert = 'RED')       AS red,
            COUNT(*) FILTER (WHERE anomaly_flag)        AS anomalies,
            AVG(score)::int                              AS avg_score,
            COUNT(*) FILTER (WHERE written_onchain_at IS NULL) AS unsynced
        FROM agent_scores
        """,
    ) or {})


async def find_agents_due_for_scoring(conn: asyncpg.Connection) -> list[str]:
    """
    Active agents that have a baseline AND need their score (re)computed.

    Returns the union of:
      - Agents with a baseline but no score
      - Agents whose last score is older than 23h (next epoch is due)
    """
    rows = await conn.fetch(
        """
        SELECT ra.agent_wallet
        FROM registered_agents ra
        JOIN agent_baselines    ab ON ab.agent_wallet = ra.agent_wallet
        LEFT JOIN agent_scores  sc ON sc.agent_wallet = ra.agent_wallet
        WHERE ra.active = TRUE
          AND (sc.agent_wallet IS NULL
               OR sc.computed_at < NOW() - INTERVAL '23 hours')
        ORDER BY COALESCE(sc.computed_at, ab.computed_at) ASC
        """,
    )
    return [r["agent_wallet"] for r in rows]
