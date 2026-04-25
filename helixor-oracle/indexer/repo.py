"""
indexer/repo.py — typed database access.

All SQL lives here. Keeps the FastAPI handlers and tests free of SQL strings.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import asyncpg
import structlog

from indexer.parser import ParsedTransaction

log = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Agent registration cache
# ─────────────────────────────────────────────────────────────────────────────

async def is_agent_active(conn: asyncpg.Connection, agent_wallet: str) -> bool:
    """Fast lookup: does this agent exist and is it active?"""
    return await conn.fetchval(
        "SELECT active FROM registered_agents WHERE agent_wallet = $1",
        agent_wallet,
    ) is True


async def get_active_agent_wallets(conn: asyncpg.Connection) -> list[str]:
    """All currently active agent wallets — used by reconciler."""
    rows = await conn.fetch(
        "SELECT agent_wallet FROM registered_agents WHERE active = TRUE"
    )
    return [r["agent_wallet"] for r in rows]


async def upsert_registered_agent(
    conn: asyncpg.Connection,
    *,
    agent_wallet:        str,
    owner_wallet:        str,
    name:                str | None,
    registration_pda:    str,
    registered_at:       datetime,
    onchain_signature:   str,
) -> None:
    """
    Idempotent: called by agent_sync when AgentRegistered event fires.
    Safe to call multiple times for the same registration tx.
    """
    await conn.execute(
        """
        INSERT INTO registered_agents
            (agent_wallet, owner_wallet, name, registration_pda,
             registered_at, onchain_signature, active)
        VALUES ($1, $2, $3, $4, $5, $6, TRUE)
        ON CONFLICT (onchain_signature) DO NOTHING
        """,
        agent_wallet, owner_wallet, name, registration_pda,
        registered_at, onchain_signature,
    )


async def attach_webhook_id(
    conn: asyncpg.Connection,
    agent_wallet: str,
    helius_webhook_id: str,
) -> None:
    """After successful Helius webhook registration, record the ID."""
    await conn.execute(
        """
        UPDATE registered_agents
        SET helius_webhook_id     = $2,
            webhook_registered_at = NOW(),
            webhook_failures      = 0
        WHERE agent_wallet = $1
        """,
        agent_wallet, helius_webhook_id,
    )


async def record_webhook_failure(
    conn: asyncpg.Connection,
    agent_wallet: str,
    error_message: str,
) -> None:
    """Increment failure counter when Helius registration fails."""
    await conn.execute(
        """
        UPDATE registered_agents
        SET webhook_failures = webhook_failures + 1
        WHERE agent_wallet = $1
        """,
        agent_wallet,
    )
    await conn.execute(
        """
        INSERT INTO webhook_subscriptions
            (agent_wallet, state, error_message)
        VALUES ($1, 'failed', $2)
        """,
        agent_wallet, error_message,
    )


async def agents_pending_webhook(conn: asyncpg.Connection) -> list[dict[str, Any]]:
    """View — used by the webhook registrar background task."""
    rows = await conn.fetch("SELECT * FROM agents_pending_webhook")
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# Transactions
# ─────────────────────────────────────────────────────────────────────────────

async def insert_transactions_batch(
    conn: asyncpg.Connection,
    txs: list[ParsedTransaction],
    *,
    source: str = "webhook",
) -> tuple[int, int]:
    """
    Bulk-insert transactions. Returns (inserted, skipped).

    Skipped = duplicates (ON CONFLICT) or unknown agents (foreign key reject).
    Uses executemany for batch-insert performance — single round-trip per
    100 rows on a typical PG.

    `source` distinguishes:
      - 'webhook'  : real-time stream
      - 'backfill' : RPC catchup after downtime
      - 'replay'   : manual re-import
    """
    if not txs:
        return (0, 0)

    # Pre-fetch the active set of agents so we don't FK-violate
    agent_wallets = list({tx.fee_payer for tx in txs})
    active_rows = await conn.fetch(
        "SELECT agent_wallet FROM registered_agents WHERE agent_wallet = ANY($1::text[]) AND active = TRUE",
        agent_wallets,
    )
    active_set = {r["agent_wallet"] for r in active_rows}

    # Filter to active agents only — silently skip transactions for unknown
    # or deactivated agents (these are common: an agent was deregistered
    # mid-stream and Helius hasn't been told yet).
    eligible = [tx for tx in txs if tx.fee_payer in active_set]
    skipped_inactive = len(txs) - len(eligible)

    if not eligible:
        return (0, skipped_inactive)

    # Build value tuples for executemany
    rows = [
        (
            tx.fee_payer,
            tx.signature,
            tx.slot,
            tx.block_time,
            tx.success,
            tx.program_ids,
            tx.sol_change,
            tx.fee,
            json.dumps(tx.raw_meta),
            source,
        )
        for tx in eligible
    ]

    # Use COPY for max throughput? executemany is fine for batches < 1000.
    # We track inserted count via RETURNING; ON CONFLICT skipped rows
    # don't appear in RETURNING.
    inserted = 0
    async with conn.transaction():
        for row in rows:
            result = await conn.execute(
                """
                INSERT INTO agent_transactions
                    (agent_wallet, tx_signature, slot, block_time, success,
                     program_ids, sol_change, fee, raw_meta, source)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)
                ON CONFLICT (tx_signature) DO NOTHING
                """,
                *row,
            )
            # asyncpg returns 'INSERT 0 1' or 'INSERT 0 0' — split off the count
            if result.endswith(" 1"):
                inserted += 1

    skipped_duplicates = len(eligible) - inserted
    return (inserted, skipped_inactive + skipped_duplicates)


# ─────────────────────────────────────────────────────────────────────────────
# Webhook event audit log
# ─────────────────────────────────────────────────────────────────────────────

async def record_webhook_event(
    conn: asyncpg.Connection,
    *,
    request_id:     str,
    tx_count:       int,
    inserted_count: int,
    skipped_count:  int,
    duration_ms:    int,
    error:          str | None = None,
) -> None:
    """One row per webhook POST received — for SLO tracking + debugging."""
    await conn.execute(
        """
        INSERT INTO webhook_events
            (request_id, tx_count, inserted_count, skipped_count, duration_ms, error)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        request_id, tx_count, inserted_count, skipped_count, duration_ms, error,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Diagnostics
# ─────────────────────────────────────────────────────────────────────────────

async def webhook_health_summary(
    conn: asyncpg.Connection,
    window_minutes: int = 5,
) -> dict[str, Any]:
    """Recent webhook stats — used by /health endpoint."""
    return dict(await conn.fetchrow(
        f"""
        SELECT
            COUNT(*)                                AS total_events,
            COALESCE(SUM(tx_count), 0)              AS total_txs,
            COALESCE(SUM(inserted_count), 0)        AS total_inserted,
            COALESCE(SUM(skipped_count), 0)         AS total_skipped,
            COUNT(*) FILTER (WHERE error IS NOT NULL) AS errors,
            COALESCE(AVG(duration_ms), 0)::int      AS avg_duration_ms
        FROM webhook_events
        WHERE received_at >= NOW() - INTERVAL '{int(window_minutes)} minutes'
        """
    ) or {})
