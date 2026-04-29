#!/usr/bin/env python3
"""
scripts/operator/add_monitored_agent.py — designate a real agent for Day 11 tracking.

Day 11 success criterion: ONE specific real agent is registered, observed,
and scored continuously for ≥24h. This script marks that agent in the
monitored_agents table so per-agent checks fire on it specifically.

Usage:
    python -m scripts.operator.add_monitored_agent \
        --wallet AGENT_PUBKEY \
        --label "First production agent" \
        --min-score 600
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import structlog

from indexer import db

log = structlog.get_logger()


async def run(
    wallet:    str,
    label:     str,
    min_score: int | None,
    notes:     str,
) -> int:
    structlog.configure(processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ])

    await db.init_pool()
    pool = await db.get_pool()

    try:
        async with pool.acquire() as conn:
            # Verify the agent is registered first
            registered = await conn.fetchval(
                "SELECT 1 FROM registered_agents WHERE agent_wallet = $1",
                wallet,
            )
            if not registered:
                print(f"\n  ✗ Agent {wallet} is not registered with Helixor.")
                print(f"    Register first via Day 2's register_agent ix.")
                return 1

            await conn.execute(
                """
                INSERT INTO monitored_agents
                  (agent_wallet, label, expected_min_score, notes, enabled)
                VALUES ($1, $2, $3, $4, TRUE)
                ON CONFLICT (agent_wallet) DO UPDATE SET
                  label              = EXCLUDED.label,
                  expected_min_score = EXCLUDED.expected_min_score,
                  notes              = EXCLUDED.notes,
                  enabled            = TRUE
                """,
                wallet, label, min_score, notes,
            )

        print(f"\n  ✓ Monitoring enabled for '{label}' ({wallet[:12]}...)")
        if min_score is not None:
            print(f"    Will alert if score drops below {min_score}.")
        print(f"\n    Run `python -m monitoring.runner --once` to test immediately.")
        return 0

    finally:
        await db.close_pool()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--wallet",    required=True, help="Agent wallet pubkey")
    p.add_argument("--label",     required=True, help="Human-readable name")
    p.add_argument("--min-score", type=int, default=None,
                   help="Alert if score drops below this (optional)")
    p.add_argument("--notes",     default="", help="Free-form operator notes")
    args = p.parse_args()

    sys.exit(asyncio.run(run(args.wallet, args.label, args.min_score, args.notes)))


if __name__ == "__main__":
    main()
