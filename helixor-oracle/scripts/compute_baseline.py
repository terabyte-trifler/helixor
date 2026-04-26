#!/usr/bin/env python3
"""
scripts/compute_baseline.py — manual baseline computation for one agent.

This is the Day 5 "done when" check:

    python -m scripts.compute_baseline <agent_wallet>

Prints the computed baseline as JSON. If insufficient data, prints a
clear error message explaining what's needed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

import structlog

from indexer import db
from scoring import baseline_engine
from scoring.signals import (
    InsufficientActiveDays,
    InsufficientData,
    baseline_to_dict,
)

log = structlog.get_logger()


async def run(agent_wallet: str, *, store: bool, window_days: int) -> int:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
    )

    await db.init_pool()
    pool = await db.get_pool()

    try:
        async with pool.acquire() as conn:
            try:
                if store:
                    result = await baseline_engine.compute_and_store(
                        conn, agent_wallet, window_days=window_days,
                    )
                else:
                    # Compute without persisting — useful for one-off inspection
                    from datetime import datetime, timedelta, timezone
                    from scoring import repo
                    from scoring.signals import compute_signals

                    window_end   = datetime.now(tz=timezone.utc)
                    window_start = window_end - timedelta(days=window_days)

                    txs = await repo.fetch_window_transactions(
                        conn, agent_wallet,
                        window_start=window_start,
                        window_end=window_end,
                    )
                    result = compute_signals(
                        txs,
                        window_start=window_start,
                        window_end=window_end,
                    )
            except InsufficientData as e:
                print(json.dumps({
                    "ok":          False,
                    "reason":      "insufficient_tx_count",
                    "observed":    e.observed,
                    "required":    e.required,
                    "agent":       agent_wallet,
                    "window_days": window_days,
                    "hint":        f"Agent has {e.observed} txs in last {window_days}d; "
                                   f"need {e.required}. Wait for more, or lower min_tx_count.",
                }, indent=2))
                return 1
            except InsufficientActiveDays as e:
                print(json.dumps({
                    "ok":          False,
                    "reason":      "insufficient_active_days",
                    "observed":    e.observed,
                    "required":    e.required,
                    "agent":       agent_wallet,
                    "hint":        "Agent has txs but on too few distinct days.",
                }, indent=2))
                return 1

            print(json.dumps({
                "ok":      True,
                "stored":  store,
                "agent":   agent_wallet,
                "result":  baseline_to_dict(result),
            }, indent=2, default=str))
            return 0

    finally:
        await db.close_pool()


def main() -> None:
    p = argparse.ArgumentParser(
        description="Compute a baseline for one agent (Day 5 verification CLI)",
    )
    p.add_argument("agent_wallet", help="Agent wallet pubkey")
    p.add_argument("--store",   action="store_true",
                   help="Persist to agent_baselines (default: dry run)")
    p.add_argument("--window-days", type=int, default=30,
                   help="Rolling window in days (default: 30)")
    args = p.parse_args()

    exit_code = asyncio.run(run(
        args.agent_wallet,
        store=args.store,
        window_days=args.window_days,
    ))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
