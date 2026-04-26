#!/usr/bin/env python3
"""
scripts/compute_score.py — manual scoring for one agent.

Day 6 "done when" check:

    python -m scripts.compute_score <agent_wallet>

Prints the computed score + breakdown as JSON.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

import structlog

from indexer import db
from scoring import score_engine
from scoring.engine import score_to_dict

log = structlog.get_logger()


async def run(agent_wallet: str, *, dry_run: bool) -> int:
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
            if dry_run:
                # Compute without persisting — peek at what the score would be
                from datetime import datetime, timedelta, timezone
                from scoring import repo as baseline_repo
                from scoring.engine import score_agent
                from scoring.window import (
                    DEFAULT_WINDOW_DAYS,
                    InsufficientWindowData,
                    compute_window,
                )
                from scoring.score_repo import get_current_score

                baseline = await baseline_repo.get_baseline(conn, agent_wallet)
                if baseline is None:
                    print(json.dumps({
                        "ok": False,
                        "reason": "no_baseline",
                        "agent": agent_wallet,
                        "hint": "Run: python -m scripts.compute_baseline "
                                f"{agent_wallet} --store",
                    }, indent=2))
                    return 1

                window_end   = datetime.now(tz=timezone.utc)
                window_start = window_end - timedelta(days=DEFAULT_WINDOW_DAYS)
                txs = await baseline_repo.fetch_window_transactions(
                    conn, agent_wallet,
                    window_start=window_start, window_end=window_end,
                )

                try:
                    window = compute_window(
                        txs, window_start=window_start, window_end=window_end,
                    )
                except InsufficientWindowData as e:
                    print(json.dumps({
                        "ok": False,
                        "reason": "insufficient_window_tx",
                        "observed": e.observed,
                        "required": e.required,
                        "agent": agent_wallet,
                    }, indent=2))
                    return 1

                previous = await get_current_score(conn, agent_wallet)
                result = score_agent(window, baseline, previous_score=previous)

            else:
                result = await score_engine.score_one(conn, agent_wallet)
                if result is None:
                    print(json.dumps({
                        "ok": False,
                        "reason": "no_baseline_or_insufficient_window",
                        "agent": agent_wallet,
                    }, indent=2))
                    return 1

            print(json.dumps({
                "ok":     True,
                "stored": not dry_run,
                "agent":  agent_wallet,
                "result": score_to_dict(result),
            }, indent=2, default=str))
            return 0

    finally:
        await db.close_pool()


def main() -> None:
    p = argparse.ArgumentParser(description="Compute trust score for one agent")
    p.add_argument("agent_wallet", help="Agent wallet pubkey")
    p.add_argument("--dry-run", action="store_true",
                   help="Compute without persisting (default: persists)")
    args = p.parse_args()

    sys.exit(asyncio.run(run(args.agent_wallet, dry_run=args.dry_run)))


if __name__ == "__main__":
    main()
