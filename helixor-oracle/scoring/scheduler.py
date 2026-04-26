"""
scoring/scheduler.py — periodic baseline recompute service.

Runs as its own docker-compose service. Wakes on an interval, finds:
  - Agents with no baseline yet (newly registered, enough tx now)
  - Agents whose baseline has expired

…then recomputes each. Idempotent — safe to restart anytime.

Run as: python -m scoring.scheduler
"""

from __future__ import annotations

import asyncio
import structlog

from indexer import db
from indexer.config import settings
from scoring import baseline_engine, repo

log = structlog.get_logger(__name__)


# How often we wake to look for stale baselines.
# Per-baseline freshness is controlled by valid_until (default 24h).
# Wakeup interval just needs to be << TTL.
SCHEDULE_INTERVAL_SECONDS = 600  # 10 minutes


async def run_one_pass() -> dict[str, int]:
    """One scheduling pass — recompute stale + uninitialised baselines."""
    pool = await db.get_pool()

    async with pool.acquire() as conn:
        without = await repo.find_agents_without_baseline(conn)
        stale   = await repo.find_stale_baselines(conn)

    targets = list({*without, *stale})

    if not targets:
        log.debug("no_baselines_need_recompute")
        return {"computed": 0, "insufficient_tx": 0, "insufficient_days": 0, "error": 0}

    log.info(
        "scheduler_pass_starting",
        without=len(without),
        stale=len(stale),
        total=len(targets),
    )

    # Compute one agent per acquire → release to avoid hogging the pool
    summary = {"computed": 0, "insufficient_tx": 0, "insufficient_days": 0, "error": 0}
    for agent in targets:
        async with pool.acquire() as conn:
            outcomes = await baseline_engine.batch_recompute(conn, [agent])
            outcome = outcomes.get(agent, "error")
            summary[outcome] = summary.get(outcome, 0) + 1

    log.info("scheduler_pass_complete", **summary)
    return summary


async def loop() -> None:
    await db.init_pool()
    log.info("baseline_scheduler_starting", interval_s=SCHEDULE_INTERVAL_SECONDS)

    try:
        while True:
            try:
                await run_one_pass()
            except Exception as e:
                log.error("scheduler_iteration_failed", error=str(e))
            await asyncio.sleep(SCHEDULE_INTERVAL_SECONDS)
    finally:
        await db.close_pool()


def main() -> None:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
    )
    asyncio.run(loop())


if __name__ == "__main__":
    main()
