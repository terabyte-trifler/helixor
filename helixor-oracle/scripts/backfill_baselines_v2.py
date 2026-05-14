#!/usr/bin/env python3
"""
scripts/backfill_baselines_v2.py — compute v2 baselines for every agent.

The Day-2 "done when": every active devnet agent has a v2 baseline with a
committed stats_hash.

DESIGN — this job is built to be run repeatedly without fear:

  IDEMPOTENT  Re-running does not double-write. The worklist query only
              returns agents WITHOUT an up-to-date v2 baseline, and the
              history table de-dups on (agent_wallet, stats_hash, window_end).

  RESUMABLE   If it crashes at agent 340 of 500, just run it again — the
              340 already-done agents fall out of the worklist automatically.

  DRY-RUN     --dry-run computes everything and reports, writes nothing.

  OBSERVABLE  Per-agent status line; a summary with counts; non-zero exit
              code if any agent failed, so CI / cron can detect a bad run.

  BOUNDED     --limit N processes at most N agents (for incremental rollout).

Usage:
    python -m scripts.backfill_baselines_v2 --dry-run
    python -m scripts.backfill_baselines_v2
    python -m scripts.backfill_baselines_v2 --limit 50
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import asyncpg
import structlog

from baseline import (
    BASELINE_ALGO_VERSION,
    InsufficientDataError,
    compute_baseline,
)
from baseline import repository as repo
from features import ExtractionWindow, FeatureVector, Transaction

log = structlog.get_logger()


# The baseline window: 30 days ending "now". For the backfill, "now" is the
# job start time, captured once so every agent gets the SAME window end —
# making the run reproducible.
BASELINE_WINDOW_DAYS = 30


@dataclass
class AgentResult:
    agent_wallet: str
    status:       str          # "written" | "dry-run-ok" | "insufficient-data" | "error"
    detail:       str
    is_provisional: bool = False
    stats_hash:   str | None = None


# =============================================================================
# Per-agent transaction loading
# =============================================================================

async def _load_transactions(
    conn:   asyncpg.Connection,
    wallet: str,
    window: ExtractionWindow,
) -> list[Transaction]:
    """Load an agent's transactions in the window from agent_transactions."""
    rows = await conn.fetch(
        """
        SELECT tx_signature, slot, block_time, success,
               program_ids, sol_change, fee,
               COALESCE(priority_fee, 0)  AS priority_fee,
               COALESCE(compute_units, 0) AS compute_units,
               counterparty
        FROM agent_transactions
        WHERE agent_wallet = $1
          AND block_time >= $2
          AND block_time <= $3
        ORDER BY block_time, slot, tx_signature
        """,
        wallet, window.start, window.end,
    )
    txs: list[Transaction] = []
    for r in rows:
        block_time = r["block_time"]
        if block_time.tzinfo is None:
            block_time = block_time.replace(tzinfo=timezone.utc)
        txs.append(Transaction(
            signature=r["tx_signature"],
            slot=r["slot"],
            block_time=block_time,
            success=r["success"],
            program_ids=tuple(r["program_ids"] or ()),
            sol_change=r["sol_change"],
            fee=r["fee"],
            priority_fee=r["priority_fee"],
            compute_units=r["compute_units"],
            counterparty=r["counterparty"],
        ))
    return txs


# =============================================================================
# Per-agent processing
# =============================================================================

async def _process_agent(
    conn:      asyncpg.Connection,
    wallet:    str,
    window:    ExtractionWindow,
    job_start: datetime,
    dry_run:   bool,
) -> AgentResult:
    """Compute (and optionally persist) one agent's v2 baseline."""
    try:
        txs = await _load_transactions(conn, wallet, window)

        baseline = compute_baseline(
            agent_wallet=wallet,
            transactions=txs,
            window=window,
            computed_at=job_start,
        )

        if dry_run:
            return AgentResult(
                agent_wallet=wallet,
                status="dry-run-ok",
                detail=(
                    f"{baseline.transaction_count} txs, "
                    f"{baseline.days_with_activity} active days, "
                    f"{'provisional' if baseline.is_provisional else 'full'}"
                ),
                is_provisional=baseline.is_provisional,
                stats_hash=baseline.stats_hash,
            )

        await repo.save_baseline(conn, baseline)
        return AgentResult(
            agent_wallet=wallet,
            status="written",
            detail=(
                f"{baseline.transaction_count} txs, "
                f"{baseline.days_with_activity} active days"
            ),
            is_provisional=baseline.is_provisional,
            stats_hash=baseline.stats_hash,
        )

    except InsufficientDataError as e:
        return AgentResult(wallet, "insufficient-data", str(e))
    except Exception as e:  # noqa: BLE001 — backfill must not abort on one bad agent
        log.warning("backfill_agent_failed", agent=wallet, error=str(e))
        return AgentResult(wallet, "error", f"{type(e).__name__}: {e}")


# =============================================================================
# Main
# =============================================================================

async def run(database_url: str, dry_run: bool, limit: int | None) -> int:
    structlog.configure(processors=[structlog.dev.ConsoleRenderer()])

    job_start = datetime.now(timezone.utc)
    window = ExtractionWindow.ending_at(job_start, days=BASELINE_WINDOW_DAYS)
    schema_fp = FeatureVector.feature_schema_fingerprint()

    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  Helixor — Baseline v2 Backfill                              ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"  mode            : {'DRY RUN (no writes)' if dry_run else 'LIVE'}")
    print(f"  algo version    : v{BASELINE_ALGO_VERSION}")
    print(f"  schema fp       : {schema_fp[:24]}...")
    print(f"  window          : {window.start.date()} → {window.end.date()} ({BASELINE_WINDOW_DAYS}d)")
    print()

    pool = await asyncpg.create_pool(database_url, min_size=1, max_size=4)
    try:
        async with pool.acquire() as conn:
            # Worklist: agents WITHOUT an up-to-date v2 baseline. Re-running the
            # job naturally shrinks this list — that's the resumability.
            worklist = await repo.list_agents_needing_v2_baseline(
                conn,
                current_algo_version=BASELINE_ALGO_VERSION,
                current_schema_fingerprint=schema_fp,
            )
            if limit is not None:
                worklist = worklist[:limit]

            already_current, total_active = await repo.count_v2_baselines(
                conn,
                current_algo_version=BASELINE_ALGO_VERSION,
                current_schema_fingerprint=schema_fp,
            )

        print(f"  active agents   : {total_active}")
        print(f"  already on v2   : {already_current}")
        print(f"  to process      : {len(worklist)}")
        print()

        if not worklist:
            print("  ✓ every active agent already has an up-to-date v2 baseline.")
            print()
            return 0

        results: list[AgentResult] = []
        for i, wallet in enumerate(worklist, start=1):
            # Each agent gets its own connection acquisition so a long backfill
            # doesn't hold one connection for the whole run.
            async with pool.acquire() as conn:
                result = await _process_agent(conn, wallet, window, job_start, dry_run)
            results.append(result)

            mark = {
                "written":           "\x1b[32m✓\x1b[0m",
                "dry-run-ok":        "\x1b[36m·\x1b[0m",
                "insufficient-data": "\x1b[33m!\x1b[0m",
                "error":             "\x1b[31m✗\x1b[0m",
            }[result.status]
            prov = " [provisional]" if result.is_provisional else ""
            print(f"  {mark} [{i:>4}/{len(worklist)}] {wallet[:16]}...  {result.detail}{prov}")

        # ── Summary ──────────────────────────────────────────────────────────
        written      = sum(1 for r in results if r.status == "written")
        dry_ok       = sum(1 for r in results if r.status == "dry-run-ok")
        provisional  = sum(1 for r in results if r.is_provisional)
        insufficient = sum(1 for r in results if r.status == "insufficient-data")
        errored      = sum(1 for r in results if r.status == "error")

        print()
        print("  ┌─────────────────────────────────────────────┐")
        print(f"  │  processed         {len(results):>6}                   │")
        if dry_run:
            print(f"  │  would write       {dry_ok:>6}                   │")
        else:
            print(f"  │  written           {written:>6}                   │")
        print(f"  │  provisional       {provisional:>6}  (low data)       │")
        print(f"  │  insufficient data {insufficient:>6}  (skipped)        │")
        print(f"  │  errors            {errored:>6}                   │")
        print("  └─────────────────────────────────────────────┘")
        print()

        if not dry_run:
            # Re-check the "done when" condition.
            async with pool.acquire() as conn:
                current, total = await repo.count_v2_baselines(
                    conn,
                    current_algo_version=BASELINE_ALGO_VERSION,
                    current_schema_fingerprint=schema_fp,
                )
            print(f"  v2 baseline coverage: {current}/{total} active agents")
            if current == total:
                print("  \x1b[32m✓ Day-2 done-when satisfied: all active agents have a v2 baseline.\x1b[0m")
            else:
                missing = total - current
                print(f"  \x1b[33m! {missing} agent(s) still without a v2 baseline "
                      f"(insufficient data or errors — see above).\x1b[0m")
            print()

        # Non-zero exit if anything errored, so cron / CI notices.
        return 1 if errored > 0 else 0

    finally:
        await pool.close()


def main() -> None:
    import os

    parser = argparse.ArgumentParser(description="Backfill v2 baselines for all agents.")
    parser.add_argument("--dry-run", action="store_true",
                        help="compute + report, write nothing")
    parser.add_argument("--limit", type=int, default=None,
                        help="process at most N agents (incremental rollout)")
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL"),
                        help="Postgres connection string (or set DATABASE_URL)")
    args = parser.parse_args()

    if not args.database_url:
        print("error: --database-url or DATABASE_URL is required", file=sys.stderr)
        sys.exit(2)

    exit_code = asyncio.run(run(args.database_url, args.dry_run, args.limit))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
