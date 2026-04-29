"""
monitoring/runner.py — orchestrates all health checks.

Run modes:
  --once   single pass, exit code 0 if all healthy, 1 if any warning,
           2 if any critical
  (default) loop forever, configurable interval, suitable for systemd

Run as:
    python -m monitoring.runner --once       # CI / cron
    python -m monitoring.runner              # systemd service
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
import uuid
from pathlib import Path

import structlog

from indexer import db
from indexer.config import settings
from monitoring.alert_state import AlertDecision, evaluate, record_slo_sample
from monitoring.alerts.channels import MultiChannel
from monitoring.checks import agent_checks, system_checks
from monitoring.types import CheckResult, CheckRunSummary

log = structlog.get_logger(__name__)

DEFAULT_INTERVAL_SECONDS = 300  # 5 minutes


# =============================================================================
# Oracle pubkey resolution
# =============================================================================

def _resolve_oracle_pubkey() -> str | None:
    """Read oracle keypair to extract pubkey for balance checks."""
    path = Path(settings.oracle_keypair_path).expanduser()
    if not path.exists():
        return None
    try:
        import json
        from solders.keypair import Keypair
        secret = json.loads(path.read_text())
        return str(Keypair.from_bytes(bytes(secret)).pubkey())
    except Exception as e:
        log.warning("oracle_pubkey_resolve_failed", error=str(e))
        return None


# =============================================================================
# One pass — collect all check results
# =============================================================================

async def run_one_pass() -> CheckRunSummary:
    run_id  = uuid.uuid4().hex[:12]
    started = time.time()
    log_ctx = log.bind(run_id=run_id)
    log_ctx.info("monitoring_pass_starting")

    results: list[CheckResult] = []
    pool = await db.get_pool()
    oracle_pubkey = _resolve_oracle_pubkey()

    # ── System-level checks ──────────────────────────────────────────────────
    async with pool.acquire() as conn:
        results.append(await system_checks.check_database(conn))
        results.append(await system_checks.check_webhook_freshness(conn))
        results.append(await system_checks.check_epoch_freshness(conn))
        results.append(await system_checks.check_unsynced_backlog(conn))

    api_url = os.environ.get("HELIXOR_API_URL", "http://localhost:8001")
    results.append(await system_checks.check_api_health(api_url))

    if oracle_pubkey:
        results.append(
            await system_checks.check_oracle_balance(
                settings.solana_rpc_url, oracle_pubkey,
            ),
        )

    # ── Per-agent checks ─────────────────────────────────────────────────────
    async with pool.acquire() as conn:
        monitored = await agent_checks.list_monitored_agents(conn)

    log_ctx.info("monitored_agents_count", count=len(monitored))

    for agent in monitored:
        async with pool.acquire() as conn:
            results.append(await agent_checks.check_agent_score_fresh(
                conn, agent["agent_wallet"], agent["label"],
            ))
            results.append(await agent_checks.check_agent_score_floor(
                conn, agent["agent_wallet"], agent["label"],
                agent["expected_min_score"],
            ))
            results.append(await agent_checks.check_agent_anomaly(
                conn, agent["agent_wallet"], agent["label"],
            ))

    # ── Alert decisions + delivery ───────────────────────────────────────────
    channels = MultiChannel.from_env()
    fired = 0
    resolved = 0

    for result in results:
        async with pool.acquire() as conn:
            decision = await evaluate(conn, result)
            await record_slo_sample(conn, result)

        if decision is None:
            continue
        if decision.is_resolution:
            resolved += 1
        else:
            fired += 1

        if decision.should_notify:
            await channels.deliver(decision)

    finished = time.time()
    summary = CheckRunSummary(
        run_id=run_id, started_at=started, finished_at=finished,
        results=tuple(results),
        alerts_fired=fired, alerts_resolved=resolved,
    )

    log_ctx.info(
        "monitoring_pass_complete",
        duration_ms=summary.duration_ms,
        total_checks=len(results),
        unhealthy=sum(1 for r in results if not r.healthy),
        fired=fired, resolved=resolved,
    )
    return summary


# =============================================================================
# Modes
# =============================================================================

async def run_once() -> int:
    """One pass, exit code reflects health."""
    structlog.configure(processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ])
    await db.init_pool()
    try:
        summary = await run_one_pass()
    finally:
        await db.close_pool()

    print()
    print(f"  Run {summary.run_id} — {len(summary.results)} checks "
          f"({summary.duration_ms}ms)")
    print(f"  Healthy: {sum(1 for r in summary.results if r.healthy)}/{len(summary.results)}")
    print(f"  Fired:   {summary.alerts_fired}  Resolved: {summary.alerts_resolved}")
    print()

    for r in summary.results:
        mark = "✓" if r.healthy else ("✗" if r.severity == "critical" else "!")
        print(f"  {mark} {r.name}: {r.title}")
        if not r.healthy:
            print(f"      {r.body}")

    if summary.critical_count:
        return 2
    if any(not r.healthy for r in summary.results):
        return 1
    return 0


async def loop_forever(interval_seconds: int) -> None:
    structlog.configure(processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ])
    await db.init_pool()
    log.info("monitoring_loop_starting", interval_seconds=interval_seconds)

    try:
        while True:
            try:
                await run_one_pass()
            except Exception as e:
                log.error("monitoring_pass_failed", error=str(e))
            await asyncio.sleep(interval_seconds)
    finally:
        await db.close_pool()


# =============================================================================
# Entry
# =============================================================================

def main() -> None:
    p = argparse.ArgumentParser(description="Helixor monitoring runner")
    p.add_argument("--once", action="store_true",
                   help="Run a single pass and exit")
    p.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_SECONDS,
                   help=f"Seconds between passes when looping (default: {DEFAULT_INTERVAL_SECONDS})")
    args = p.parse_args()

    if args.once:
        sys.exit(asyncio.run(run_once()))
    else:
        try:
            asyncio.run(loop_forever(args.interval))
        except KeyboardInterrupt:
            log.info("monitoring_stopped_by_user")


if __name__ == "__main__":
    main()
