"""
monitoring/checks/system_checks.py — system-level health checks.

Each check is an async function returning a CheckResult. Checks know nothing
about delivery — they just produce typed results. The runner aggregates,
deduplicates, and notifies.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone

import asyncpg
import httpx
import structlog

from monitoring.types import CheckResult

log = structlog.get_logger(__name__)


# =============================================================================
# DB connectivity
# =============================================================================

async def check_database(conn: asyncpg.Connection) -> CheckResult:
    """Confirm DB is reachable + schema is current."""
    started = time.perf_counter()
    try:
        version = await conn.fetchval(
            "SELECT MAX(version) FROM schema_version",
        )
    except Exception as e:
        return CheckResult(
            name="database_reachable",
            healthy=False,
            severity="critical",
            title="Database unreachable",
            body=f"SELECT failed: {e}",
        )

    if version is None or version < 5:
        return CheckResult(
            name="database_schema",
            healthy=False, severity="critical",
            title="Database schema out of date",
            body=f"Expected schema_version >= 5, got {version}. Run migrations.",
        )

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return CheckResult(
        name="database_reachable",
        healthy=True,
        title="Database reachable",
        body=f"schema_version={version}, query took {elapsed_ms}ms",
        value_ms=elapsed_ms,
        context={"schema_version": version},
    )


# =============================================================================
# API liveness + readiness
# =============================================================================

async def check_api_health(api_url: str) -> CheckResult:
    """GET /health — should return 200 fast."""
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=5) as http:
            r = await http.get(f"{api_url}/health")
        elapsed_ms = int((time.perf_counter() - started) * 1000)
    except httpx.TimeoutException:
        return CheckResult(
            name="api_health", healthy=False, severity="critical",
            title="API /health timed out",
            body=f"No response within 5s. URL: {api_url}/health",
        )
    except Exception as e:
        return CheckResult(
            name="api_health", healthy=False, severity="critical",
            title="API /health unreachable",
            body=f"{type(e).__name__}: {e}",
        )

    if r.status_code != 200:
        return CheckResult(
            name="api_health", healthy=False, severity="critical",
            title=f"API /health returned {r.status_code}",
            body=r.text[:300],
            value_ms=elapsed_ms,
        )

    return CheckResult(
        name="api_health", healthy=True,
        title="API healthy",
        body=f"GET /health → 200 in {elapsed_ms}ms",
        value_ms=elapsed_ms,
        context={"url": api_url},
    )


# =============================================================================
# Webhook receiver — last successful event
# =============================================================================

async def check_webhook_freshness(
    conn: asyncpg.Connection,
    *,
    max_age_minutes: int = 60,
) -> CheckResult:
    """
    Healthy if we received any webhook event in the last N minutes.

    Critical: this checks the RECEIVER (every event we got, regardless of
    whether it referenced a known agent), not "transactions per agent."
    A receiver that's been silent for an hour means Helius can't reach us.
    """
    row = await conn.fetchrow(
        """
        SELECT MAX(received_at) AS last_received,
               COUNT(*) FILTER (WHERE received_at >= NOW() - INTERVAL '1 hour') AS recent
        FROM webhook_events
        """,
    )

    last = row["last_received"] if row else None
    recent = row["recent"] if row else 0

    if last is None:
        return CheckResult(
            name="webhook_freshness", healthy=False, severity="warning",
            title="Webhook receiver has never received an event",
            body="webhook_events table is empty. Is the registrar running?",
        )

    age = datetime.now(tz=timezone.utc) - last
    age_minutes = int(age.total_seconds() / 60)
    age_ms      = int(age.total_seconds() * 1000)

    if age > timedelta(minutes=max_age_minutes):
        return CheckResult(
            name="webhook_freshness", healthy=False, severity="warning",
            title=f"No webhook events for {age_minutes}min",
            body=f"Last event at {last.isoformat()} ({age_minutes}min ago). "
                 f"Threshold: {max_age_minutes}min. "
                 f"Check Helius webhook config + reconciler logs.",
            value_ms=age_ms,
            context={"last_received_at": last.isoformat(), "recent_1h": recent},
        )

    return CheckResult(
        name="webhook_freshness", healthy=True,
        title="Webhook receiver fresh",
        body=f"Last event {age_minutes}min ago. {recent} events in last 1h.",
        value_ms=age_ms,
        context={"last_received_at": last.isoformat(), "recent_1h": recent},
    )


# =============================================================================
# Epoch runner — last on-chain submission
# =============================================================================

async def check_epoch_freshness(
    conn: asyncpg.Connection,
    *,
    max_age_hours: int = 26,
) -> CheckResult:
    """
    Healthy if SOMEONE got a fresh on-chain score recently.
    Threshold: 26h (allows for the 24h epoch + 2h grace).

    We use written_onchain_at, NOT computed_at — we care about on-chain
    write success, not just local computation.
    """
    last = await conn.fetchval(
        """
        SELECT MAX(written_onchain_at)
        FROM agent_scores
        WHERE written_onchain_at IS NOT NULL
        """,
    )

    if last is None:
        return CheckResult(
            name="epoch_freshness", healthy=False, severity="critical",
            title="No score has ever been written on-chain",
            body="agent_scores has no row with written_onchain_at set. "
                 "Run epoch_runner manually and check oracle wallet balance.",
        )

    age = datetime.now(tz=timezone.utc) - last
    age_hours = age.total_seconds() / 3600
    age_ms = int(age.total_seconds() * 1000)

    if age > timedelta(hours=max_age_hours):
        return CheckResult(
            name="epoch_freshness", healthy=False, severity="critical",
            title=f"Last on-chain score is {age_hours:.1f}h old",
            body=f"Last write at {last.isoformat()}. Threshold: {max_age_hours}h. "
                 f"Check epoch_runner logs and oracle wallet balance.",
            value_ms=age_ms,
            context={"last_onchain_at": last.isoformat()},
        )

    return CheckResult(
        name="epoch_freshness", healthy=True,
        title="Epoch fresh",
        body=f"Last on-chain write {age_hours:.1f}h ago.",
        value_ms=age_ms,
        context={"last_onchain_at": last.isoformat()},
    )


# =============================================================================
# Unsynced scores — backlog detection
# =============================================================================

async def check_unsynced_backlog(
    conn: asyncpg.Connection,
    *,
    max_unsynced: int = 20,
) -> CheckResult:
    """
    Healthy if fewer than max_unsynced agents have computed scores not yet
    on-chain. A growing backlog means epoch_runner is failing to submit.
    """
    count = await conn.fetchval(
        """
        SELECT COUNT(*) FROM agent_scores
        WHERE written_onchain_at IS NULL
          AND computed_at < NOW() - INTERVAL '2 hours'
        """,
    )
    count = count or 0

    if count > max_unsynced:
        return CheckResult(
            name="unsynced_backlog", healthy=False, severity="warning",
            title=f"{count} unsynced scores older than 2h",
            body=f"epoch_runner is falling behind. Threshold: {max_unsynced}. "
                 f"Investigate priority fees or oracle balance.",
            value_ms=count,
            context={"unsynced_count": count},
        )

    return CheckResult(
        name="unsynced_backlog", healthy=True,
        title="Submission backlog within bounds",
        body=f"{count} unsynced scores (threshold {max_unsynced}).",
        value_ms=count,
        context={"unsynced_count": count},
    )


# =============================================================================
# Oracle wallet balance
# =============================================================================

async def check_oracle_balance(
    rpc_url:        str,
    oracle_pubkey:  str,
    *,
    min_lamports: int = 100_000_000,   # 0.1 SOL
) -> CheckResult:
    """
    Verify oracle wallet has enough SOL to keep paying tx fees + new cert rent.
    Below 0.1 SOL = warning. Below 0.01 SOL = critical (one bad day from empty).
    """
    try:
        async with httpx.AsyncClient(timeout=10) as http:
            r = await http.post(rpc_url, json={
                "jsonrpc": "2.0", "id": 1,
                "method": "getBalance",
                "params": [oracle_pubkey, {"commitment": "confirmed"}],
            })
        body = r.json()
        lamports = body["result"]["value"]
    except Exception as e:
        return CheckResult(
            name="oracle_balance", healthy=False, severity="warning",
            title="Cannot read oracle wallet balance",
            body=f"{type(e).__name__}: {e}",
        )

    sol = lamports / 1_000_000_000
    severity = ("critical" if lamports < min_lamports // 10
                else "warning" if lamports < min_lamports
                else "info")

    if lamports < min_lamports:
        return CheckResult(
            name="oracle_balance", healthy=False, severity=severity,
            title=f"Oracle balance low: {sol:.4f} SOL",
            body=f"Pubkey {oracle_pubkey} has {sol:.4f} SOL "
                 f"({lamports} lamports). Threshold: 0.1 SOL. "
                 f"Top up before next epoch.",
            value_ms=lamports,
            context={"oracle_pubkey": oracle_pubkey, "lamports": lamports},
        )

    return CheckResult(
        name="oracle_balance", healthy=True,
        title="Oracle balance OK",
        body=f"{sol:.4f} SOL ({lamports} lamports)",
        value_ms=lamports,
        context={"oracle_pubkey": oracle_pubkey, "lamports": lamports},
    )
