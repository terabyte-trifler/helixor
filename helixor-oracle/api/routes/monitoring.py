"""
api/routes/monitoring.py — operator-facing monitoring endpoints.

  GET /monitoring/agents         — list monitored agents + current state
  GET /monitoring/alerts         — open alerts with first/last fired times
  GET /monitoring/slos           — SLO percentiles per check
  GET /monitoring/runbook/{key}  — runbook for an alert key

These are NOT public — operators only. In production gate behind admin auth.
For Day 11 we keep them open since the API itself is on a private network.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from indexer import db
from monitoring import slo

router = APIRouter()


@router.get("/monitoring/agents")
async def list_monitored() -> dict[str, Any]:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT m.agent_wallet, m.label, m.expected_min_score,
                   m.monitor_started_at,
                   s.score, s.alert, s.anomaly_flag,
                   s.computed_at, s.written_onchain_at
            FROM monitored_agents m
            LEFT JOIN agent_scores s ON s.agent_wallet = m.agent_wallet
            WHERE m.enabled = TRUE
            ORDER BY m.monitor_started_at ASC
        """)
    return {
        "items": [dict(r) for r in rows],
        "count": len(rows),
    }


@router.get("/monitoring/alerts")
async def list_alerts(active_only: bool = True) -> dict[str, Any]:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT alert_key, severity, is_active, first_fired_at,
                   last_fired_at, fire_count, last_notified_at, resolved_at
            FROM monitoring_alert_state
            {'WHERE is_active = TRUE' if active_only else ''}
            ORDER BY first_fired_at DESC
            """,
        )
    return {"items": [dict(r) for r in rows], "count": len(rows)}


@router.get("/monitoring/slos")
async def slo_summary() -> dict[str, Any]:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        reports = await slo.slo_summary(conn)
    return {
        "items": [
            {
                "check_name":    r.check_name,
                "window_hours":  r.window_hours,
                "sample_count":  r.sample_count,
                "healthy_rate":  r.healthy_rate,
                "p50_ms":        r.p50_ms,
                "p95_ms":        r.p95_ms,
                "p99_ms":        r.p99_ms,
            }
            for r in reports
        ],
    }


# Runbook strings — the "what to do at 3am" answer for each alert key.
# We match by prefix (so per-agent keys like agent_score_stale:ABC inherit
# the agent_score_stale runbook).
RUNBOOKS: dict[str, str] = {
    "database_reachable": (
        "1. Check Postgres is running: `systemctl status postgresql`\n"
        "2. Check disk space: `df -h /var/lib/postgresql`\n"
        "3. Check connection limit: `SELECT count(*) FROM pg_stat_activity;`\n"
        "4. Restart Helixor services after Postgres is healthy."
    ),
    "api_health": (
        "1. Check the API service: `systemctl status helixor-api`\n"
        "2. Last 100 log lines: `journalctl -u helixor-api -n 100`\n"
        "3. If asyncpg pool is exhausted, restart the API.\n"
        "4. Verify port 8001 is open and not bound by another process."
    ),
    "epoch_freshness": (
        "1. Check epoch_runner service: `systemctl status helixor-epoch.service`\n"
        "2. Check the timer: `systemctl list-timers helixor-epoch.timer`\n"
        "3. Run one pass manually: `python -m oracle.epoch_runner --once`\n"
        "4. If submissions fail, check oracle wallet balance."
    ),
    "webhook_freshness": (
        "1. Check webhook_receiver: `systemctl status helixor-webhook`\n"
        "2. Verify Helius webhook is registered:\n"
        "   curl https://api.helius.xyz/v0/webhooks?api-key=$HELIUS_API_KEY\n"
        "3. Manually inject a test event: `bash scripts/test_webhook_manually.sh`\n"
        "4. Check reconciler logs for backfill errors."
    ),
    "unsynced_backlog": (
        "1. Check epoch_runner is running and not stuck on a single agent.\n"
        "2. Check oracle wallet balance.\n"
        "3. Review priority fees during congestion.\n"
        "4. Manually run epoch_runner --once to drain backlog."
    ),
    "oracle_balance": (
        "1. Top up the oracle wallet:\n"
        "   solana airdrop 2 $ORACLE_PUBKEY  (devnet)\n"
        "   or transfer SOL from treasury (mainnet).\n"
        "2. Verify balance: `solana balance $ORACLE_PUBKEY`\n"
        "3. Resume epoch_runner if it crashed."
    ),
    "agent_score_stale": (
        "1. Verify the agent is still active (not deactivated).\n"
        "2. Check baseline freshness: `SELECT * FROM agent_baselines WHERE agent_wallet = X;`\n"
        "3. Check epoch_runner ran for this agent (look for ScoreUpdated event).\n"
        "4. If specific to one agent, check agent_transactions for recent activity."
    ),
    "agent_score_floor": (
        "1. Review agent's recent transactions — anomaly investigation.\n"
        "2. Compare current 7-day window to baseline.\n"
        "3. If score is correctly low (agent failing), the alert is working.\n"
        "4. If score is incorrectly low, file a scoring algorithm bug."
    ),
    "agent_anomaly": (
        "1. Read agent_score_history for the trend over last 7 days.\n"
        "2. Compare current success_rate to baseline.\n"
        "3. Check if agent had recent network/RPC issues that look like failures.\n"
        "4. anomaly_flag clears automatically when the next score is non-anomalous."
    ),
}


@router.get("/monitoring/runbook/{key:path}")
async def runbook(key: str) -> dict[str, str]:
    # Match longest-prefix match (so "agent_score_stale:ABC123" matches
    # "agent_score_stale" runbook)
    base_key = key.split(":")[0]
    body = RUNBOOKS.get(base_key, "No runbook for this alert key. "
                                   "Update api/routes/monitoring.py to add one.")
    return {"alert_key": key, "runbook": body}
