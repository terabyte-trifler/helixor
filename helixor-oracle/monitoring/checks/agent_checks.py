"""
monitoring/checks/agent_checks.py — agent-specific monitoring.

Day 11's success criterion: ONE specific real agent has been continuously
scored for 24+ hours. These checks verify EACH monitored agent specifically.

Each monitored agent gets its OWN alert key — `agent_score_stale:{wallet}` —
so different agents alert independently. One stuck agent doesn't suppress
alerts for other stuck agents.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import asyncpg

from monitoring.types import CheckResult


def _short(wallet: str) -> str:
    return wallet[:8] + "..." + wallet[-4:]


# =============================================================================
# Per-agent: score is fresh
# =============================================================================

async def check_agent_score_fresh(
    conn:         asyncpg.Connection,
    agent_wallet: str,
    label:        str,
    *,
    max_age_hours: int = 26,
) -> CheckResult:
    """A specific monitored agent must have a fresh on-chain score."""
    row = await conn.fetchrow(
        """
        SELECT score, alert, written_onchain_at, computed_at
        FROM agent_scores
        WHERE agent_wallet = $1
        """,
        agent_wallet,
    )

    key = f"agent_score_stale:{agent_wallet}"

    if row is None:
        return CheckResult(
            name="agent_score_fresh", key=key,
            healthy=False, severity="warning",
            title=f"Monitored agent '{label}' has no score yet",
            body=f"Agent {_short(agent_wallet)} is registered + monitored "
                 f"but agent_scores has no row. "
                 f"Has the baseline been computed?",
            context={"agent": agent_wallet, "label": label},
        )

    if row["written_onchain_at"] is None:
        # We have a computed score but haven't synced it
        age = datetime.now(tz=timezone.utc) - row["computed_at"]
        return CheckResult(
            name="agent_score_fresh", key=key,
            healthy=False, severity="warning",
            title=f"Agent '{label}' score not on-chain",
            body=f"Computed {int(age.total_seconds()/3600)}h ago "
                 f"({row['computed_at'].isoformat()}) but never synced. "
                 f"Check epoch_runner.",
            context={"agent": agent_wallet, "label": label,
                     "computed_at": row["computed_at"].isoformat()},
        )

    age = datetime.now(tz=timezone.utc) - row["written_onchain_at"]
    age_hours = age.total_seconds() / 3600
    age_ms    = int(age.total_seconds() * 1000)

    if age > timedelta(hours=max_age_hours):
        return CheckResult(
            name="agent_score_fresh", key=key,
            healthy=False, severity="warning",
            title=f"Agent '{label}' on-chain score is {age_hours:.1f}h old",
            body=f"Last write {row['written_onchain_at'].isoformat()}. "
                 f"Threshold: {max_age_hours}h. Score: {row['score']} ({row['alert']}).",
            value_ms=age_ms,
            context={"agent": agent_wallet, "label": label,
                     "score": row["score"], "alert": row["alert"]},
        )

    return CheckResult(
        name="agent_score_fresh", key=key,
        healthy=True,
        title=f"Agent '{label}' fresh",
        body=f"Score {row['score']} ({row['alert']}), updated {age_hours:.1f}h ago.",
        value_ms=age_ms,
        context={"agent": agent_wallet, "label": label,
                 "score": row["score"], "alert": row["alert"]},
    )


# =============================================================================
# Per-agent: score above expected minimum
# =============================================================================

async def check_agent_score_floor(
    conn:               asyncpg.Connection,
    agent_wallet:       str,
    label:              str,
    expected_min_score: int | None,
) -> CheckResult:
    """If the operator set expected_min_score, alert when agent drops below."""
    if expected_min_score is None:
        return CheckResult(
            name="agent_score_floor",
            key=f"agent_score_floor:{agent_wallet}",
            healthy=True,
            title=f"Agent '{label}' floor not configured",
            body="No expected_min_score set; skipping.",
        )

    score = await conn.fetchval(
        "SELECT score FROM agent_scores WHERE agent_wallet = $1",
        agent_wallet,
    )

    key = f"agent_score_floor:{agent_wallet}"

    if score is None:
        return CheckResult(
            name="agent_score_floor", key=key,
            healthy=False, severity="info",
            title=f"Agent '{label}' has no score to compare",
            body=f"Cannot evaluate floor of {expected_min_score}; agent has no score yet.",
            context={"agent": agent_wallet, "label": label},
        )

    if score < expected_min_score:
        severity = "warning" if score >= expected_min_score - 100 else "critical"
        return CheckResult(
            name="agent_score_floor", key=key,
            healthy=False, severity=severity,
            title=f"Agent '{label}' below floor: {score} < {expected_min_score}",
            body=f"Score {score} is below operator-set floor {expected_min_score}. "
                 f"Investigate transaction history.",
            value_ms=score,
            context={"agent": agent_wallet, "label": label,
                     "score": score, "floor": expected_min_score},
        )

    return CheckResult(
        name="agent_score_floor", key=key,
        healthy=True,
        title=f"Agent '{label}' above floor",
        body=f"Score {score} ≥ floor {expected_min_score}.",
        value_ms=score,
        context={"agent": agent_wallet, "label": label,
                 "score": score, "floor": expected_min_score},
    )


# =============================================================================
# Per-agent: anomaly flag fires
# =============================================================================

async def check_agent_anomaly(
    conn:         asyncpg.Connection,
    agent_wallet: str,
    label:        str,
) -> CheckResult:
    """Anomaly flag = scoring engine detected unusual behaviour. Always alert."""
    row = await conn.fetchrow(
        "SELECT score, anomaly_flag FROM agent_scores WHERE agent_wallet = $1",
        agent_wallet,
    )
    key = f"agent_anomaly:{agent_wallet}"

    if row is None or not row["anomaly_flag"]:
        return CheckResult(
            name="agent_anomaly", key=key, healthy=True,
            title=f"Agent '{label}' no anomaly",
            body="anomaly_flag = false",
            context={"agent": agent_wallet, "label": label},
        )

    return CheckResult(
        name="agent_anomaly", key=key,
        healthy=False, severity="warning",
        title=f"Agent '{label}' anomaly flag set",
        body=f"Score {row['score']}. Recent behavior diverges from baseline. "
             f"Review agent_baseline_history vs current 7-day window.",
        context={"agent": agent_wallet, "label": label, "score": row["score"]},
    )


# =============================================================================
# List enabled monitored agents
# =============================================================================

async def list_monitored_agents(conn: asyncpg.Connection):
    """Return all enabled monitored agents for the runner."""
    rows = await conn.fetch(
        """
        SELECT agent_wallet, label, expected_min_score, expected_alert_level
        FROM monitored_agents
        WHERE enabled = TRUE
        ORDER BY monitor_started_at ASC
        """,
    )
    return [
        {
            "agent_wallet":       r["agent_wallet"],
            "label":              r["label"],
            "expected_min_score": r["expected_min_score"],
            "expected_alert_level": r["expected_alert_level"],
        }
        for r in rows
    ]
