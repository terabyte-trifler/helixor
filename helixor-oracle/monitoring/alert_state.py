"""
monitoring/alert_state.py — alert deduplication state machine.

The principle: an alert key represents one ongoing concern. While that
concern persists, we only NOTIFY at most once per cooldown window
(default 1h for warnings, 30min for critical). When the underlying check
recovers, we mark the alert resolved + emit a single recovery notification.

This is what separates "a paging system" from "an inbox bombarded into noise."
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import asyncpg
import structlog

from monitoring.types import CheckResult, Severity

log = structlog.get_logger(__name__)


# Cooldown windows — re-notify only if this much time elapsed since last notify
COOLDOWN_BY_SEVERITY: dict[Severity, timedelta] = {
    "critical": timedelta(minutes=30),
    "warning":  timedelta(hours=1),
    "info":     timedelta(hours=6),
}


@dataclass(frozen=True, slots=True)
class AlertDecision:
    """What the runner should do with this check result."""
    should_notify:   bool       # send to Telegram/email/etc
    is_new:          bool       # first time firing
    is_resolution:   bool       # recovery notification
    fire_count:      int        # how many times since first fire
    title:           str
    body:            str
    severity:        Severity
    context:         dict[str, Any]


async def evaluate(
    conn:    asyncpg.Connection,
    result:  CheckResult,
) -> AlertDecision | None:
    """
    Decide whether to notify based on previous state + cooldown.

    Returns None if the check is healthy AND there's no prior alert to resolve.
    Returns an AlertDecision otherwise.

    All DB writes (state update + audit row) happen here so the caller just
    has to deliver the notification if `should_notify` is True.
    """
    now = datetime.now(tz=timezone.utc)

    # Look up previous state for this key
    state_row = await conn.fetchrow(
        """
        SELECT alert_key, is_active, severity, first_fired_at, last_fired_at,
               fire_count, last_notified_at, resolved_at
        FROM monitoring_alert_state
        WHERE alert_key = $1
        """,
        result.key,
    )

    # ── HEALTHY check: maybe resolve an open alert ───────────────────────────
    if result.healthy:
        if state_row is None or not state_row["is_active"]:
            # Nothing to do — never alerted, or already resolved
            return None

        # Resolution: notify recovery exactly once
        await conn.execute(
            """
            UPDATE monitoring_alert_state
            SET is_active        = FALSE,
                resolved_at      = $2,
                last_notified_at = $2
            WHERE alert_key = $1
            """,
            result.key, now,
        )

        log.info("alert_resolved", key=result.key,
                 first_fired=state_row["first_fired_at"].isoformat(),
                 fire_count=state_row["fire_count"])

        return AlertDecision(
            should_notify = True,
            is_new        = False,
            is_resolution = True,
            fire_count    = state_row["fire_count"],
            title         = f"RESOLVED: {result.title or result.name}",
            body          = f"Check {result.name} recovered. Was firing since "
                            f"{state_row['first_fired_at'].isoformat()}, "
                            f"{state_row['fire_count']} occurrences.",
            severity      = "info",
            context       = {**result.context, "resolved": True},
        )

    # ── UNHEALTHY check: insert/upsert state, decide whether to notify ───────
    if state_row is None:
        # First time firing this key
        await conn.execute(
            """
            INSERT INTO monitoring_alert_state
              (alert_key, is_active, severity,
               first_fired_at, last_fired_at, fire_count, last_notified_at)
            VALUES ($1, TRUE, $2, $3, $3, 1, $3)
            """,
            result.key, result.severity, now,
        )
        await _audit(conn, result, now, notified=True)

        log.warning("alert_fired_first_time", key=result.key, severity=result.severity)

        return AlertDecision(
            should_notify = True, is_new = True, is_resolution = False,
            fire_count    = 1,
            title         = result.title or result.name,
            body          = result.body,
            severity      = result.severity,
            context       = result.context,
        )

    # Already-active alert: check cooldown
    cooldown = COOLDOWN_BY_SEVERITY[result.severity]
    last_notified = state_row["last_notified_at"]
    new_count = state_row["fire_count"] + 1

    should_notify = (
        last_notified is None
        or (now - last_notified) >= cooldown
    )

    await conn.execute(
        """
        UPDATE monitoring_alert_state
        SET last_fired_at    = $2,
            fire_count       = $3,
            last_notified_at = CASE WHEN $4 THEN $2 ELSE last_notified_at END,
            severity         = $5,
            is_active        = TRUE,
            resolved_at      = NULL
        WHERE alert_key = $1
        """,
        result.key, now, new_count, should_notify, result.severity,
    )
    await _audit(conn, result, now, notified=should_notify)

    if should_notify:
        log.warning("alert_renotified",
                    key=result.key, fire_count=new_count,
                    cooldown_seconds=cooldown.total_seconds())

    return AlertDecision(
        should_notify = should_notify,
        is_new        = False,
        is_resolution = False,
        fire_count    = new_count,
        title         = result.title or result.name,
        body          = result.body,
        severity      = result.severity,
        context       = result.context,
    )


async def _audit(
    conn: asyncpg.Connection,
    result: CheckResult,
    fired_at: datetime,
    *,
    notified: bool,
) -> None:
    """Insert a row into monitoring_alerts (audit trail)."""
    import json
    await conn.execute(
        """
        INSERT INTO monitoring_alerts
          (alert_key, severity, title, body, context, delivered_to, fired_at)
        VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
        """,
        result.key, result.severity,
        result.title or result.name,
        result.body,
        json.dumps(result.context),
        ["pending"] if notified else [],
        fired_at,
    )


async def record_slo_sample(
    conn:   asyncpg.Connection,
    result: CheckResult,
) -> None:
    """Persist one SLO sample row for percentile computation later."""
    import json
    await conn.execute(
        """
        INSERT INTO monitoring_slo_samples
          (check_name, value_ms, healthy, context)
        VALUES ($1, $2, $3, $4::jsonb)
        """,
        result.slo_check_name(),
        result.value_ms,
        result.healthy,
        json.dumps(result.context),
    )
