#!/usr/bin/env python3
"""
scripts/operator/show_status.py — single-pass status dashboard.

Prints a colored summary of:
  - All monitored agents and their current scores
  - System health checks
  - SLO percentiles for the last 7 days
  - Open alerts

Run this when something feels off — or daily as a sanity check.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone

import structlog

from indexer import db
from monitoring import slo


GREEN = "\033[0;32m"; YELLOW = "\033[1;33m"; RED = "\033[0;31m"; BOLD = "\033[1m"; DIM = "\033[2m"; NC = "\033[0m"


async def run() -> int:
    structlog.configure(processors=[structlog.dev.ConsoleRenderer()])
    await db.init_pool()
    pool = await db.get_pool()

    try:
        async with pool.acquire() as conn:
            # ── Header ───────────────────────────────────────────────────
            print()
            print(f"{BOLD}╔══════════════════════════════════════════════════════╗{NC}")
            print(f"{BOLD}║  Helixor Oracle Status                               ║{NC}")
            print(f"{BOLD}║  {datetime.now(tz=timezone.utc).isoformat(timespec='seconds')}                            ║{NC}")
            print(f"{BOLD}╚══════════════════════════════════════════════════════╝{NC}")
            print()

            # ── Monitored agents ─────────────────────────────────────────
            print(f"{BOLD}── Monitored agents ──{NC}")
            agents = await conn.fetch("""
                SELECT m.agent_wallet, m.label, m.expected_min_score,
                       s.score, s.alert, s.anomaly_flag,
                       s.computed_at, s.written_onchain_at
                FROM monitored_agents m
                LEFT JOIN agent_scores s ON s.agent_wallet = m.agent_wallet
                WHERE m.enabled = TRUE
                ORDER BY m.monitor_started_at ASC
            """)
            if not agents:
                print(f"  {DIM}(none — add via scripts/operator/add_monitored_agent.py){NC}")
            for row in agents:
                wallet = row["agent_wallet"][:12] + "..."
                label  = row["label"]
                if row["score"] is None:
                    print(f"  {YELLOW}!{NC} {label:30} {wallet} — no score yet")
                else:
                    color = (GREEN if row["alert"] == "GREEN"
                            else YELLOW if row["alert"] == "YELLOW" else RED)
                    sync_age = ""
                    if row["written_onchain_at"]:
                        age_h = (datetime.now(tz=timezone.utc) - row["written_onchain_at"]).total_seconds()/3600
                        sync_age = f" (on-chain {age_h:.1f}h ago)"
                    elif row["computed_at"]:
                        sync_age = f" {DIM}(unsynced){NC}"
                    anomaly = f" {RED}[ANOMALY]{NC}" if row["anomaly_flag"] else ""
                    print(f"  {color}●{NC} {label:30} {wallet} score {row['score']} ({row['alert']}){sync_age}{anomaly}")

            # ── System checks (last sample per check) ────────────────────
            print()
            print(f"{BOLD}── System health (last sample) ──{NC}")
            sys_checks = await conn.fetch("""
                SELECT DISTINCT ON (check_name)
                  check_name, healthy, value_ms, sampled_at
                FROM monitoring_slo_samples
                ORDER BY check_name, sampled_at DESC
            """)
            if not sys_checks:
                print(f"  {DIM}(no checks yet — run `python -m monitoring.runner --once`){NC}")
            for row in sys_checks:
                age_min = (datetime.now(tz=timezone.utc) - row["sampled_at"]).total_seconds() / 60
                mark = f"{GREEN}✓{NC}" if row["healthy"] else f"{RED}✗{NC}"
                ms_str = f"  ({row['value_ms']}ms)" if row["value_ms"] else ""
                print(f"  {mark} {row['check_name']:24}{ms_str}  {DIM}({age_min:.0f}min ago){NC}")

            # ── SLOs ─────────────────────────────────────────────────────
            print()
            print(f"{BOLD}── SLOs (7-day rolling) ──{NC}")
            reports = await slo.slo_summary(conn)
            if not reports:
                print(f"  {DIM}(no SLO samples yet){NC}")
            for r in reports:
                rate_color = (GREEN if r.healthy_rate >= 0.99
                              else YELLOW if r.healthy_rate >= 0.95 else RED)
                p50 = f"{r.p50_ms}" if r.p50_ms is not None else "—"
                p95 = f"{r.p95_ms}" if r.p95_ms is not None else "—"
                p99 = f"{r.p99_ms}" if r.p99_ms is not None else "—"
                print(f"  {r.check_name:24} "
                      f"{rate_color}{r.healthy_rate:.2%}{NC} "
                      f"({r.healthy_count}/{r.sample_count})  "
                      f"p50={p50:>6}  p95={p95:>6}  p99={p99:>6}")

            # ── Open alerts ──────────────────────────────────────────────
            print()
            print(f"{BOLD}── Open alerts ──{NC}")
            alerts = await conn.fetch("""
                SELECT alert_key, severity, fire_count, first_fired_at, last_fired_at
                FROM monitoring_alert_state
                WHERE is_active = TRUE
                ORDER BY first_fired_at ASC
            """)
            if not alerts:
                print(f"  {GREEN}none ✓{NC}")
            for a in alerts:
                color = RED if a["severity"] == "critical" else YELLOW
                age_h = (datetime.now(tz=timezone.utc) - a["first_fired_at"]).total_seconds() / 3600
                print(f"  {color}{a['severity']:8}{NC} {a['alert_key']:40} "
                      f"firing {age_h:.1f}h ({a['fire_count']}×)")
            print()

        return 0
    finally:
        await db.close_pool()


def main() -> None:
    sys.exit(asyncio.run(run()))


if __name__ == "__main__":
    main()
