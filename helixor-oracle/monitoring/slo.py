"""
monitoring/slo.py — SLO computation over monitoring_slo_samples.

For each check we maintain percentiles over a rolling window. Operators see
"epoch_freshness p99 over last 7 days = 25h" and know whether they're
meeting their commitment to partners.
"""

from __future__ import annotations

from dataclasses import dataclass

import asyncpg


@dataclass(frozen=True, slots=True)
class SloReport:
    check_name:    str
    window_hours:  int
    sample_count:  int
    healthy_count: int
    healthy_rate:  float
    p50_ms:        int | None
    p95_ms:        int | None
    p99_ms:        int | None


async def compute_slo(
    conn:        asyncpg.Connection,
    check_name:  str,
    *,
    window_hours: int = 24 * 7,    # 7 days
) -> SloReport:
    row = await conn.fetchrow(
        f"""
        SELECT
          COUNT(*)                                                   AS n,
          COUNT(*) FILTER (WHERE healthy)                            AS n_healthy,
          PERCENTILE_DISC(0.50) WITHIN GROUP (ORDER BY value_ms)::int AS p50,
          PERCENTILE_DISC(0.95) WITHIN GROUP (ORDER BY value_ms)::int AS p95,
          PERCENTILE_DISC(0.99) WITHIN GROUP (ORDER BY value_ms)::int AS p99
        FROM monitoring_slo_samples
        WHERE check_name = $1
          AND sampled_at >= NOW() - ($2 || ' hours')::INTERVAL
          AND value_ms IS NOT NULL
        """,
        check_name, str(window_hours),
    )

    n = row["n"] or 0
    return SloReport(
        check_name    = check_name,
        window_hours  = window_hours,
        sample_count  = n,
        healthy_count = row["n_healthy"] or 0,
        healthy_rate  = (row["n_healthy"] or 0) / n if n > 0 else 0.0,
        p50_ms        = row["p50"],
        p95_ms        = row["p95"],
        p99_ms        = row["p99"],
    )


async def slo_summary(conn: asyncpg.Connection) -> list[SloReport]:
    """Compute SLO for every check_name we've seen samples for."""
    names = [r["n"] for r in await conn.fetch(
        "SELECT DISTINCT check_name AS n FROM monitoring_slo_samples ORDER BY n"
    )]
    return [await compute_slo(conn, n) for n in names]
