"""
Benchmark Day-15 TimescaleDB query latency against a plain Postgres table.

This is intentionally a standalone benchmark, not a unit test:
  * it needs a real TimescaleDB instance,
  * it seeds a large synthetic transaction history,
  * it prints measured p50/p95/p99 latency numbers as JSON.

Usage:
    DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:55432/postgres \
      python scripts/benchmark_timescale_latency.py \
        --agents 250 --days 180 --tx-per-agent-day 20 --iterations 80

The benchmark creates three objects:
  * bench_agent_tx_plain       regular Postgres table
  * bench_agent_tx_hyper       TimescaleDB hypertable
  * bench_agent_tx_daily       continuous aggregate on the hypertable

It measures:
  * plain_window_raw: 30-day raw transaction scan/aggregate on the plain table
  * hyper_window_raw: 30-day raw transaction scan/aggregate on the hypertable
  * hyper_daily_cagg: 30-day daily rollup read from the continuous aggregate

The raw plain/hyper comparison is not forced to show a win; with a good
(agent_wallet, block_time) index, plain Postgres can be competitive on modest
datasets. The continuous aggregate comparison is the Day-15 production win:
daily baseline reads become 30 precomputed rows instead of raw aggregation.
"""

from __future__ import annotations

import sys

# When invoked as `python scripts/benchmark_timescale_latency.py`, Python puts
# `scripts/` on sys.path. That directory contains `scripts/operator`, which can
# shadow the stdlib `operator` module. Remove the script directory before
# importing stdlib modules that depend on it.
_script_dir = __file__.rsplit("/", 1)[0]
if _script_dir in sys.path:
    sys.path.remove(_script_dir)

import argparse
import asyncio
import json
import os
import statistics
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import asyncpg


DEFAULT_DSN = "postgresql://postgres:postgres@127.0.0.1:55432/postgres"


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    rows_returned: int
    iterations: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    min_ms: float
    max_ms: float


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, round((percentile / 100) * (len(ordered) - 1)))
    return ordered[idx]


def _summarize(name: str, rows_returned: int, samples: list[float]) -> ScenarioResult:
    return ScenarioResult(
        name=name,
        rows_returned=rows_returned,
        iterations=len(samples),
        p50_ms=statistics.median(samples),
        p95_ms=_percentile(samples, 95),
        p99_ms=_percentile(samples, 99),
        min_ms=min(samples),
        max_ms=max(samples),
    )


async def _timed_fetch(
    conn: asyncpg.Connection,
    sql: str,
    *params: Any,
    iterations: int,
) -> tuple[int, list[float]]:
    samples: list[float] = []
    rows_returned = 0
    for _ in range(iterations):
        start = time.perf_counter()
        rows = await conn.fetch(sql, *params)
        samples.append((time.perf_counter() - start) * 1000)
        rows_returned = len(rows)
    return rows_returned, samples


async def _setup(conn: asyncpg.Connection, *, agents: int, days: int, tx_per_agent_day: int) -> None:
    await conn.execute("CREATE EXTENSION IF NOT EXISTS timescaledb")
    await conn.execute("DROP MATERIALIZED VIEW IF EXISTS bench_agent_tx_daily")
    await conn.execute("DROP TABLE IF EXISTS bench_agent_tx_hyper")
    await conn.execute("DROP TABLE IF EXISTS bench_agent_tx_plain")

    schema = """
        agent_wallet  TEXT        NOT NULL,
        signature     TEXT        NOT NULL,
        slot          BIGINT      NOT NULL,
        block_time    TIMESTAMPTZ NOT NULL,
        success       BOOLEAN     NOT NULL,
        program_ids   TEXT[]      NOT NULL DEFAULT '{}',
        sol_change    BIGINT      NOT NULL DEFAULT 0,
        fee           BIGINT      NOT NULL DEFAULT 0,
        priority_fee  BIGINT      NOT NULL DEFAULT 0,
        compute_units BIGINT      NOT NULL DEFAULT 0,
        counterparty  TEXT,
        PRIMARY KEY (signature, block_time)
    """
    await conn.execute(f"CREATE TABLE bench_agent_tx_plain ({schema})")
    await conn.execute(f"CREATE TABLE bench_agent_tx_hyper ({schema})")
    await conn.execute(
        """
        SELECT create_hypertable(
            'bench_agent_tx_hyper',
            'block_time',
            chunk_time_interval => INTERVAL '1 day',
            if_not_exists => TRUE
        )
        """,
    )

    seed_sql = """
        INSERT INTO {table}
            (agent_wallet, signature, slot, block_time, success, program_ids,
             sol_change, fee, priority_fee, compute_units, counterparty)
        SELECT
            'agent_' || lpad(agent_id::text, 5, '0') AS agent_wallet,
            {prefix} || '_' || agent_id || '_' || day_id || '_' || tx_id AS signature,
            1000000000 + (agent_id * $2 * $3) + (day_id * $3) + tx_id AS slot,
            $4::timestamptz
                - (day_id || ' days')::interval
                + ((tx_id % 24) || ' hours')::interval AS block_time,
            (tx_id % 20) <> 0 AS success,
            ARRAY['JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4']::text[] AS program_ids,
            CASE WHEN tx_id % 2 = 0 THEN 1000000 ELSE -400000 END AS sol_change,
            5000 AS fee,
            CASE WHEN tx_id % 5 = 0 THEN 100 ELSE 0 END AS priority_fee,
            200000 AS compute_units,
            'cp_' || ((agent_id + tx_id) % 200) AS counterparty
        FROM generate_series(0, $1 - 1) AS agent_id
        CROSS JOIN generate_series(0, $2 - 1) AS day_id
        CROSS JOIN generate_series(0, $3 - 1) AS tx_id
    """
    ref_end = datetime(2026, 5, 1, 12, tzinfo=UTC)
    await conn.execute(
        seed_sql.format(table="bench_agent_tx_plain", prefix="'plain'"),
        agents,
        days,
        tx_per_agent_day,
        ref_end,
    )
    await conn.execute(
        seed_sql.format(table="bench_agent_tx_hyper", prefix="'hyper'"),
        agents,
        days,
        tx_per_agent_day,
        ref_end,
    )

    await conn.execute(
        "CREATE INDEX bench_plain_wallet_time ON bench_agent_tx_plain (agent_wallet, block_time DESC)",
    )
    await conn.execute(
        "CREATE INDEX bench_hyper_wallet_time ON bench_agent_tx_hyper (agent_wallet, block_time DESC)",
    )
    await conn.execute("ANALYZE bench_agent_tx_plain")
    await conn.execute("ANALYZE bench_agent_tx_hyper")

    await conn.execute(
        """
        CREATE MATERIALIZED VIEW bench_agent_tx_daily
        WITH (timescaledb.continuous) AS
        SELECT
            agent_wallet,
            time_bucket(INTERVAL '1 day', block_time) AS day,
            count(*) AS tx_count,
            count(*) FILTER (WHERE success) AS success_count,
            avg(CASE WHEN success THEN 1.0 ELSE 0.0 END) AS success_rate,
            sum(sol_change) AS net_sol_change,
            sum(fee + priority_fee) AS total_fees,
            count(DISTINCT counterparty) AS distinct_counterparties
        FROM bench_agent_tx_hyper
        GROUP BY agent_wallet, day
        WITH NO DATA
        """,
    )
    await conn.execute(
        """
        CALL refresh_continuous_aggregate(
            'bench_agent_tx_daily',
            $1::timestamptz - ($2::text || ' days')::interval,
            $1::timestamptz + INTERVAL '1 day'
        )
        """,
        ref_end,
        str(days),
    )


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    conn = await asyncpg.connect(args.database_url)
    try:
        if not args.skip_setup:
            await _setup(
                conn,
                agents=args.agents,
                days=args.days,
                tx_per_agent_day=args.tx_per_agent_day,
            )

        total_rows = args.agents * args.days * args.tx_per_agent_day
        agent_wallet = f"agent_{args.agent_index:05d}"
        ref_end = datetime(2026, 5, 1, 12, tzinfo=UTC)
        start = ref_end.replace() - args.window_days_delta

        raw_sql = """
            SELECT date_trunc('day', block_time) AS day,
                   count(*) AS tx_count,
                   avg(CASE WHEN success THEN 1.0 ELSE 0.0 END) AS success_rate,
                   sum(sol_change) AS net_sol_change,
                   sum(fee + priority_fee) AS total_fees
              FROM {table}
             WHERE agent_wallet = $1
               AND block_time >= $2
               AND block_time < $3
             GROUP BY day
             ORDER BY day ASC
        """
        cagg_sql = """
            SELECT day, tx_count, success_rate, net_sol_change, total_fees
              FROM bench_agent_tx_daily
             WHERE agent_wallet = $1
               AND day >= $2
               AND day < $3
             ORDER BY day ASC
        """

        # Warm cache before measuring.
        await conn.fetch(raw_sql.format(table="bench_agent_tx_plain"), agent_wallet, start, ref_end)
        await conn.fetch(raw_sql.format(table="bench_agent_tx_hyper"), agent_wallet, start, ref_end)
        await conn.fetch(cagg_sql, agent_wallet, start, ref_end)

        results: list[ScenarioResult] = []
        rows, samples = await _timed_fetch(
            conn,
            raw_sql.format(table="bench_agent_tx_plain"),
            agent_wallet,
            start,
            ref_end,
            iterations=args.iterations,
        )
        results.append(_summarize("plain_window_raw", rows, samples))

        rows, samples = await _timed_fetch(
            conn,
            raw_sql.format(table="bench_agent_tx_hyper"),
            agent_wallet,
            start,
            ref_end,
            iterations=args.iterations,
        )
        results.append(_summarize("hyper_window_raw", rows, samples))

        rows, samples = await _timed_fetch(
            conn,
            cagg_sql,
            agent_wallet,
            start,
            ref_end,
            iterations=args.iterations,
        )
        results.append(_summarize("hyper_daily_cagg", rows, samples))

        by_name = {r.name: r for r in results}
        raw_p95_speedup = (
            by_name["plain_window_raw"].p95_ms / by_name["hyper_window_raw"].p95_ms
            if by_name["hyper_window_raw"].p95_ms else None
        )
        cagg_p95_speedup = (
            by_name["plain_window_raw"].p95_ms / by_name["hyper_daily_cagg"].p95_ms
            if by_name["hyper_daily_cagg"].p95_ms else None
        )
        return {
            "dataset": {
                "agents": args.agents,
                "days": args.days,
                "tx_per_agent_day": args.tx_per_agent_day,
                "total_rows_per_table": total_rows,
                "measured_agent_wallet": agent_wallet,
                "window_days": args.window_days,
                "iterations": args.iterations,
            },
            "results": [r.__dict__ for r in results],
            "speedups": {
                "plain_raw_p95_over_hyper_raw_p95": raw_p95_speedup,
                "plain_raw_p95_over_hyper_cagg_p95": cagg_p95_speedup,
            },
        }
    finally:
        await conn.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL", DEFAULT_DSN))
    parser.add_argument("--agents", type=int, default=250)
    parser.add_argument("--days", type=int, default=180)
    parser.add_argument("--tx-per-agent-day", type=int, default=20)
    parser.add_argument("--window-days", type=int, default=30)
    parser.add_argument("--agent-index", type=int, default=123)
    parser.add_argument("--iterations", type=int, default=80)
    parser.add_argument("--skip-setup", action="store_true")
    args = parser.parse_args()
    from datetime import timedelta

    args.window_days_delta = timedelta(days=args.window_days)
    return args


def main() -> None:
    result = asyncio.run(_run(parse_args()))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
