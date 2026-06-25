"""
audit/load_tests/db_stress.py — TimescaleDB stress at 50M behavioral
data points.

Acceptance:
  * Insert 50M behavioral data points (transactions / score-history rows)
  * Sustained insert rate >= 10K rows/sec (= 5000s for 50M)
  * p95 read latency on agent-by-time queries < 100ms after the load

The harness inserts in batched COPY operations into the hypertable, then
runs a representative read query mix and reports timings.

HONEST EXECUTION
----------------
This harness is the load runner — it talks to a live TimescaleDB via
$DATABASE_URL. The audit operator runs:

    DATABASE_URL=postgres://phylanx:...@db/phylanx \\
        python audit/load_tests/db_stress.py --rows 50_000_000

For a quick sanity slice (local dev / CI), --rows 100_000 validates the
harness itself and the schema migrations:

    DATABASE_URL=postgres://localhost/phylanx \\
        python audit/load_tests/db_stress.py --rows 100_000

The smoke run extrapolates: if 100K rows insert at 12K rows/s on local
hardware, 50M rows at the same rate take ~70 minutes — well within the
audit window.

REQUIRED SCHEMA
---------------
The harness expects the phylanx-indexer schema from Day 17:
  * Hypertable `agent_transactions` (time-bucketed by block_time)
  * Hypertable `agent_score_history` (time-bucketed by epoch_end)
The harness creates them with `CREATE TABLE IF NOT EXISTS` so a fresh DB
works out of the box.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path


SCHEMA = """
CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS agent_transactions (
    block_time      TIMESTAMPTZ NOT NULL,
    agent_wallet    TEXT        NOT NULL,
    signature       TEXT        NOT NULL,
    program_id      TEXT        NOT NULL,
    amount_lamports BIGINT      NOT NULL,
    instruction_idx INT         NOT NULL
);
SELECT create_hypertable(
    'agent_transactions', 'block_time',
    if_not_exists => TRUE, chunk_time_interval => INTERVAL '1 day'
);
CREATE INDEX IF NOT EXISTS ix_agent_tx_wallet_time
    ON agent_transactions (agent_wallet, block_time DESC);

CREATE TABLE IF NOT EXISTS agent_score_history (
    epoch_end       TIMESTAMPTZ NOT NULL,
    agent_wallet    TEXT        NOT NULL,
    epoch           BIGINT      NOT NULL,
    score           SMALLINT    NOT NULL,
    alert_tier      SMALLINT    NOT NULL,
    flags           INTEGER     NOT NULL,
    immediate_red   BOOLEAN     NOT NULL
);
SELECT create_hypertable(
    'agent_score_history', 'epoch_end',
    if_not_exists => TRUE, chunk_time_interval => INTERVAL '7 days'
);
"""


def setup(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(SCHEMA)
    conn.commit()


def insert_batch(conn, rows) -> None:
    """COPY-insert a batch. The fastest path for TimescaleDB bulk load."""
    import io
    buf = io.StringIO()
    for row in rows:
        buf.write("\t".join(str(c) for c in row) + "\n")
    buf.seek(0)
    with conn.cursor() as cur:
        cur.copy_expert(
            "COPY agent_transactions "
            "(block_time, agent_wallet, signature, program_id, "
            "amount_lamports, instruction_idx) FROM STDIN",
            buf,
        )
    conn.commit()


def gen_row(epoch_start_unix: int, i: int) -> tuple:
    from datetime import datetime, timezone, timedelta
    block_time = (datetime.fromtimestamp(epoch_start_unix, tz=timezone.utc)
                  + timedelta(seconds=i % 86400))
    return (
        block_time.isoformat(),
        f"agent{i % 1000:04d}{'x'*36}"[:44],
        f"sig{i:020d}",
        "11111111111111111111111111111112",   # SystemProgram
        random.randint(1000, 1_000_000_000),
        i % 10,
    )


def run_insert(conn, total_rows: int, batch_size: int = 10_000) -> dict:
    """Insert `total_rows` rows in batches; measure throughput."""
    epoch_start = int(time.time()) - 86400 * 30
    started = time.perf_counter()
    inserted = 0
    while inserted < total_rows:
        batch = [
            gen_row(epoch_start, inserted + k)
            for k in range(min(batch_size, total_rows - inserted))
        ]
        insert_batch(conn, batch)
        inserted += len(batch)
        if inserted % 100_000 == 0:
            rate = inserted / (time.perf_counter() - started)
            print(f"  [insert] {inserted:>10d} rows  ({rate:.0f} rows/sec)")
    elapsed = time.perf_counter() - started
    return {
        "rows_inserted": inserted,
        "elapsed_s":     elapsed,
        "throughput":    inserted / elapsed,
    }


def run_reads(conn, num_queries: int = 1000) -> dict:
    """Representative read mix — wallet+time-range queries."""
    latencies = []
    for _ in range(num_queries):
        wallet = f"agent{random.randint(0, 999):04d}{'x'*36}"[:44]
        started = time.perf_counter()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*), SUM(amount_lamports) "
                "FROM agent_transactions "
                "WHERE agent_wallet = %s "
                "  AND block_time > NOW() - INTERVAL '7 days'",
                (wallet,),
            )
            cur.fetchall()
        latencies.append((time.perf_counter() - started) * 1000)
    latencies.sort()
    return {
        "queries":  len(latencies),
        "p50_ms":   latencies[len(latencies) // 2],
        "p95_ms":   latencies[int(0.95 * len(latencies))],
        "p99_ms":   latencies[int(0.99 * len(latencies))],
        "max_ms":   latencies[-1],
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rows", type=int, default=100_000,
                   help="rows to insert (default 100K smoke; audit run = 50M)")
    p.add_argument("--report",
                   default="audit/reports/db_stress.json")
    args = p.parse_args(argv)

    try:
        import psycopg2
    except ImportError:
        print("❌ psycopg2 not installed — pip install psycopg2-binary")
        return 2

    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print("❌ DATABASE_URL not set")
        return 2

    conn = psycopg2.connect(db_url)
    setup(conn)
    insert_stats = run_insert(conn, args.rows)
    read_stats = run_reads(conn)
    conn.close()

    result = {"insert": insert_stats, "read": read_stats, "rows": args.rows}
    print(json.dumps(result, indent=2))
    out = Path(args.report)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))

    # ── Acceptance ──────────────────────────────────────────────────────────
    failed = False
    if insert_stats["throughput"] < 10_000:
        print(f"❌ insert throughput {insert_stats['throughput']:.0f} "
              f"rows/sec under 10K target")
        failed = True
    if read_stats["p95_ms"] > 100:
        print(f"❌ read p95 {read_stats['p95_ms']:.1f}ms exceeds 100ms")
        failed = True
    if failed:
        return 1
    print("✅ DB STRESS CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
