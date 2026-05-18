# Day 15 TimescaleDB Latency Benchmark

Measured locally on May 19, 2026 with a temporary TimescaleDB container:

```bash
docker run -d --name helixor-timescale-bench \
  -e POSTGRES_PASSWORD=postgres \
  -p 55432:5432 \
  timescale/timescaledb:latest-pg16

DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:55432/postgres \
  PYTHONPATH=. ./.venv/bin/python -m scripts.benchmark_timescale_latency \
  --agents 250 --days 180 --tx-per-agent-day 20 --iterations 80
```

Dataset:

- 250 agents
- 180 days
- 20 transactions per agent per day
- 900,000 rows in the plain table
- 900,000 rows in the hypertable
- Measured wallet: `agent_00123`

## 30-Day Window

| Scenario | Rows | p50 ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: | ---: |
| Plain Postgres raw daily aggregate | 31 | 0.647 | 0.882 | 0.917 |
| Timescale hypertable raw daily aggregate | 31 | 1.782 | 2.031 | 2.322 |
| Timescale continuous aggregate | 30 | 0.455 | 0.697 | 1.293 |

Measured p95 speedup:

- Plain raw vs Timescale raw: `0.43x`
- Plain raw vs Timescale continuous aggregate: `1.27x`

## 90-Day Window

Command:

```bash
DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:55432/postgres \
  PYTHONPATH=. ./.venv/bin/python -m scripts.benchmark_timescale_latency \
  --agents 250 --days 180 --tx-per-agent-day 20 --iterations 80 \
  --window-days 90 --skip-setup
```

| Scenario | Rows | p50 ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: | ---: |
| Plain Postgres raw daily aggregate | 91 | 1.003 | 1.898 | 3.459 |
| Timescale hypertable raw daily aggregate | 91 | 3.130 | 4.795 | 5.172 |
| Timescale continuous aggregate | 90 | 0.765 | 1.302 | 1.624 |

Measured p95 speedup:

- Plain raw vs Timescale raw: `0.40x`
- Plain raw vs Timescale continuous aggregate: `1.46x`

## Interpretation

The honest result: a hypertable is not automatically faster than a well-indexed
plain Postgres table for one-agent raw window scans at this local 900k-row
scale. The production win is the continuous aggregate: the baseline daily
series becomes a read of precomputed per-day rows instead of an aggregate over
raw transaction rows.

This upgrades the Day 15 claim from structural proof to benchmarked proof for
the part Helixor actually depends on: daily feature/baseline rollups.
