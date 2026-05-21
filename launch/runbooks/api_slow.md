# Runbook — API p95 > 500ms

**Severity:** Ticket.
**Trigger:** `ApiP95LatencyHigh`.

## What's happening

The read API is slow. Users feel this; the cluster does not.

## Triage

```bash
# 1. Slowest endpoints:
curl -s http://api:9090/metrics | grep -E 'request_seconds_count|sum' |
    grep -v "#" | sort

# 2. DB query latencies:
psql "$DATABASE_URL" -c "
  SELECT query, mean_exec_time, calls
  FROM pg_stat_statements
  ORDER BY mean_exec_time DESC LIMIT 10;"
```

## Decision tree

- **One endpoint is slow:** investigate that handler.
- **All slow:** DB-wide — VACUUM, ANALYZE, refresh continuous aggregates.
