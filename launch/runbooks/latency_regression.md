# Runbook — Epoch latency regression

**Severity:** Ticket (not page).
**Trigger:** `EpochLatencyHigh` — p95 epoch latency > 60s for 10 min.

## What's happening

A normal cluster epoch takes ~6 seconds; p95 > 60s is a 10x regression.
The 24-hour protocol budget is not at risk (still > 1400x margin), but
the regression hides something worth understanding.

Most likely causes:
1. **Detector code regression** — a new detector is O(n^2) in agents.
2. **Database slowness** — TimescaleDB query degradation (compaction,
   bloat).
3. **Cross-region network** — a peer is reachable but slow.

## Triage

Read recent deploys. Compare per-stage timing in the structured logs:

```bash
journalctl -u phylanx-oracle-0 -n 1000 | grep "epoch .* pipeline" |
    awk '{print $0}' | tail -20
```

Each line carries `elapsed_seconds` for the whole pipeline; instrument
the sub-stages if needed.

## Decision tree

- **Coincides with a deploy:** rollback, file performance regression.
- **Coincides with a DB event (long-running query):** investigate the DB.
- **No obvious cause:** profile one full epoch in `py-spy`.

No on-call wake unless latency crosses 600s (10x another 10x).
