# Helixor Oracle — Day 5

> **Baseline engine.** From the `agent_transactions` table, compute three
> signals over a 30-day window: success rate, median daily tx count, and
> SOL volatility (MAD). Persist them. Hash them deterministically.

This builds on Day 4's `helixor-oracle/` codebase. Day 5 adds the `scoring/`
package, two new database tables, and one new background service.

---

## Day 5 Status

| Item | Status |
|------|--------|
| Three pure signal computations (success_rate, median_daily_tx, sol_volatility_mad) | ✅ |
| Tz-aware UTC throughout (no naive `datetime.utcnow()`) | ✅ |
| MAD instead of stdev for outlier robustness | ✅ |
| Async asyncpg (consistent with Day 4 stack) | ✅ |
| Deterministic SHA-256 baseline hash | ✅ |
| `agent_baselines` (current) + `agent_baseline_history` (audit) tables | ✅ |
| Algorithm version tag (bump-on-change) | ✅ |
| Cache with `valid_until` TTL | ✅ |
| `baseline_scheduler` service for periodic recompute | ✅ |
| CLI: `compute_baseline.py` + `seed_baseline_test_data.py` | ✅ |
| 18 pure unit tests + 9 integration tests | ✅ |

---

## Architecture

```
                          ┌──────────────────────┐
                          │  agent_transactions  │  (Day 4 — 100s/day/agent)
                          └──────────┬───────────┘
                                     │  fetch window
                                     ▼
              ┌──────────────────────────────────────────┐
              │  scoring/signals.py  (pure functions)    │
              │                                          │
              │  • success_rate     (binomial)           │
              │  • median_daily_tx  (active days only)   │
              │  • sol_volatility   (MAD, robust)        │
              │  • baseline_hash    (canonical SHA-256)  │
              └──────────────────┬───────────────────────┘
                                 │  BaselineResult
                                 ▼
              ┌──────────────────────────────────────────┐
              │  scoring/baseline_engine.py              │
              │                                          │
              │  compute_and_store(conn, agent)          │
              │  get_or_compute(conn, agent)             │
              │  batch_recompute(conn, [agents])         │
              └──────────────────┬───────────────────────┘
                                 │
                                 ▼
              ┌────────────────────────┬─────────────────┐
              │  agent_baselines       │ agent_baseline_ │
              │  (one row per agent)   │ history (audit) │
              └────────────────────────┴─────────────────┘
                                 ▲
                                 │  every 10 minutes
              ┌──────────────────┴───────────────────────┐
              │  scoring/scheduler.py                    │
              │  • find_agents_without_baseline()        │
              │  • find_stale_baselines()                │
              │  • batch_recompute()                     │
              └──────────────────────────────────────────┘
```

---

## The Three Signals

| Signal | Type | Why this exact formula |
|--------|------|------------------------|
| `success_rate` | float (6 dp) | Binomial proportion. Most direct measure of "does the agent's strategy work?" |
| `median_daily_tx` | int | Median over **active days only**. Captures behavioral tempo without being skewed by agents that take weekends off. |
| `sol_volatility_mad` | int (lamports) | Median Absolute Deviation of daily \|sol_change\| sums. **Robust** — single outlier days can't move it the way they move stdev. |

**Why no float for SOL.** Lamports are u64 on-chain. We hold them as Python
ints (arbitrary precision) and never cast to float. Float arithmetic on
billions of lamports loses precision. Floats are forbidden in the canonical
hash.

**Why MAD instead of standard deviation.** Real on-chain agents have spike
days — airdrops, rebalancing, liquidations. Standard deviation doubles when
you double a single outlier. MAD barely moves. With MAD, one bad day doesn't
permanently mark an agent as "volatile."

**Why active days only.** An agent that runs Mon-Fri has 22 active days per
month, not 30. Padding with zeros for Sat/Sun would halve the median.
"Median daily tx count" is computed only over days the agent was actually
active.

---

## What Got Fixed vs the Spec

| Bug in spec | Fix |
|-------------|-----|
| `psycopg2.connect()` sync calls in async stack | Reuses Day 4's asyncpg pool |
| `datetime.utcnow()` (naive, deprecated) | `datetime.now(tz=timezone.utc)` everywhere |
| `statistics.stdev` (outlier-sensitive) | MAD: `median(|x - median(x)|)` |
| Hash includes `computed_at` (non-deterministic) | Hash is over signals + algo_version only |
| Float `repr` in hash (platform-dependent) | success_rate formatted as `f"{:.6f}"` string |
| `INTERVAL '%s days'` SQL injection risk | Parameter binding via asyncpg `$N` |
| Returns None silently when insufficient data | Raises `InsufficientData(observed, required)` |
| No persistence — recomputed every call | `agent_baselines` table + `valid_until` TTL |
| No history — can't observe baseline drift | `agent_baseline_history` append-only |
| Hardcoded thresholds, no algo version | `ALGO_VERSION` constant + stored alongside |
| `abs(sol_change or 0)` — direction lost everywhere | abs() only for volatility; signals.py preserves sign for downstream |
| No test coverage | 18 unit + 9 integration tests |

---

## Quick Start

```bash
# Build on Day 4's installation
bash scripts/setup.sh
```

The script:
1. Boots Postgres (auto-applies migrations 0001 + 0002)
2. Installs Python deps
3. Runs unit tests (pure math — no DB needed)
4. Runs integration tests (testcontainers Postgres)
5. Seeds 100 test transactions for a synthetic agent
6. Computes the baseline and stores it
7. Prints the row from `agent_baselines`

---

## Manual Verification

The Day 5 "done when" check, exactly as the spec asks:

```bash
# Seed 100 transactions for a test agent
python -m scripts.seed_baseline_test_data \
    --wallet TESTAGENTwallet1234567890123456789012345 \
    --tx-count 100 \
    --active-days 10 \
    --success-rate 0.95

# Compute the baseline (dry run — doesn't store)
python -m scripts.compute_baseline TESTAGENTwallet1234567890123456789012345

# Compute and store
python -m scripts.compute_baseline TESTAGENTwallet1234567890123456789012345 --store
```

Expected output:

```json
{
  "ok": true,
  "stored": true,
  "agent": "TESTAGENTwallet1234567890123456789012345",
  "result": {
    "success_rate": 0.95,
    "median_daily_tx": 10,
    "sol_volatility_mad": 380123,
    "tx_count": 100,
    "active_days": 10,
    "window_start": "2026-03-26T...",
    "window_end": "2026-04-25T...",
    "window_days": 30,
    "baseline_hash": "a3f8b2c1...",
    "algo_version": 1
  }
}
```

If you run it twice, you get the same `baseline_hash` both times. If you
change a single transaction, the hash changes. That determinism is the
contract: scoring (Day 6) and on-chain commitment (Day 7) both depend on it.

---

## Programmatic API

```python
from indexer import db
from scoring import baseline_engine

await db.init_pool()
pool = await db.get_pool()

async with pool.acquire() as conn:
    # Cached read — recomputes if expired
    result = await baseline_engine.get_or_compute(conn, agent_wallet)

    if result is None:
        print("Insufficient data yet")
    else:
        print(f"Score this agent against baseline {result.baseline_hash}")
```

---

## File Structure (additions to Day 4)

```
helixor-oracle/
├── scoring/                              ← NEW package
│   ├── __init__.py
│   ├── signals.py                        ← pure math, fully tested
│   ├── repo.py                           ← async DB layer
│   ├── baseline_engine.py                ← orchestrator
│   └── scheduler.py                      ← periodic recompute service
│
├── db/migrations/
│   └── 0002_baselines.sql                ← agent_baselines + history
│
├── tests/scoring/
│   ├── test_signals.py                   ← 18 unit tests, pure
│   └── test_baseline_engine.py           ← 9 integration tests
│
└── scripts/
    ├── compute_baseline.py               ← Day 5 CLI verification
    └── seed_baseline_test_data.py        ← test data generator
```

`docker-compose.yml` adds one new service: `baseline_scheduler`.

---

## Operational Notes

**When does a baseline get recomputed?** A baseline is fresh for
`DEFAULT_BASELINE_TTL_SECONDS` (24 hours). After that, the scheduler picks
it up on its next 10-minute pass. If you need to force a recompute, run:

```sql
UPDATE agent_baselines SET valid_until = NOW() WHERE agent_wallet = '...';
```

**When does a new agent get its first baseline?** As soon as it has 50+
transactions across at least 3 active days. The scheduler runs
`find_agents_without_baseline` and tries to compute. If insufficient, it
will retry on the next pass.

**What if the algorithm changes?** Bump `ALGO_VERSION` in `scoring/signals.py`.
Every new baseline will store the new version, and consumers (Day 6 scoring)
can detect the change and re-score accordingly. Old baselines remain
inspectable in `agent_baseline_history`.

**Algorithm changes are versioned, not retroactive.** We never silently
re-interpret old baselines under new rules.

---

*Helixor Oracle · Day 5 complete · Next: Day 6 scoring engine*
