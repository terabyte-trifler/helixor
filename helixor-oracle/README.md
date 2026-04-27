# Helixor Oracle

> This folder now includes the Day 7 epoch runner and Day 8 REST API in
> addition to the Day 6 scoring engine below. For the latest project-wide
> status and run instructions, start with the top-level `README.md`.

> **Scoring engine.** Three signals → one number between 0 and 1000.
> Stable agents score ≥ 700 (GREEN). Failing agents score < 400 (RED).
> Score change capped at 200 points per epoch (guard rail).

Builds on Day 5's baseline engine. Day 6 adds the `engine.py` scorer,
`window.py` for current-window stats, score persistence, and the orchestrator
that wires everything together for Day 7's on-chain CPI.

---

## Day 6 Status

| Item | Status |
|------|--------|
| Pure scoring engine (no I/O) | ✅ |
| 7-day window stats computation | ✅ |
| Versioned `ScoringWeights` (default scheme + A/B-able) | ✅ |
| Three components: success rate (0-500), consistency (0-300), stability (0-200) | ✅ |
| Guard rail: max 200pt change per epoch | ✅ |
| Anomaly flag: relative drop OR absolute floor | ✅ |
| Algorithm version compatibility check | ✅ |
| Score persistence + immutable history | ✅ |
| Day 7 hooks: `find_unsynced_scores` + `mark_score_onchain` | ✅ |
| 40+ unit tests + 11 integration tests | ✅ |
| Manual CLI: `python -m scripts.compute_score <wallet>` | ✅ |

---

## The Scoring Formula

```
total_score (0-1000) = success_rate_score (0-500)
                     + consistency_score  (0-300)
                     + stability_score    (0-200)

# Then guard-rail clamp: |new - previous| ≤ 200
```

### Component 1 — Success Rate (50% weight, 0-500 pts)

**Absolute** thresholds, NOT relative to baseline:

| Window success rate | Points |
|---------------------|--------|
| ≥ 97% | 500 |
| 80% – 97% | linear 0–500 |
| ≤ 80% | 0 |

Why absolute, not relative? An agent with a 50% baseline AND 50% window
success rate would otherwise score full points — the spec's design.
That's wrong. 50% success is not trustworthy regardless of consistency.

### Component 2 — Consistency (30% weight, 0-300 pts)

`ratio = window_daily_tx / baseline_median_daily_tx`

| Ratio | Points |
|-------|--------|
| 0.5 – 1.5 | 300 (in band — normal tempo) |
| 0.3–0.5 or 1.5–2.0 | 150 (partial) |
| < 0.3 or > 2.0 | 0 (suspiciously off) |

### Component 3 — Stability (20% weight, 0-200 pts)

`ratio = window_volatility_mad / baseline_volatility_mad`

| Ratio | Points |
|-------|--------|
| ≤ 1.5 | 200 (volatility unchanged) |
| 1.5 – 3.0 | 100 (somewhat elevated) |
| > 3.0 | 0 (suspiciously volatile) |

### Guard rail

`|new_score - previous_score| ≤ MAX_DELTA (default 200)`

If a score would jump from 500 to 1000 in one epoch, it's clamped to 700.
Both `raw_score` (pre-clamp) and `score` (post-clamp) are stored — so the
breakdown shows what the engine wanted to do AND what actually happened.

### Anomaly flag

Fires when EITHER:
- Window success rate dropped > 15 pp below baseline, OR
- Window success rate < 75% absolute (regardless of baseline)

This separates "agent is normally good but had a bad week" (no anomaly,
score adjusts) from "agent is structurally failing" (anomaly fires, downstream
consumers should react).

---

## What Got Fixed vs the Spec

| Bug in spec | Fix |
|-------------|-----|
| `baseline.get("sol_volatility")` — wrong key name (Day 5 stores `sol_volatility_mad`) | Type-safe `BaselineResult` consumption |
| Success rate scoring is **relative to baseline** | Absolute brackets: 80% / 97% pin points |
| Spec uses `statistics.stdev` for window volatility | Matches Day 5: MAD throughout |
| `current_daily = window.tx_count_7d / 7.0` | Divide by **elapsed** days when agent < 7 days old |
| No baseline algo version check | Refuses to score against unknown versions |
| Hardcoded weights — no A/B testability | Versioned `ScoringWeights` dataclass |
| Anomaly flag only relative — fails for low-baseline agents | Adds absolute floor at 75% |
| Spec only computes; doesn't persist | `agent_scores` + `agent_score_history` |
| No way to find unsynced scores for Day 7 | `find_unsynced_scores` + `mark_score_onchain` |
| Boolean outputs — score and anomaly conflated | Separate fields, separate consumer policies |
| No CLI verification | `compute_score.py` with `--dry-run` |
| Spec returns `dict` for breakdown | Frozen `ScoreBreakdown` dataclass — immutable |

---

## Quick Start

```bash
# Build on Day 5
bash scripts/setup.sh
```

The script:
1. Applies migration 0003 (score tables)
2. Runs unit tests (40+ pure-math tests)
3. Runs integration tests (11 with PG)
4. Seeds 150 transactions + computes baseline + computes score
5. Prints the stored score row

---

## Manual Verification

```bash
# 1. Seed test agent (from Day 5)
python -m scripts.seed_baseline_test_data \
    --wallet TESTAGENT12345... --tx-count 150 --active-days 25

# 2. Compute baseline (from Day 5)
python -m scripts.compute_baseline TESTAGENT12345... --store

# 3. Compute score (Day 6)
python -m scripts.compute_score TESTAGENT12345...

# Or dry-run: compute without storing
python -m scripts.compute_score TESTAGENT12345... --dry-run
```

Expected output:

```json
{
  "ok": true,
  "stored": true,
  "agent": "TESTAGENT12345...",
  "result": {
    "score": 850,
    "alert": "GREEN",
    "anomaly_flag": false,
    "breakdown": {
      "success_rate_score": 500,
      "consistency_score": 300,
      "stability_score": 50,
      "raw_score": 850,
      "guard_rail_applied": false,
      "consistency_ratio": 1.05,
      "stability_ratio": 2.1
    },
    "window_success_rate": 0.97,
    "window_tx_count": 50,
    "window_sol_volatility": 2100000,
    "baseline_hash": "a3f8b2c1...",
    "baseline_algo_version": 1,
    "scoring_algo_version": 1,
    "weights_version": 1
  }
}
```

---

## Programmatic API

```python
from indexer import db
from scoring import score_engine

await db.init_pool()
pool = await db.get_pool()

async with pool.acquire() as conn:
    result = await score_engine.score_one(conn, agent_wallet)

    if result is None:
        print("Insufficient data — agent has no baseline or empty window")
    else:
        print(f"Score {result.score} ({result.alert})")
        if result.anomaly_flag:
            print("Anomaly detected — investigate")
```

---

## File Structure (additions to Day 5)

```
helixor-oracle/
├── scoring/
│   ├── window.py                     ← 7-day window stats (NEW)
│   ├── engine.py                     ← pure scoring math (NEW)
│   ├── score_repo.py                 ← async DB layer (NEW)
│   └── score_engine.py               ← orchestrator (NEW)
│
├── db/migrations/
│   └── 0003_scores.sql               ← agent_scores + history (NEW)
│
├── tests/scoring/
│   ├── test_engine.py                ← 40+ unit tests (NEW)
│   ├── test_window.py                ← window stat tests (NEW)
│   └── test_score_engine.py          ← 11 integration tests (NEW)
│
└── scripts/
    └── compute_score.py              ← Day 6 CLI (NEW)
```

---

## Test Coverage Highlights

```
Group 1: Stable agent → GREEN
  ✓ Perfect agent scores 1000
  ✓ Baseline-matched window → ≥700

Group 2: Failing agent → RED
  ✓ 30% success rate → 0 success-rate points
  ✓ Failing+volatile+inconsistent → score 0, RED

Group 3: Linear interpolation 80%-97%
  ✓ Midpoint (88.5%) → ~250 pts
  ✓ Quarter (84.25%) → ~125 pts

Group 4-5: Consistency + Stability brackets
  ✓ All in/out-of-band cases verified
  ✓ Zero-baseline edge cases (no division by zero)

Group 6: Guard rail
  ✓ First score has no clamp
  ✓ Big upward + downward jumps clamped
  ✓ Custom max_delta respected

Group 7: Anomaly flag
  ✓ Relative drop fires
  ✓ Absolute floor fires (catches structurally-bad agents)
  ✓ Both can fire simultaneously

Group 8-11: Alert tiers, algo version, weights validation, output shape
```

---

## Notes for Day 7

`agent_scores.written_onchain_at` is `NULL` immediately after scoring.
Day 7's `epoch_runner` reads `find_unsynced_scores`, calls `update_score`
on-chain via CPI, and on success calls `mark_score_onchain(agent, tx_sig)`
which sets `written_onchain_at` and annotates the latest history row.

The scoring engine NEVER writes on-chain — it only computes + persists locally.
Day 7's runner is the only thing that talks to Solana.

---

*Helixor Oracle · Day 6 complete · Next: Day 7 update_score on-chain*
