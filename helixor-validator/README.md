# helixor-validation — Day 14

> **48h continuous devnet validation.**
>
> 5 agents with formally-defined behaviour profiles, automated injection of
> mid-window transactions, periodic snapshots, machine-checkable PASS/FAIL,
> and an HTML report you can hand to a partner or investor.

---

## Day 14 Status

| Item | Status |
|------|--------|
| 5 distinct profiles (stable_a, stable_b, degrading, recovering, volatile) | ✅ |
| Each profile has a deterministic `successRateAt(hours)` function | ✅ |
| Each profile has machine-checkable acceptance criteria | ✅ |
| Pre-history seeding (30 days of baseline behaviour before t=0) | ✅ |
| Mid-validation transaction injection (every 30min) | ✅ |
| Automatic baseline + score recompute on every tick | ✅ |
| Automatic on-chain epoch submission on every tick | ✅ |
| Score snapshot persistence (every 30min for all 5 agents) | ✅ |
| Crash-resumable (state.json on disk) | ✅ |
| PASS/FAIL verdict per agent with detailed reasons | ✅ |
| Mid-window checkpoint validation (degrading / recovering profiles) | ✅ |
| HTML report with inline SVG timelines, verdict banner, epoch log | ✅ |
| Mainnet refusal (env-time validation) | ✅ |
| GitHub Actions workflow runs compressed validation weekly | ✅ |

---

## What got fixed vs the spec

| Spec problem | Fix |
|--------------|-----|
| Profiles are name-only | Each profile is a typed `AgentProfile` with `successRateAt(h)` function and explicit acceptance criteria |
| "Cron will handle next epoch in 24h" | Monitor script drives epoch_runner on every tick — no cron dependency, no hidden assumptions |
| No mid-test diagnostics | Every 30min: snapshot + persist; full timeline preserved on disk |
| "Scores match expected tier" is human-judged | `verify_validation.ts` computes PASS/FAIL with structured reasons + exit code |
| Volatile range "300-500 YELLOW→RED" is ambiguous | Each profile has explicit `finalScoreRange` AND `finalAlertSet` — both must match |
| No mid-validation transaction injection | `injectTransactions` runs every 30min using the profile's success-rate-at-time function |
| `register_test_agents.ts` doesn't exist | `stage_validation.ts` is the actual implementation, with deterministic per-profile seeding |
| No reset mechanism | `--fresh-start` flag clears prior validation data; idempotent re-staging always creates a new runId |
| No epoch latency tracking | `state.epochs` records every epoch run with exit code + duration; report shows p50/p95/max |
| No final report | `build_report.ts` produces single-page HTML with inline SVG timelines, verdict banner, epoch log |

---

## Profile definitions

| Profile | Pre-history | Trajectory | Expected final |
|---------|-------------|------------|----------------|
| **stable_a** | 30d @ 95% | 95% steady | score 700-1000, GREEN, no anomaly |
| **stable_b** | 30d @ 92% | 92% steady | score 650-1000, GREEN, no anomaly |
| **degrading** | 30d @ 95% | 95% → 70% linear | score 350-600, YELLOW or RED, **anomaly=true** |
| **recovering** | 30d @ 60% | 60% → 92% linear | score 450-700, YELLOW or GREEN, no anomaly |
| **volatile** | 30d @ 75% | 75% ± 15% sine, 12h period | score 300-600, YELLOW or RED |

The `degrading` and `recovering` profiles have mid-window checkpoints to
verify the trajectory (not just the endpoint).

---

## Quick Start

```bash
cp .env.example .env
# Edit to point at devnet endpoints

npm install

# 1. Stage (creates 5 agents, seeds pre-history, runs initial baseline+score)
npm run stage
# → prints runId, e.g. "abc12345"

# 2. Start the long-running monitor (run in tmux/screen for 48h)
npm run monitor
# → on each 30min tick: inject txs → recompute → epoch → snapshot
# → loops until duration reached, then exits

# 3. Verify (any time during or after monitoring)
npm run verify
# → exit 0 if all 5 PASS, exit 1 otherwise

# 4. Build the HTML report
npm run report
# → reports/run_<runId>/report.html

# 5. Clean up
npm run teardown
```

For a one-shot CI-friendly compressed run (2h instead of 48h):

```bash
HELIXOR_VALIDATION_INTERVAL_MS=600000 npm run run-full
# 12 ticks × 10min = 2h
```

---

## Architecture

```
                  ┌──────────────────────────────────────┐
                  │  stage_validation.ts                 │
                  │  - generate 5 agents (Keypair)       │
                  │  - seed pre-history per profile      │
                  │  - run initial baseline + score      │
                  │  - persist state.json                │
                  └────────────┬─────────────────────────┘
                               │ runId
                               ▼
                  ┌──────────────────────────────────────┐
                  │  monitor_validation.ts (LONG-RUNNING)│
                  │  every 30min:                         │
                  │   1. inject txs per profile           │
                  │   2. recompute baseline + score       │
                  │   3. run epoch_runner                 │
                  │   4. snapshot all 5 agents            │
                  │   5. persist state.json               │
                  └────────────┬─────────────────────────┘
                               │ accumulated state
                               ▼
                  ┌──────────────────────────────────────┐
                  │  verify_validation.ts                │
                  │  for each agent:                     │
                  │   - check finalScoreRange            │
                  │   - check finalAlertSet              │
                  │   - check finalAnomalyFlag           │
                  │   - check is_fresh                   │
                  │   - check mid-window checkpoints     │
                  │  exit 0 if all pass                  │
                  └────────────┬─────────────────────────┘
                               │
                               ▼
                  ┌──────────────────────────────────────┐
                  │  build_report.ts                     │
                  │  → HTML with:                        │
                  │    - verdict banner                  │
                  │    - per-agent SVG timelines         │
                  │    - epoch log + p50/p95/max         │
                  │    - per-agent reasons               │
                  └──────────────────────────────────────┘
```

---

## File Structure

```
helixor-validation/
├── profiles/
│   └── profiles.ts                    5 typed AgentProfile definitions
├── helpers/
│   ├── env.ts                         strict env + mainnet refusal
│   ├── state.ts                       ValidationState + JSON persistence
│   ├── db.ts                          seed pre-history, inject mid-validation, teardown
│   └── pipeline.ts                    drive Day 5/6/7 CLIs via subprocess
├── scripts/
│   ├── stage_validation.ts            create + seed + initial score
│   ├── monitor_validation.ts          long-running tick loop
│   ├── verify_validation.ts           PASS/FAIL with exit code
│   ├── build_report.ts                HTML report with SVG timelines
│   ├── teardown_validation.ts         remove all validation data
│   └── run_full_validation.ts         single-command flow (CI)
├── .github/workflows/
│   └── validation_short.yml           weekly compressed validation
├── package.json
├── tsconfig.json
├── .env.example
└── README.md
```

---

## When something fails

1. Open `reports/run_<runId>/report.html`
2. The verdict banner says which profile(s) failed
3. Each agent card shows the failing reasons inline
4. The timeline SVG shows where the score went wrong
5. The epoch log shows whether on-chain submission was the bottleneck

If the failure is a real bug → file a regression test in `helixor-integration/tests/integration/regressions/` (Day 13's structure) before fixing.

If the failure is the validation itself (profile too aggressive, threshold too tight) → tune the profile in `profiles/profiles.ts` and document why in this README.

---

*Helixor MVP · Day 14 complete · Next: Day 15 — mainnet deployment with verified artifact + first paying partner.*
