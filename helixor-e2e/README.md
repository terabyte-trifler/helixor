# helixor-e2e — End-to-end loop validation

> **The single test that proves the whole MVP works.**
>
> Registers a synthetic agent, injects 100 transactions, drives baselines
> through scoring through on-chain submission, and asserts that the SDK
> reads the same score back. Three personas verified in parallel:
> stable (GREEN), failing (RED + anomaly), provisional.

---

## What this validates

```
[register agent in DB]
       ↓
[seed 100 txs into agent_transactions]
       ↓
[trigger baseline computation]    ← Day 5
       ↓
[trigger scoring]                  ← Day 6
       ↓
[trigger epoch_runner]             ← Day 7
       ↓
[verify TrustCertificate on-chain] ← Day 7
       ↓
[verify API returns same score]    ← Day 8
       ↓
[verify requireMinScore policies]  ← Day 8 SDK
```

The whole loop, end-to-end, in one `npm run test:loop` invocation. ~3 minutes.

---

## Why DB-side seeding (not real Helius webhooks)

CI can't poll Helius for real transactions to arrive. We inject directly
into `agent_transactions` so the loop can be exercised in seconds. Webhook
ingestion itself is tested separately in Day 4's `test_webhook.py`.

The pieces that ARE exercised end-to-end here:
- baseline_engine + signals (Day 5)
- scoring_engine (Day 6)
- epoch_runner + on-chain submission (Day 7)
- API service + cache (Day 8)
- SDK client behavior (Day 8)

The pieces that are NOT exercised (tested separately):
- Helius webhook receiver (Day 4 `test_webhook.py`)
- elizaOS plugin (Day 9 `tests/`)
- Anchor program logic (Day 7 `update_score.ts` integration tests)

---

## Quick Start

```bash
# Once you have the full stack running (Day 7 deployed, Day 8 API serving):
cp .env.example .env
# Edit .env to point at your devnet endpoints
npm install
npm run setup        # ~10s — verifies env, prints status
npm run test:smoke   # ~3s — fast pre-flight checks
npm run test:loop    # ~3min — the real loop
```

Or all at once: `npm run test`.

---

## Mainnet refusal

`tests/env.ts` refuses to run if any endpoint contains "mainnet" or matches
known mainnet host patterns. There is no path where these tests submit a
transaction to mainnet.

If you ever need to validate mainnet, write a separate read-only suite that
only calls `getScore` against existing data. NEVER run this seed-then-score
suite anywhere except devnet/localnet.

---

## What the test asserts

### Stable agent (90% success rate)
- API returns `source: "live"` and `is_fresh: true`
- Score ≥ 700, alert = GREEN, anomaly_flag = false
- `requireMinScore(700)` passes
- On-chain TrustCertificate exists and matches API to the byte
- Breakdown components sum to raw_score

### Failing agent (30% success rate)
- Score < 400, alert = RED
- anomaly_flag = true (absolute floor 75% triggered)
- `requireMinScore(600)` throws ScoreTooLowError or AnomalyDetectedError
- Error carries the actual score
- On-chain cert agrees: score < 400, RED, anomaly = true

### Provisional agent (registered, no transactions)
- API returns `source: "provisional"`
- Score = 500, alert = YELLOW
- is_fresh = false
- `requireMinScore` throws ProvisionalScoreError even with allowStale + allowAnomaly
  (provisional is **never** acceptable for financial actions)
- No on-chain cert (provisional means we didn't score yet)

### Loop integrity
- API and on-chain scores agree to the byte
- Scoring algorithm version + weights version are consistent across agents

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `Refusing to run E2E... mainnet` | Wrong RPC URL | Edit `.env` to use devnet |
| `Program ... not found on RPC` | Program not deployed | `cd helixor-programs && anchor deploy --provider.cluster devnet` |
| `compute stable: <stderr>` shows `IncompatibleAlgoVersion` | Day 5 baseline algo bumped | Re-seed agents (teardown + run again) |
| Cert poll times out at 90s | epoch_runner couldn't submit | Check oracle wallet balance + RPC; check `epoch_runner` logs |
| Smoke test fails on `/docs` | API not running | `cd helixor-oracle && uvicorn api.main:app --port 8001` |
| `OracleConfig not initialized` from epoch_runner | Day 7 setup not run | `cd helixor-programs && ts-node scripts/initialize_oracle_config.ts` |

---

## Manual demo

If you want to demo the loop without running the test suite:

```bash
npm run seed
# → seeds 3 agents, prints their pubkeys + curl commands

# Then in another terminal:
curl http://localhost:8001/score/<STABLE_PUBKEY>
curl http://localhost:8001/score/<FAILING_PUBKEY>
curl http://localhost:8001/score/<PROVISIONAL_PUBKEY>

npm run teardown
# → cleans up
```

---

## File Structure

```
helixor-e2e/
├── tests/
│   ├── env.ts               ← strict env validation + mainnet refusal
│   ├── poll.ts              ← pollUntil with structured timeouts
│   ├── fixtures.ts          ← deterministic agent + tx seeding
│   ├── pipeline.ts          ← drives baseline_engine + epoch_runner via subprocess
│   ├── onchain.ts           ← reads TrustCertificate PDA from chain
│   ├── smoke.test.ts        ← 8 fast pre-flight checks
│   ├── full_loop.test.ts    ← THE TEST — 18 assertions across 3 personas
│   └── consumer_cpi.test.ts ← optional CPI integration test
├── scripts/
│   ├── setup.ts             ← env + connectivity verification
│   ├── seed_loop_state.ts   ← manual seed for demos
│   └── teardown.ts          ← clean up test agents
├── package.json
├── tsconfig.json
├── vitest.config.ts
├── .env.example
└── README.md
```

---

*Helixor MVP · Day 10 complete · The full loop runs end-to-end in 3 minutes.*
*Next: Day 11 — keep one real agent continuously scored on devnet.*
