# Helixor — Day 7

> **`update_score` on-chain.** The oracle Python process computes scores
> (Day 6) and writes them to `TrustCertificate` PDAs every 24h via signed
> CPI. `get_health()` returns Live scores instead of Provisional.

Day 7 spans **two repos**:
- `helixor-programs/` — Anchor program with new `update_score` instruction
- `helixor-oracle/` — Python epoch runner that submits to chain

---

## Day 7 Status

| Item | Status |
|------|--------|
| `update_score` instruction with 7 validations | ✅ |
| `OracleConfig` PDA — singleton with admin/oracle/pause/epoch | ✅ |
| `initialize_oracle_config` — deploy bootstrap | ✅ |
| `update_oracle_config` — admin-only key rotation + pause | ✅ |
| 23h cooldown + 200pt guard rail enforced on-chain | ✅ |
| Score range + success_rate range validation | ✅ |
| Pause halts all writes (emergency stop) | ✅ |
| Active-agent check (deactivated agents can't be scored) | ✅ |
| `baseline_hash_prefix` + algo versions stored on-chain | ✅ |
| `ScoreUpdated` event with full payload | ✅ |
| Async Python epoch runner with priority fees | ✅ |
| Per-agent retry with exponential backoff on transient errors | ✅ |
| Typed exception mapping (TooFrequent, DeltaTooLarge, etc.) | ✅ |
| `mark_score_onchain` after successful submission | ✅ |
| 18 program integration tests | ✅ |

---

## What `update_score` Does

```
oracle calls update_score(payload)
  │
  ├── 1. score ≤ 1000                 → ScoreOutOfRange
  ├── 2. success_rate ≤ 10000         → SuccessRateOutOfRange
  ├── 3. signer == oracle_config.oracle_key → UnauthorizedOracle
  ├── 4. !oracle_config.paused        → OraclePaused
  ├── 5. agent_registration.active    → AgentDeactivated
  ├── 6. (cert.updated_at == 0) OR (now - updated_at >= 23h)  → UpdateTooFrequent
  ├── 7. (cert.updated_at == 0) OR (|new - old| <= 200)        → ScoreDeltaTooLarge
  │
  ├── init or mutate TrustCertificate PDA
  ├── increment OracleConfig.epoch
  └── emit!(ScoreUpdated)
```

---

## What Got Fixed vs the Spec

| Bug in spec | Fix |
|-------------|-----|
| `init_if_needed` without explaining safety | Documented: only the authorized oracle can call this; PDAs are deterministic |
| Spec reuses `StaleCertificate` for "too soon" | New distinct `UpdateTooFrequent` error |
| Missing `agent_registration.active` check | Added — deactivated agents can't be scored |
| Missing score / success_rate range validation | Added explicit bounds checks |
| Missing pause mechanism | `OracleConfig.paused` + `update_oracle_config` admin instruction |
| Missing oracle key rotation path | `update_oracle_config` accepts new_oracle_key |
| No `OracleConfig` initialization shown | `initialize_oracle_config` ix + bootstrap script |
| No epoch counter | `OracleConfig.epoch` increments each successful update |
| No on-chain link to baseline | Added `baseline_hash_prefix` + algo versions to cert |
| Sync `psycopg2` Python | Async asyncpg consistent with Days 4-6 |
| No tx confirmation logic | Awaits confirmation with timeout |
| No retry on transient failures | Per-agent retry with exponential backoff (5s, 15s, 45s) |
| No mapping of on-chain errors → Python types | Typed exceptions (TooFrequent, DeltaTooLarge, Paused, Unauthorized) |
| `get_previous_score` decodes by raw byte offset | Documented offset (after 8-byte disc) + length-checked |
| `submit_score_update` undefined in spec | `oracle/submit.py` with full implementation |
| No priority fees | `set_compute_unit_price` for mainnet congestion handling |
| Single-agent loop, blocks for hours on 100 agents | `MAX_AGENTS_PER_PASS=100` + retry budget per agent |
| No way to mark scores synced | `mark_score_onchain` from Day 6 wired up |

---

## Quick Start

```bash
# 1. Program side (helixor-programs/)
cd helixor-programs
bash scripts/setup.sh

# 2. Copy IDL to oracle service
cp target/idl/health_oracle.json ../helixor-oracle/idl/

# 3. Oracle side (helixor-oracle/)
cd ../helixor-oracle

# Set ORACLE_KEYPAIR_PATH in .env to keys/oracle-node.json
# from the helixor-programs/keys/ directory

bash scripts/run_epoch_once.sh
```

Then on Solana Explorer, find the `TrustCertificate` PDA for your test agent
and verify the score matches what was written off-chain.

---

## OracleConfig Lifecycle

```
1. Deploy program
2. initialize_oracle_config(oracle_key, admin_key)   ← run ONCE
3. Oracle node submits scores via update_score
4. (rare) admin rotates oracle_key via update_oracle_config
5. (emergency) admin sets paused=true via update_oracle_config
   → all subsequent update_score calls revert with OraclePaused
   → off-chain Python keeps computing but doesn't submit
6. (resolution) admin sets paused=false to resume
```

Pause is the kill switch. If a critical bug is discovered in the scoring
algorithm, the admin pauses on-chain in one transaction. Off-chain scoring
continues (so engineers can investigate), but no bad scores can leak to
DeFi consumers.

---

## Test Coverage

```
Group 1: Bootstrap (3 tests)
  [1] OracleConfig fields after init
  [2] Re-init blocked (init constraint)
  [3] oracle_key == admin_key rejected

Group 2: Happy path (4 tests)
  [4] First update creates the cert with all fields
  [5] ScoreUpdated event with full payload
  [6] Alert auto-derives from score (6 score→alert mappings)
  [7] Epoch counter increments

Group 3: Authorization (2 tests)
  [8] Wrong signer → UnauthorizedOracle
  [9] Non-admin update_oracle_config → UnauthorizedAdmin

Group 4: Validation (3 tests)
  [10] score > 1000 → ScoreOutOfRange
  [11] success_rate > 10000 → SuccessRateOutOfRange
  [13] Paused oracle → OraclePaused

Group 5: Guard rails (3 tests)
  [14] Score change > 200 → ScoreDeltaTooLarge
  [16] Update within 23h → UpdateTooFrequent
  [17] First update has no cooldown

Group 6: Admin rotation (1 test)
  [18] Admin rotates oracle_key — old blocked, new succeeds
```

---

## File Structure

```
helixor-programs/
├── programs/health-oracle/src/
│   ├── lib.rs                       (5 instructions wired)
│   ├── state.rs                     (+ OracleConfig, extended TrustCertificate)
│   ├── errors.rs                    (+ Day 7 errors)
│   └── instructions/
│       ├── register_agent.rs        (Day 2 — frozen)
│       ├── get_health.rs            (Day 3 — frozen)
│       ├── update_score.rs          (Day 7 — COMPLETE)
│       ├── initialize_oracle_config.rs   (Day 7 — NEW)
│       └── update_oracle_config.rs       (Day 7 — NEW)
├── tests/
│   └── update_score.ts              (18 integration tests)
└── scripts/
    ├── setup.sh
    └── initialize_oracle_config.ts

helixor-oracle/
├── oracle/
│   ├── submit.py                    ← Anchor tx submission with retries
│   └── epoch_runner.py              ← async epoch loop + service entry
├── scripts/
│   └── run_epoch_once.sh            ← Day 7 manual verification
├── docker-compose.yml               ← + epoch_runner service
└── README.md
```

---

## Operational Notes

**Oracle wallet must hold SOL.** Each first-time cert costs ~0.00128 SOL in
rent (paid by oracle). For 1000 agents that's 1.28 SOL upfront. The
`epoch_runner` warns if balance drops below 0.1 SOL.

**Priority fees.** Default 1000 micro-lamports/CU (~negligible cost on devnet,
small cost on mainnet). During mainnet congestion, bump
`PRIORITY_FEE_MICRO_LAMPORTS` in `oracle/submit.py`.

**Retries are bounded.** Up to 3 attempts per agent with exponential backoff.
After exhaustion the score stays unsynced; next epoch_runner pass will retry.
This is by design — we never want to submit identical txs to the network in
a tight loop and risk depleting the oracle wallet.

**Pause is loud, not silent.** When paused, every submission throws `Paused`
which halts the entire epoch pass. Operator MUST be alerted (logs at ERROR
level). Don't deploy without log monitoring.

---

*Helixor MVP · Day 7 complete · Next: Day 8 FastAPI REST + TypeScript SDK*
