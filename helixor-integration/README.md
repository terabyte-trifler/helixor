# helixor-integration — Day 13

> **The merge gate.**
>
> Hardening checks + cross-layer integration tests + regression suite.
> CI runs this on every PR; nothing reaches Day 14 (devnet validation)
> until this gate is green.

---

## What this delivers

```
helixor-integration/
├── tests/integration/
│   ├── smoke.test.ts                    7  fast pre-flight checks
│   ├── invariants.test.ts              10  algebraic properties (always-hold)
│   ├── transitions.test.ts             11  state-machine transitions
│   ├── failure_modes.test.ts            9  upstream failure handling
│   ├── determinism.test.ts              4  same-input → same-output
│   ├── onchain_constraints.test.ts      8  PDA + authority constraints
│   └── regressions/                       per-bug regression files
│       └── R2026-04-29_score_boundary_1000.test.ts
├── helpers/
│   ├── env.ts          mainnet-refusal, env validation
│   ├── fixtures.ts     fresh per-test agents, deterministic seeding
│   ├── pipeline.ts     drive Day 5/6/7 CLIs via subprocess
│   ├── onchain.ts      decode TrustCertificate + AgentRegistration + OracleConfig
│   └── poll.ts         pollUntil with structured timeouts
├── scripts/
│   ├── harden_rust.ts        cargo-audit + clippy + bumps + authority checks
│   ├── harden_secrets.ts     secret leak scan + env hygiene
│   ├── harden_all.ts         the full gate (CI entry point)
│   └── verify_artifact.ts    deployed .so byte-matches local build
└── .github/workflows/
    └── gate.yml              runs harden_all on every PR
```

---

## Status

### Integration tests
| Layer | What it covers |
|-------|----------------|
| **smoke** | env validity, API up, RPC reachable, program deployed, schema≥5, error envelope correctness |
| **invariants** | breakdown components sum to raw_score, score in [0,1000], component caps (500/300/200), alert tier matches score, deterministic recompute, scoring_algo_version stable across agents, source field semantics for live/provisional/stale |
| **transitions** | provisional → live (after first score), live → stale (48h boundary), score=min boundary (passes), score=min-1 (fails), score=0 with min=0, deactivation flow, anomaly persistence + clearing |
| **failure_modes** | malformed pubkey → InvalidAgentWalletError (no network), AgentNotFoundError carries requestId, 1ms timeout → TimeoutError, zero-tx provisional, registered <24h provisional, version field present, 100 parallel reads same score, rate limit returns 429 with retry-after |
| **determinism** | recompute idempotent, baseline_hash stable, two agents with identical data produce identical scores (no agent_wallet leakage into scoring), API JSON stable across reads (sans served_at) |
| **onchain_constraints** | OracleConfig PDA exists + deterministic, TrustCertificate PDA derivation deterministic, on-chain ↔ DB byte-match for synced agents, update_score authority constraint verified, non-existent agent has no cert |
| **regressions** | one file per fixed bug; never deleted |

### Hardening
| Check | Pass criterion |
|-------|----------------|
| `cargo audit` | zero reported vulnerabilities |
| `cargo clippy --all-targets --all-features -- -D warnings` | zero warnings |
| `overflow-checks = true` in `[profile.release]` | present |
| No naked `.unwrap()` in `programs/*/src/` (excl. tests) | zero |
| No `.expect("...")` in `programs/*/src/` (excl. tests) | zero |
| All PDA-backed accounts persist `bump` field | enforced (excl. OracleConfig singleton) |
| No 64-byte numeric arrays in source (potential keypair leakage) | warning if found |
| `update_score.rs` has explicit oracle authority constraint | enforced |
| Secret scan: Solana keys, UUID API keys, OpenAI/Anthropic/Telegram tokens, hxop_ keys | zero matches across all repos |
| Oracle keypair loaded from configured path, not hardcoded | enforced in `oracle/submit.py` |
| No committed `.env` files (only `.env.example`) | enforced |
| Deployed `.so` sha256 matches local build (Day 14 prereq) | exact match |

---

## Quick Start

```bash
# Once on a fresh machine:
cp .env.example .env
# Edit to point at your devnet endpoints

npm install
npm run test:smoke              # 5s — verify environment
npm run harden:all              # full gate, ~5min on a clean repo
```

---

## Per-stage running

```bash
npm run test:smoke              # 7 fast pre-flight checks
npm run test:invariants         # algebraic properties
npm run test:transitions        # state-machine transitions
npm run test:failures           # graceful failure handling
npm run test:determinism        # reproducibility properties
npm run test:onchain            # on-chain constraint reads
npm run test:regressions        # all regression tests

npm run harden:rust             # Rust-side checks only
npm run harden:secrets          # secret hygiene only
npm run verify:artifact         # deployed program ↔ local build
```

---

## What got fixed vs the spec

| Spec problem | Fix |
|--------------|-----|
| Test bodies are aspirational `{ ... }` | Every test has real assertions, real fixtures, real teardown |
| No test isolation | Each test creates fresh `Keypair.generate()` agents — no inter-test interference |
| No layer separation | One file per concern: invariants, transitions, failures, determinism, on-chain |
| Tests duplicate Day 10 coverage | Day 13 hits invariants, edge boundaries, and failure modes Day 10 doesn't |
| Bash one-liner hardening checklist | Programmatic checks in TS, exit-code structured |
| `grep -rn "unwrap()"` ignores test scope | Scanner skips `tests/`, `_test.rs`, `*/tests/*` paths |
| No regression test mechanism | `regressions/` folder, one file per bug, naming convention `R{date}_{slug}.test.ts` |
| No artifact verification | `verify_artifact.ts` byte-compares deployed `.so` to local build |
| No CI gate | `.github/workflows/gate.yml` runs `harden_all` on every PR |
| No secret scanning | `harden_secrets.ts` scans across all sibling repos for known token patterns |
| Hardening mixes "should" and "must" | `harden_all.ts` distinguishes fatal stages from warnings |

---

## Test counts

```
   smoke                7 tests
   invariants          10 tests
   transitions         11 tests
   failure_modes        9 tests
   determinism          4 tests
   onchain_constraints  8 tests
   regressions          3 tests (R2026-04-29_score_boundary_1000)
                       ──
   total               52 tests
```

Compared to spec's "10 tests": Day 13 ships 5x the coverage with real
isolation, real determinism guarantees, real failure-mode handling.

---

## When a test fails on a PR

1. Read the failure message (each helper throws structured errors)
2. Reproduce locally: `npm run test:<stage>`
3. Don't disable the test
4. If you're fixing a real bug, add a regression test BEFORE the fix lands
5. If the test itself is wrong, the fix needs explicit reviewer sign-off

---

## When mainnet day arrives

1. Run `npm run harden:all` against devnet — green
2. Build with the exact commit hash you'll deploy
3. `anchor deploy` to mainnet
4. `HELIXOR_PROGRAM_ID=<mainnet>` `HELIXOR_SOLANA_RPC_URL=<mainnet>` `npm run verify:artifact`
5. If hashes match → safe. If not → halt deployment, debug.

The artifact verifier doesn't replace audits but it catches the most common
class of "wait, what did we deploy?" bugs.

---

*Helixor MVP · Day 13 complete · Next: Day 14 — 48h devnet validation with 5 agents.*
