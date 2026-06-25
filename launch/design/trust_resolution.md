# Trust-Assumption Resolution — the eight audit trust assumptions

**Status:** IMPLEMENTED.
**Audit findings:** the 8-entry TRUST ASSUMPTIONS inventory from the
launch-readiness audit (TA-1..TA-8).
**Owners:** protocol engineering (TA-1, TA-6, TA-7), oracle engineering
(TA-3, TA-4, TA-5, TA-8), platform engineering (TA-2).
**Related code / config:**
- `phylanx-oracle/slashing/divergence.py` (TA-1)
- `phylanx-indexer/indexer/production_config.py` (TA-2 — `assert_source_verified_for_cluster`)
- `phylanx-indexer/indexer/consensus.py` (TA-2 — `is_verified_consensus_source` marker)
- `phylanx-indexer/indexer/runner.py` (TA-2 — pre-flight call site)
- `phylanx-oracle/tests/scoring/test_ta3_property_invariants.py` (TA-3)
- `phylanx-oracle/oracle/library_verification.py` (TA-4)
- `phylanx-oracle/oracle/tx_window_digest.py` (TA-5)
- `phylanx-programs/programs/certificate-issuer/src/state/health_certificate.rs` (TA-6 — `MAX_AGE_SECONDS`, `is_fresh_at`)
- `phylanx-programs/programs/slash-authority/src/state/squads_transition.rs` (TA-7)
- `phylanx-oracle/oracle/multi_rpc.py` (TA-8)
- `audit/trust_assumption_check.py` + `audit/test_trust_assumption_check.py` (mechanical regression gate)

---

## Why a unified trust-assumption closure

The audit enumerated eight TRUST ASSUMPTIONS — claims the protocol made
ABOUT something outside its on-chain code that no part of the codebase
verified. Each one was a credibility tax: a sentence in the audit report
saying "we believe X" with no mechanism behind it. Some were code-level
("the Python cryptography library is uncompromised"); some were
operational ("the admin key is secure until the Squads transition");
some were data-flow assumptions ("the TimescaleDB rows are not
mutated"). All of them shared one shape: the protocol's guarantees were
contingent on a thing it neither owned nor checked.

This doc is the single source of truth for which mitigation closes which
trust assumption and where its regression gate lives. The audit gate at
`audit/trust_assumption_check.py` is the mechanical proof; this doc is
the narrative for an external reviewer.

The discipline mirrors the SPOF closure: every trust assumption is
either ELIMINATED (the claim is no longer needed) or REIFIED (the claim
becomes a check the code performs, not a thing the audit must trust).

---

## The TA inventory

| #  | Trust assumption                                            | Risk shape                | Mitigation                                                                                                      | Gate                |
|----|-------------------------------------------------------------|---------------------------|-----------------------------------------------------------------------------------------------------------------|---------------------|
| 1  | Oracle nodes are honest (≤2 Byzantine)                      | n-of-n honesty             | Off-chain `DivergenceDetector` produces a deterministic evidence hash for `challenge_oracle`.                    | TA gate TA-1        |
| 2  | Geyser plugin data is accurate                              | upstream data integrity    | `assert_source_verified_for_cluster` refuses unverified single-endpoint mainnet sources at boot.                 | TA gate TA-2        |
| 3  | Scoring algorithm is correct                                | algorithmic correctness    | Property-based invariants over `compute_composite_score` — bounds, monotonicity, IMMEDIATE_RED, determinism.    | TA gate TA-3 + pytest |
| 4  | Python cryptography library is uncompromised                | supply chain               | Runtime `verify_library_versions` boots-or-dies + hash-locked `requirements.txt`.                                | TA gate TA-4        |
| 5  | TimescaleDB data is unmodified                              | data-store integrity       | `compute_tx_window_digest` folds an input-row commitment into the AW-04 on-chain digest.                         | TA gate TA-5        |
| 6  | DeFi protocols implement freshness checks                   | downstream consumer hygiene| `HealthCertificate::is_fresh_at` + `MAX_AGE_SECONDS = 48h` give the SDK a first-class freshness predicate.       | TA gate TA-6        |
| 7  | Admin key is secure until Squads transition                 | operational                | Pure on-chain deadline `SQUADS_TRANSITION_DEADLINE_UNIX = 2026-09-01T00:00:00Z` + predicate any handler can gate on. | TA gate TA-7        |
| 8  | Solana RPC endpoint is honest                               | upstream data integrity    | `MultiRpcConsensus` K-of-N over RPC reads; mainnet floor of 3 endpoints, K=2.                                    | TA gate TA-8        |

---

## How each fix works

### TA-1 — oracle-node honesty

The threshold-signing layer already refuses to land a cert without
`floor(n/2)+1` cluster signatures, so a lone Byzantine node cannot mint
a forged cert. What was missing was an evidence trail: a Byzantine node
could submit garbage every epoch with no economic penalty because
nothing produced a deterministic, on-chain-anchorable record of
"node X diverged on epoch Y."

`DivergenceDetector.detect(agent, epoch, verdicts)` (in
`phylanx-oracle/slashing/divergence.py`) takes the per-node submissions
for one epoch and computes:

- the cluster's MEDIAN score (Byzantine-robust — a Byzantine minority
  cannot move the median by more than `DEFAULT_SCORE_TOLERANCE = 50`),
- the set of divergent nodes (score outside tolerance OR immediate_red
  bit disagrees with majority),
- a canonical SHA-256 EVIDENCE HASH over
  `agent || epoch || consensus || sorted(divergent_nodes)`.

The evidence hash is the input to a future `challenge_oracle`
instruction on slash-authority. Because the hash is deterministic, any
two honest cluster members compute byte-identical evidence — the
challenger does not need to "be the first" to see a divergence to win.

### TA-2 — Geyser plugin data integrity

`indexer/consensus.py` already implemented K-of-N consensus over
multiple Yellowstone endpoints (SPOF-#8 mitigation). The trust
assumption that REMAINED was that any production runner had been
constructed THROUGH the verified path. A future patch that handed a raw
`YellowstoneStreamSource` to `GeyserIndexer.__init__` would silently
bypass consensus.

The fix is a duck-typed marker + a load-time pre-flight:

- `ConsensusStream` declares `is_verified_consensus_source: bool = True`
  in its class body. Any other source omits the attribute.
- `indexer.production_config.assert_source_verified_for_cluster(source)`
  reads `PHYLANX_SOLANA_CLUSTER`; on mainnet, refuses any source whose
  marker is not `True`, raising `UnverifiedStreamSourceError`.
- `GeyserIndexer.__init__` calls the pre-flight before storing the
  source. A mainnet runner with a single-endpoint source EXITS at
  construction — it never opens a subscription.

### TA-3 — scoring-algorithm correctness

"No formal verification, only unit tests" was the audit's framing. We
do not claim a formal proof of `compute_composite_score`. We DO claim
the following invariants, asserted as property-based tests in
`tests/scoring/test_ta3_property_invariants.py`:

- P1–P4: output bounds (0..1000), correct types, alert tier consistency.
- P5: `IMMEDIATE_RED` flag forces tier == RED. No bypass.
- P6: per-dimension weighted contributions sum to within ±5 of the
  composite — the score is the weighted aggregate, no extra term.
- P7: byte-identical output for byte-identical input (determinism is the
  cluster-signing precondition).
- P8: all-zero inputs map to RED.
- P9: per-dimension MONOTONICITY — raising any one dimension cannot
  lower the composite. This is parametrised across all 5 dimensions and
  is the property a hostile contributor would most plausibly try to
  break (a weight sign flip).
- P10: alert tier boundaries are exact: 700 == GREEN, 699 == YELLOW;
  400 == YELLOW, 399 == RED.

Sampling is via `random.Random(seed)` (deterministic, no hypothesis
dep), 200 samples per property.

### TA-4 — Python cryptography library

`audit/supply_chain_check.py` already enforced that `requirements.in`
exact-pins every direct dependency. What was missing was a RUNTIME
check: a deployer who skipped `pip install --require-hashes` left no
trace at boot.

`oracle/library_verification.py` closes that gap:

- `EXPECTED_LIBRARY_VERSIONS` mirrors `requirements.in` for the
  security-critical and native-code packages (`cryptography`, `solana`,
  `solders`, `grpcio`, `protobuf`, `asyncpg`). The TA-4 audit gate
  cross-checks the two — drift in either fails the gate.
- `verify_library_versions()` is called once at process startup. Reads
  the installed version via `importlib.metadata.version()`; raises
  `LibraryVerificationError` on any mismatch. The process exits before
  opening a network port.

### TA-5 — TimescaleDB data integrity

The on-chain cert already binds the SCORE (cluster signature), the
BASELINE payload hash (AW-03), and the SCORING KERNEL hash (AW-04).
What it did NOT bind was the IDENTIFIED SET OF TRANSACTIONS the scorer
read. A row mutation in TimescaleDB (DBA mistake, intrusion, replica
divergence) would produce a non-reproducible score with no on-chain
marker saying "these were the inputs."

`oracle/tx_window_digest.py:compute_tx_window_digest(transactions, window)`
returns a 32-byte SHA-256 over the canonical, order-independent
serialisation of the window. Folded into the `score_components_hash`
already on chain via AW-04, so any consumer SDK that re-derives the
digest from a fetched indexer view detects a mismatch.

The digest is order-independent (sort by `(slot, signature)` before
hashing), deterministic, and rejects duplicate signatures so a replay
cannot inflate the input set.

### TA-6 — DeFi consumer freshness

"DeFi protocols implement freshness checks" is a claim about strangers'
code. Mitigation is to make it CHEAP and OBVIOUS to do the right thing
from the on-chain account.

`programs/certificate-issuer/src/state/health_certificate.rs` exposes:

```rust
pub const MAX_AGE_SECONDS: i64 = 48 * 60 * 60;  // 48h ceiling

pub fn is_fresh_at(&self, now_unix: i64, max_age_seconds: i64) -> bool;
pub fn is_fresh_default(&self, now_unix: i64) -> bool;
```

A DeFi consumer doing a CPI read calls `is_fresh_default(clock.unix_timestamp)`
and refuses to act on a stale cert. The ceiling matches the on-chain
`mainnet_refusal` cert TTL — exceeding 48h is structurally invalid, not
just stale.

### TA-7 — admin key vs. Squads transition

The audit's concern was a SLOW operator: mainnet deploys land with the
admin key still owning upgrade authority, the operator forgets to
transfer to Squads, the single-key risk persists. There was no on-chain
anchor saying "this MUST be done by date X."

`programs/slash-authority/src/state/squads_transition.rs` introduces
`SQUADS_TRANSITION_DEADLINE_UNIX = 1_788_220_800` (2026-09-01T00:00:00Z)
and the predicate `is_before_squads_transition(now_unix)`. Any
admin-gated handler a future patch may add should wrap itself in
`require!(is_before_squads_transition(clock.unix_timestamp), …)`. The
existing single-admin instructions already return refusal errors; the
deadline catches any newly-introduced admin path post-launch.

The ISO mirror `SQUADS_TRANSITION_DEADLINE_ISO = "2026-09-01T00:00:00Z"`
is pinned alongside the unix value; the audit gate verifies the two
stay in lockstep so a code-review-bypass that bumps the unix without
bumping the ISO is caught.

### TA-8 — Solana RPC endpoint honesty

The Geyser INGEST path is now consensus-verified (SPOF-#8 / TA-2). The
COMMIT path was NOT: `oracle/commit_baseline.py` and similar callers
read a single `SOLANA_RPC_URL`. A compromised RPC there can lie about
the current slot or block hash, race the cluster's view, or silently
drop a submission.

`oracle/multi_rpc.py:MultiRpcConsensus(endpoints, min_agreements)`
mirrors the SPOF-#8 construction contract for RPC reads:

- Default threshold is strict majority: `max(MIN_RPC_CONSENSUS_THRESHOLD=2, floor(N/2)+1)`.
- Mainnet floor: callers SHOULD pass at least `MAINNET_MIN_RPC_ENDPOINTS = 3`.
- `.fetch(fetcher)` invokes the injected callable once per endpoint;
  returns `RpcConsensusReport[T]` with the K-of-N agreed value, or
  raises `RpcDivergenceError` with a per-endpoint outcome map.

The fetcher is injected, so the helper is fully testable without
network. Returned values must be hashable (used as a `Counter` key);
endpoints that raise are recorded in `report.errors` and do not
contribute to the tally.

---

## What the audit gate guarantees

`audit/trust_assumption_check.py` runs eight static-grep probes against
the as-shipped tree. It will fail the build if any of the following
goes wrong:

- A marker file is deleted (e.g. `divergence.py`, `multi_rpc.py`,
  `squads_transition.rs`, `library_verification.py`, `tx_window_digest.py`).
- A load-bearing constant is changed without review (`MAX_AGE_SECONDS`,
  `MAINNET_MIN_RPC_ENDPOINTS`, `MIN_RPC_CONSENSUS_THRESHOLD`,
  `DEFAULT_SCORE_TOLERANCE`, `SQUADS_TRANSITION_DEADLINE_UNIX`).
- The Squads deadline UNIX value and ISO string drift apart.
- `EXPECTED_LIBRARY_VERSIONS` in `library_verification.py` falls out of
  sync with `requirements.in` pins.
- A class or function the protocol depends on is renamed or deleted
  (`DivergenceDetector`, `MultiRpcConsensus`, `RpcDivergenceError`,
  `UnverifiedStreamSourceError`, `assert_source_verified_for_cluster`,
  `compute_tx_window_digest`, `is_fresh_at`).
- The runner stops calling its TA-2 pre-flight.
- The TA-3 property suite drops the monotonicity or IMMEDIATE_RED
  invariants.

The gate is intentionally shallow — it greps marker strings. The
DEEPER validation (the property tests, the multi-endpoint failover
behaviour, the runtime version verifier) lives in the per-module test
suites that already run under `audit/run_all.sh`. The audit gate is the
canary that catches a regression at the contract layer BEFORE it
reaches the test layer where it might be quietly skipped.
