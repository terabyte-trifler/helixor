# Freeze Cert at High Score Resolution — red-team Path 3

**Status:** IMPLEMENTED.
**Red-team finding:** Path 3 from the red-team attack tree (root:
"Drain DeFi Protocol Integrated with Phylanx") — "Freeze Cert at
High Score" — three sub-leaves:

  3a. Exploit VULN-05 (commit-reveal block)              [LOW EFFORT]
  3b. Exploit VULN-02 (epoch advancement freeze)         [MEDIUM EFFORT]
  3c. Target DeFi protocol that doesn't check cert
      freshness                                          [LOW EFFORT]

**Owners:** oracle engineering (FRP-1, FRP-2, FRP-3); on-chain /
cluster anchors continue to be owned by the health-oracle (VULN-02),
cluster (VULN-05), and certificate-issuer (TA-6) program teams.
**Related code / config:**
- `phylanx-oracle/oracle/cluster_participation_floor.py` (FRP-1)
- `phylanx-oracle/oracle/epoch_advance_liveness.py` (FRP-2)
- `phylanx-oracle/oracle/cert_reissue_cadence.py` (FRP-3)
- `phylanx-oracle/tests/oracle/test_frp1_cluster_participation_floor.py`
- `phylanx-oracle/tests/oracle/test_frp2_epoch_advance_liveness.py`
- `phylanx-oracle/tests/oracle/test_frp3_cert_reissue_cadence.py`
- `audit/freeze_cert_check.py` +
  `audit/test_freeze_cert_check.py` (mechanical regression gate)
- On-chain / cluster anchors (UNCHANGED, cross-referenced by the
  FRP audit gate):
  - `phylanx-oracle/oracle/cluster/commit_reveal_round.py`
    (`submit_reveal` + `non_revealers` + `reveal_deadline` +
    `min_reveals`)
  - `phylanx-programs/programs/health-oracle/src/instructions/advance_epoch.rs`
    (`verify_cluster_threshold` + `consensus_threshold` +
    `InsufficientAdvanceAttestations`)
  - `phylanx-programs/programs/health-oracle/src/state/epoch_state.rs`
    (`DEFAULT_DURATION_SECONDS: i64 = 86_400`)
  - `phylanx-programs/programs/certificate-issuer/src/state/health_certificate.rs`
    (`MAX_AGE_SECONDS: i64 = 48 * 60 * 60` + `is_fresh_default`)

---

## The attack the red team named

The attack tree's Path 3 is the THIRD of three drain paths and the
one whose substrate is the cluster's LIVENESS — not the cluster's
signing authority (Path 1) nor the agent's score itself (Path 2).
Reproduced verbatim from the tree:

```
ROOT: Drain DeFi Protocol Integrated with Phylanx
├── Path 3: Freeze Cert at High Score
│   ├── 3a. Exploit VULN-05 (commit-reveal block)        [LOW EFFORT]
│   ├── 3b. Exploit VULN-02 (epoch advancement freeze)   [MEDIUM EFFORT]
│   └── 3c. Target DeFi protocol that doesn't check
│       cert freshness                                   [LOW EFFORT]
```

Pre-FRP the cluster's liveness substrate was protected by the
cluster-side `submit_reveal` + `non_revealers` + `reveal_deadline`
+ partial-reveal-quorum (`min_reveals`) machinery in
`commit_reveal_round.py` (3a), the on-chain
`verify_cluster_threshold` + `consensus_threshold` +
`InsufficientAdvanceAttestations` machinery in `advance_epoch.rs`
together with AW-02's Tier-2 fallback at 2× duration (3b), and the
on-chain `MAX_AGE_SECONDS = 48 * 60 * 60` + `is_fresh_default`
freshness ceiling in `health_certificate.rs` (3c). Each of those
defences is necessary but none of them sees the FULL shape of the
freeze residual:

- **3a residual.** A FLEET-WIDE pattern of barely-quorate rounds.
  The per-round commit-reveal defence enforces the deadline and the
  per-node strike book; what it cannot see is that an attacker who
  has compromised K nodes can keep submitting JUST ENOUGH reveals
  to scrape past `min_reveals` every round while keeping the
  participating-node count pinned at the bare-quorum floor. The
  cluster keeps closing rounds and minting certs — but every cert
  is signed by a "minimum quorum" set. An honest cluster never
  sustains minimum-quorum operation; it only happens during a real
  attack or a real outage. Either way, MINTING CERTS in that state
  freezes the score at whatever value the few participants agree
  on.
- **3b residual.** The gap between attack-start and on-chain
  ceiling. The on-chain advance-epoch instruction enforces M-of-N
  attestation per advance; AW-02 layers Tier-2 fallback recovery at
  2× the canonical 24h epoch duration (48h). Together they ensure
  the cluster CAN advance, eventually — but they do NOT refuse to
  MINT NEW CERTS during the stall window itself. An attacker who
  withholds advance attestations from K-of-N nodes freezes the
  on-chain epoch clock at E. The cluster's REMAINING nodes
  continue to produce per-round cert work — but every round signs
  against the FROZEN epoch. DeFi protocols that re-read the cert
  see the same high score for as long as the stall persists, all
  the way up to AW-02's Tier-2 fallback engaging at 48h.
- **3c residual.** A freshness-blind DeFi consumer. The on-chain
  TA-6 ceiling (48h) and SDK-side SOL-3 per-operation floors
  (LOAN_ISSUE 4h, LIQUIDATION_CHECK 12h, STATUS_READ 48h) are both
  enforced ONLY when the consumer calls `is_fresh_default(now)` on
  the cert. A consumer that integrates directly with the on-chain
  account and SKIPS the freshness check continues to lend against
  the last cert it saw, even if the cluster has stalled (3a / 3b).
  The cluster needs a CLUSTER-SIDE guarantee that the cert on
  chain cannot be older than a small bounded window —
  independently of whether the consumer remembers to check.

Path 3 therefore needs THREE new mitigations at three different
substrates of the cluster's liveness pipeline, each fail-closed and
each composable with the on-chain / cluster anchors that already
ship.

---

## Why a three-mitigation closure

The three sub-leaves cluster into three independent substrates:

| Substrate | Sub-leaf it spans | Why a single mitigation cannot reach it |
| --- | --- | --- |
| Cluster round-level participation pattern | 3a | The per-round commit-reveal defence sees one round in isolation: it enforces the deadline + strikes + partial-reveal quorum. It does NOT see the SUSTAINED pattern of rounds closing at bare quorum. FRP-1 enforces a trailing-run cap on barely-quorate rounds (≤ 3 consecutive rounds at `quorum_threshold + BARELY_QUORATE_MARGIN`) and a `MIN_HEALTHY_PARTICIPATION_RATIO = 0.8` minimum, so a sustained withholding attack fails closed on the 4th consecutive bare-quorum round. |
| Cluster-wide epoch-advance liveness | 3b | The on-chain `verify_cluster_threshold` + `InsufficientAdvanceAttestations` defence refuses an advance below the M-of-N threshold but does not refuse NEW CERT issuance during a stall. AW-02's Tier-2 fallback opens at 2× duration (48h). FRP-2 closes the gap between attack-start and Tier-2: at 1.5× duration (36h) the cluster refuses to mint new certs against a stalled epoch. AW-02's Tier-2 fallback remains the RECOVERY path; FRP-2 is the REFUSAL path. |
| Per-agent cert-reissue cadence (consumer-side residual) | 3c | The on-chain TA-6 48h ceiling fires only when the consumer calls `is_fresh_default`. SOL-3's per-operation floors (LOAN_ISSUE 4h, LIQUIDATION_CHECK 12h, STATUS_READ 48h) require the SDK. Neither closes the "freshness-blind consumer" case. FRP-3 promotes SOL-3's LOAN_ISSUE 4h floor from "consumer-side check" to "cluster-side self-discipline": the cluster commits to reissuing every active agent's cert at most 4h apart, leaving a 12× safety margin against TA-6's on-chain 48h ceiling. A consumer that DOES call `is_fresh_default` sees freshness violations long before TA-6's ceiling fires; a consumer that does NOT will at least eventually see TA-6 fire — but in the gap the cluster refuses to declare its own cert valid for high-tier consumer operations. |

The three mitigations are orthogonal: each closes a substrate the
other two cannot reach. Defeating Path 3 requires defeating all
three AND surviving the cluster-side VULN-05 commit-reveal anchor,
the on-chain VULN-02 advance-attestation anchor, AND the on-chain
TA-6 freshness ceiling.

---

## The FRP inventory

| #   | Substrate                                              | Mitigation                                                                                                                          | Pinned thresholds                                                                                                                                                                              | Gate           |
|-----|--------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------|
| 1   | Cluster round-level participation pattern              | `verify_cluster_participation_floor(history)` + `enforce_cluster_participation_floor(...)` — refuses sustained barely-quorate runs | `MIN_HEALTHY_PARTICIPATION_RATIO = 0.8`, `MAX_BARELY_QUORATE_ROUNDS = 3`, `BARELY_QUORATE_MARGIN = 1`, `PARTICIPATION_FUTURE_TOLERANCE_EPOCHS = 1`                                              | FRP gate FRP-1 |
| 2   | Cluster-wide epoch-advance liveness                    | `verify_epoch_advance_liveness(state)` + `enforce_epoch_advance_liveness(...)` — refuses cert issuance during epoch stall          | `MAX_EPOCH_ADVANCE_STALL_SECONDS = 36 * 3600`, `EXPECTED_EPOCH_DURATION_SECONDS = 24 * 3600`, `EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS = 60`                                                     | FRP gate FRP-2 |
| 3   | Per-agent cert-reissue cadence (consumer-side residual) | `verify_cert_reissue_cadence(sample)` + `enforce_cert_reissue_cadence(...)` — refuses high-tier vouching when reissue cadence slips | `MAX_CERT_REISSUE_INTERVAL_SECONDS = 4 * 3600`, `CERT_REISSUE_FUTURE_TOLERANCE_SECONDS = 60`, `TA6_ONCHAIN_MAX_AGE_SECONDS = 48 * 3600`                                                          | FRP gate FRP-3 |

---

## How each fix works

### FRP-1 — cluster participation floor

The per-round commit-reveal defence in `commit_reveal_round.py`
enforces the `reveal_deadline`, the `min_reveals` partial-reveal
quorum, and the `non_revealers()` strike book — all at the
single-round granularity. None of those see the FLEET-WIDE pattern
where rounds keep closing at bare quorum because an attacker who
has compromised K nodes scrapes past `min_reveals` every round.
FRP-1 reifies the round-level participation contract:

`oracle/cluster_participation_floor.py`:

- `ClusterParticipationSample(epoch, participating_node_count,
  total_node_count, quorum_threshold)` is one round's
  participation as observed at round close.
  `ClusterParticipationHistory(history, current_epoch)` is the
  pre-flight input for the cert-issuance coordinator.
- `MIN_HEALTHY_PARTICIPATION_RATIO = 0.8` — an honest cluster
  operates with at least 80% of nodes participating per round.
  With N=5 / K=3 this is 4-of-5 (a single tolerated outage); with
  N=9 / K=5 it's ~7-of-9. Lower ratios (3-of-5 = 60%) ARE the
  bare-quorum state FRP-1 is alarmed about.
- `MAX_BARELY_QUORATE_ROUNDS = 3` — at most 3 consecutive rounds
  may close at the bare-quorum margin. A 4th consecutive
  barely-quorate round REFUSES cert issuance entirely. Three is
  the cliff edge — by then any honest outage (a rolling upgrade,
  a partition repair, a single-node restart) would have been
  noticed and recovered.
- `BARELY_QUORATE_MARGIN = 1` — a round is "barely quorate" when
  `participating_node_count <= quorum_threshold + 1`. With N=5 /
  K=3 this means rounds with `participating_count ∈ {3, 4}` are
  "barely quorate"; 5 is "healthy". The +1 margin lets an honest
  cluster with one transient outage sneak through; a sustained
  pattern of exactly-quorum or quorum+1 rounds is what FRP-1
  refuses.
- `PARTICIPATION_FUTURE_TOLERANCE_EPOCHS = 1` — a single epoch of
  clock skew. A sample whose `epoch > current_epoch + 1` is
  REFUSED with `PARTICIPATION_EPOCH_IN_FUTURE`.
- Special states: empty history is REFUSED with
  `PARTICIPATION_HISTORY_EMPTY` (the cluster cannot issue a cert
  with no observed rounds). Zero quorum or zero total is REFUSED
  with `PARTICIPATION_INVALID_QUORUM`. Non-monotonic epoch order
  is REFUSED with `PARTICIPATION_EPOCH_NOT_MONOTONIC`.
- `PARTICIPATION_BELOW_HEALTHY_FLOOR` is a COMPLEMENTARY flag
  raised when the min ratio is below 0.8 AND the trailing run is
  at or past the barely-quorate cap. It is reported in addition
  to `PARTICIPATION_BARELY_QUORATE_TOO_LONG` so the operator
  dashboard can distinguish "one bad round at lower quorum" from
  "sustained low-participation pattern".
- The gate is fired only on the TRAILING run — not on any
  barely-quorate run that occurred earlier in the window. This
  is intentional: a cluster that had a 4-round outage in the
  middle of the window but has fully recovered IS minting healthy
  certs and should not be refused.
- `verify_cluster_participation_floor(state)` is pure: integer
  arithmetic on per-round samples + ratio compare against
  `MIN_HEALTHY_PARTICIPATION_RATIO`. No clock, no network, no
  randomness.
- `enforce_cluster_participation_floor(...)` raises
  `ClusterParticipationFloorError` on any refusal with the
  report attached.

The boundary semantics are pinned by test: exactly 3 trailing
barely-quorate rounds is OK (inclusive at the cap); 4 consecutive
is REFUSED. Exactly `current_epoch + 1` is OK (within tolerance);
beyond is REFUSED.

### FRP-2 — epoch-advance liveness floor

FRP-1 closes the round-level pattern. What it does NOT close is
the EPOCH-level case: an attacker who withholds advance
attestations from enough nodes (N-M+1) freezes the on-chain epoch
clock. The on-chain `verify_cluster_threshold` defence in
`advance_epoch.rs` refuses an advance below the M-of-N threshold,
and AW-02's Tier-2 fallback opens at 2× duration to RECOVER from
the stall. Neither defence refuses to MINT NEW CERTS during the
stall window itself. FRP-2 reifies the cluster-wide epoch-advance
contract:

`oracle/epoch_advance_liveness.py`:

- `EpochAdvanceState(last_epoch_advance_unix, current_unix,
  last_advanced_epoch, current_epoch)` is the pure input — the
  cluster's epoch-advance liveness state at the moment a cert is
  about to be issued.
- `MAX_EPOCH_ADVANCE_STALL_SECONDS = 36 * 3600` — 36 hours = 1.5×
  the canonical 24h epoch cycle (matches on-chain
  `DEFAULT_DURATION_SECONDS = 86_400`). When the cluster has not
  advanced for longer than this, the off-chain coordinator
  REFUSES to mint any new certs, regardless of the round-level
  state. AW-02's Tier-2 fallback opens at 2× duration (48h), so
  FRP-2's 1.5× floor catches the residual BEFORE Tier-2 even
  needs to engage.
- `EXPECTED_EPOCH_DURATION_SECONDS = 24 * 3600` — the canonical
  24h epoch duration, MIRRORED from on-chain
  `DEFAULT_DURATION_SECONDS`. Pinned here so the audit gate can
  cross-check the two clocks have not drifted out of lockstep.
  A refactor that changes ONE without the other lights the FRP
  audit gate red.
- `EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS = 60` — single-minute
  clock skew. A `last_epoch_advance_unix` more than 60s ahead of
  `current_unix` is REFUSED as structurally suspect.
- Special states: `last_epoch_advance_unix < 1` is REFUSED with
  `EPOCH_ADVANCE_TIMESTAMP_INVALID` (an uninitialised cluster
  must not be issuing certs at all). `last_advanced_epoch < 0`
  is REFUSED with `EPOCH_ADVANCE_EPOCH_INVALID`. `current_epoch
  < last_advanced_epoch` is REFUSED with
  `EPOCH_ADVANCE_EPOCH_NOT_MONOTONIC`.
- The stall comparison is INCLUSIVE at the floor: exactly 36h
  since last advance is OK; 36h + 1s is REFUSED. This matters
  for synchronised clusters where the next advance lands on the
  floor itself.
- `verify_epoch_advance_liveness(state)` is pure: integer
  arithmetic on `(current_unix, last_epoch_advance_unix)`.
- `enforce_epoch_advance_liveness(...)` raises
  `EpochAdvanceStallError` on refusal.

The boundary semantics are pinned by test: exactly 36h is OK
(inclusive); 36h + 1s is REFUSED. Past historical outages observed
on devnet topped out around 28h, well below the 36h floor.

### FRP-3 — cert-reissue cadence floor

FRP-1 closes the round-level pattern; FRP-2 closes the epoch-
level stall. What neither closes is the PER-AGENT case: even with
the cluster's epoch advancing and rounds succeeding, the cluster
might still let an individual agent's cert age out before reissue.
The on-chain TA-6 ceiling (48h) and SDK-side SOL-3 floors only
fire when the consumer calls `is_fresh_default(now)`. A
freshness-blind consumer keeps lending against the last cert it
saw, all the way to TA-6's 48h ceiling. FRP-3 reifies the
cluster-side reissue-cadence contract:

`oracle/cert_reissue_cadence.py`:

- `CertReissueSample(agent_wallet, last_reissue_unix,
  current_unix)` is one per-agent cert reissue observation.
- `MAX_CERT_REISSUE_INTERVAL_SECONDS = 4 * 3600` — 4 hours. The
  cluster commits to reissuing every active agent's cert at most
  4h apart. This is the LOAN_ISSUE-tier floor from SOL-3,
  PROMOTED from "consumer-side check" to "cluster-side
  self-discipline". The cluster MUST keep up — or refuse to
  declare the cert valid for high-tier consumer operations.
- `CERT_REISSUE_FUTURE_TOLERANCE_SECONDS = 60` — standard 60s
  clock-skew tolerance mirrored from the rest of the cluster.
- `TA6_ONCHAIN_MAX_AGE_SECONDS = 48 * 3600` — pinned here as a
  MIRROR of the on-chain TA-6 ceiling
  (`health_certificate.rs::MAX_AGE_SECONDS = 48 * 60 * 60`). The
  FRP audit gate cross-checks the two values so a refactor of
  one without the other lights red. The ratio
  `TA6_ONCHAIN_MAX_AGE_SECONDS // MAX_CERT_REISSUE_INTERVAL_SECONDS`
  is 12 — the SAFETY MARGIN factor. The cluster MUST reissue 12
  times before the on-chain ceiling fires.
- Special states: empty `agent_wallet` is REFUSED with
  `CERT_REISSUE_AGENT_WALLET_MISSING`. `last_reissue_unix < 1`
  is REFUSED with `CERT_REISSUE_TIMESTAMP_INVALID` (the cluster
  has never issued a cert for this agent and must not declare
  it valid). `last_reissue_unix > current_unix + 60s` is REFUSED
  with `CERT_REISSUE_TIMESTAMP_IN_FUTURE`.
- The cadence comparison is INCLUSIVE at the floor: exactly 4h
  since last reissue is OK; 4h + 1s is REFUSED.
- `verify_cert_reissue_cadence(sample)` is pure: integer
  arithmetic on `(current_unix, last_reissue_unix)`.
- `enforce_cert_reissue_cadence(...)` raises
  `CertReissueCadenceError` on refusal.

The boundary semantics are pinned by test: exactly 4h is OK
(inclusive); 4h + 1s is REFUSED. The safety-margin factor is
asserted to be exactly 12 by test, so any change to either
constant that breaks the 12× ratio lights red immediately.

### Interaction between the three mitigations and the upstream anchors

- **FRP-1 ↔ VULN-05.** FRP-1 is the FLEET-WIDE pre-flight that
  the cert-issuance coordinator runs after the round closes but
  BEFORE submitting the cert tx. The cluster-side `submit_reveal`
  + `non_revealers` + `reveal_deadline` + `min_reveals` defence
  in `commit_reveal_round.py` is the PER-ROUND anchor. The two
  are layered: the per-round anchor enforces the deadline and
  the per-node strike book; FRP-1 enforces the FLEET-WIDE pattern
  across many rounds. If the per-round anchor drifts (the
  reveal_deadline is removed, or min_reveals is unbounded), FRP-1
  cannot stand alone — and the FRP audit gate lights red.
- **FRP-2 ↔ VULN-02 / AW-02.** FRP-2 stands ON TOP of the
  on-chain `verify_cluster_threshold` +
  `InsufficientAdvanceAttestations` anchor in `advance_epoch.rs`.
  The on-chain defence enforces M-of-N per advance; FRP-2
  refuses cert issuance during the stall window. AW-02's Tier-2
  fallback is the RECOVERY path; FRP-2 is the REFUSAL path.
  AW-02 opens at 2× duration (48h); FRP-2 fires at 1.5× duration
  (36h) — so FRP-2 catches the gap BEFORE Tier-2 even engages.
  If the on-chain `consensus_threshold` is removed or
  `DEFAULT_DURATION_SECONDS` drifts away from 86_400, FRP-2's
  calibration story breaks and the FRP audit gate lights red.
- **FRP-3 ↔ TA-6.** FRP-3 is the CLUSTER-side cadence floor;
  the on-chain `MAX_AGE_SECONDS = 48 * 60 * 60` +
  `is_fresh_default` in `health_certificate.rs` is the
  CONSUMER-side ceiling. The two are calibrated as a 12× safety
  margin: the cluster reissues every 4h; the on-chain ceiling
  fires only at 48h. A freshness-checking consumer sees SOL-3
  violations long before TA-6 fires; a freshness-BLIND consumer
  still gets the 12× margin because the cluster refuses to
  declare its own cert valid past the 4h floor. If
  `MAX_AGE_SECONDS` drifts away from 48 * 60 * 60, the 12×
  margin breaks and the FRP audit gate lights red.
- **FRP-3 ↔ SOL-3.** SOL-3 (`operation_freshness.py`) imposes
  CONSUMER-side per-operation freshness floors (LOAN_ISSUE 4h,
  LIQUIDATION_CHECK 12h, STATUS_READ 48h). A consumer that
  bypasses the SDK and reads the on-chain account directly
  doesn't see SOL-3. FRP-3 is the CLUSTER-side complement:
  same 4h floor, but enforced by the CLUSTER refusing to
  declare its own cert valid past that point. The two are
  layered, not redundant — SOL-3 ensures SDK-integrated
  consumers see the floor; FRP-3 ensures the cluster doesn't
  KEEP MINTING certs against the floor either way.
- **FRP-1 ↔ FRP-2.** FRP-1 catches the ROUND-level stall
  (commit-reveal withholding). FRP-2 catches the EPOCH-level
  stall (advance-attestation withholding). A determined
  attacker may try either; the two are independent substrates
  of the same VULN-05 / VULN-02 attack family.
- **FRP-1 ↔ SOL-1.** SOL-1 (`cluster_liveness.py`) is the
  CONSUMER-side signal that the cluster IS in a degraded state
  (so DeFi protocols can fall back). FRP-1 is the CLUSTER-side
  refusal that PREVENTS a degraded-state cert from being issued
  in the first place. They are complementary: SOL-1 says
  "consumer, look out — the cluster is degraded"; FRP-1 says
  "cluster, stop minting certs in this state."

---

## What the audit gate guarantees

`audit/freeze_cert_check.py` runs three probes (FRP-1..FRP-3, each
with its paired upstream-anchor cross-check) against the as-shipped
tree. The gate fails the build if any of the following goes wrong:

- A marker file is deleted (`cluster_participation_floor.py`,
  `epoch_advance_liveness.py`, `cert_reissue_cadence.py`).
- A load-bearing function disappears
  (`verify_cluster_participation_floor` /
  `enforce_cluster_participation_floor`,
  `verify_epoch_advance_liveness` /
  `enforce_epoch_advance_liveness`,
  `verify_cert_reissue_cadence` / `enforce_cert_reissue_cadence`).
- A pinned threshold is silently changed
  (`MIN_HEALTHY_PARTICIPATION_RATIO = 0.8`,
  `MAX_BARELY_QUORATE_ROUNDS = 3`,
  `BARELY_QUORATE_MARGIN = 1`,
  `MAX_EPOCH_ADVANCE_STALL_SECONDS = 36 * 3600`,
  `EXPECTED_EPOCH_DURATION_SECONDS = 24 * 3600`,
  `EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS = 60`,
  `MAX_CERT_REISSUE_INTERVAL_SECONDS = 4 * 3600`,
  `CERT_REISSUE_FUTURE_TOLERANCE_SECONDS = 60`,
  `TA6_ONCHAIN_MAX_AGE_SECONDS = 48 * 3600`).
- The status-label constants (`PARTICIPATION_OK` /
  `PARTICIPATION_REFUSED`, `EPOCH_ADVANCE_OK` /
  `EPOCH_ADVANCE_REFUSED`, `CERT_REISSUE_OK` /
  `CERT_REISSUE_REFUSED`) are renamed.
- The cluster-side VULN-05 anchor drifts —
  `commit_reveal_round.py` missing or `submit_reveal` /
  `non_revealers` / `reveal_deadline` / `min_reveals` deleted.
- The on-chain VULN-02 anchor drifts — `advance_epoch.rs`
  missing or `verify_cluster_threshold` / `consensus_threshold`
  / `InsufficientAdvanceAttestations` deleted, or
  `epoch_state.rs::DEFAULT_DURATION_SECONDS = 86_400` drifts.
- The on-chain TA-6 anchor drifts — `health_certificate.rs`
  missing or `MAX_AGE_SECONDS: i64 = 48 * 60 * 60` /
  `is_fresh_default` removed.

The gate is intentionally narrow at the CONTRACT layer — the
deeper validation lives in the per-module property tests
(`tests/oracle/test_frp[1-3]_*.py`, 49 tests total). The audit
gate is the canary that catches a contract-layer regression
BEFORE it reaches the test layer where it might be quietly
skipped or rewritten. The `audit/test_freeze_cert_check.py`
self-test pins the gate to 0 hard / 0 soft findings on the
as-shipped tree.
