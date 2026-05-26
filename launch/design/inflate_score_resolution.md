# Inflate Legitimate Score Resolution — red-team Path 2

**Status:** IMPLEMENTED.
**Red-team finding:** Path 2 from the red-team attack tree (root:
"Drain DeFi Protocol Integrated with Helixor") — "Inflate Legitimate
Score" — three sub-leaves:

  2a. Exploit VULN-06 (baseline overwrite)           [LOW EFFORT]
  2b. Exploit VULN-07 (feature poisoning)            [MEDIUM EFFORT]
  2c. Exploit VULN-03 (Byzantine slow drift)         [HIGH EFFORT, LONG TERM]

**Owners:** oracle engineering (ILS-1, ILS-2, ILS-3); on-chain /
indexer / cluster anchors continue to be owned by the
certificate-issuer (VULN-06), indexer (VULN-07), and cluster
(VULN-03) program teams.
**Related code / config:**
- `helixor-oracle/oracle/baseline_rotation_guard.py` (ILS-1)
- `helixor-oracle/oracle/feature_corroboration.py` (ILS-2)
- `helixor-oracle/oracle/score_drift_ceiling.py` (ILS-3)
- `helixor-oracle/tests/oracle/test_ils1_baseline_rotation_guard.py`
- `helixor-oracle/tests/oracle/test_ils2_feature_corroboration.py`
- `helixor-oracle/tests/oracle/test_ils3_score_drift_ceiling.py`
- `audit/inflate_score_check.py` +
  `audit/test_inflate_score_check.py` (mechanical regression gate)
- On-chain / indexer / cluster anchors (UNCHANGED, cross-referenced
  by the ILS audit gate):
  - `helixor-programs/programs/certificate-issuer/src/instructions/record_baseline.rs`
    (`is_authorised_baseline_writer` + `BaselineRotationTooSoon` +
    `BaselineEpochNotMonotonic`)
  - `helixor-indexer/eventbus/consumer.py`
    (`TrustedProducerSet` + `verify_record_headers`)
  - `helixor-oracle/oracle/cluster/drift_detector.py`
    (`VELOCITY_THRESHOLD = 0.20` + `DRIFT_REASON_VELOCITY`)

---

## The attack the red team named

The attack tree's Path 2 is the SECOND of three drain paths and the
one whose substrate is the agent's score itself — not the
cluster's signing authority (Path 1) nor the consumer's verifier
(Paths 3/4). Reproduced verbatim from the tree:

```
ROOT: Drain DeFi Protocol Integrated with Helixor
├── Path 2: Inflate Legitimate Score
│   ├── 2a. Exploit VULN-06 (baseline overwrite)           [LOW EFFORT]
│   ├── 2b. Exploit VULN-07 (feature poisoning)            [MEDIUM EFFORT]
│   └── 2c. Exploit VULN-03 (Byzantine slow drift)         [HIGH EFFORT, LONG TERM]
```

Pre-ILS the score-formation pipeline was protected by the on-chain
`is_authorised_baseline_writer` + `BaselineEpochNotMonotonic` checks
in `record_baseline.rs` (2a), the indexer-side `TrustedProducerSet`
+ `verify_record_headers` Ed25519 signature check in `consumer.py`
(2b), and the cluster-side `VELOCITY_THRESHOLD = 0.20` velocity gate
+ rolling baseline in `drift_detector.py` (2c). Each of those
defences is necessary but none of them sees the FULL shape of the
score-inflation residual:

- **2a residual.** A single compromised cluster key. The on-chain
  monotonicity check accepts `proposed_epoch = current_epoch + 1`;
  there is no calendar floor on how OFTEN a baseline can be
  rewritten, and the on-chain "authorised writer" set is one of K
  cluster keys, so a single key compromise can rotate the baseline
  every single epoch (mirroring the VULN-06 grind attack) without
  any other cluster operator co-signing.
- **2b residual.** A single compromised trusted producer key. The
  indexer's `verify_record_headers` confirms the signature is valid
  for a known producer pubkey — but a producer pubkey that has
  leaked once is still "trusted" until the cluster rotates the
  trusted set. An attacker who exfiltrates ONE producer key can
  stamp 100% of records for a target agent and the
  signature check passes every time. Worse, an attacker with a
  since-decommissioned producer key can backfill records with stale
  `produced_unix` timestamps.
- **2c residual.** Sub-velocity drift. The cluster's velocity gate
  refuses any per-epoch score delta above 0.20. An attacker who
  drips 0.04 per-epoch deltas (well below the velocity threshold)
  can compound a 0.30+ inflation over ~10 epochs and stay under the
  gate the entire time. Velocity is a per-step quantity; the
  cumulative drift across the full history is not bounded by it.

Path 2 therefore needs THREE new mitigations at three different
substrates of the score-formation pipeline, each fail-closed and
each composable with the on-chain / indexer / cluster anchors that
already ship.

---

## Why a three-mitigation closure

The three sub-leaves cluster into three independent substrates:

| Substrate | Sub-leaf it spans | Why a single mitigation cannot reach it |
| --- | --- | --- |
| Baseline rotation cadence + cluster co-attestation | 2a | The on-chain `BaselineEpochNotMonotonic` check accepts `current_epoch + 1` and the authorised-writer set is one of K cluster keys — there is no calendar floor on how OFTEN a baseline can move, and no requirement that the baseline rotation be co-signed by the agent itself plus a cluster key. ILS-1 enforces a 30-epoch (60h) hard floor between baseline rotations PLUS a minimum-2-cosigner co-attestation gate (the agent's wallet MUST be in the cosigner tuple), so a single compromised cluster key cannot wholesale-rewrite an agent's baseline. |
| Per-producer corroboration + record freshness | 2b | The indexer's `TrustedProducerSet` + `verify_record_headers` confirms a SIGNATURE is valid for a trusted producer pubkey — but a single trusted producer key can sign 100% of records for a target agent's aggregation. ILS-2 refuses an aggregation drawn from fewer than 2 distinct producers (so a solo compromised producer key cannot dominate), caps single-producer dominance at 0.7 of the aggregation (so a compromised + a complicit-but-balanced producer cannot mint a forged-signal majority), and refuses records older than 24h (so an exfiltrated decommissioned producer key cannot backfill stale records into the aggregation window). |
| Cumulative score drift ceiling (cross-epoch clock) | 2c | The cluster's `VELOCITY_THRESHOLD = 0.20` gate refuses any per-epoch delta above 0.20. A 0.04 per-epoch drip stays under the velocity gate forever; over 10 epochs it compounds to ~0.48 — comfortably above the 0.30 inflation a DeFi consumer would care about. ILS-3 enforces a multi-substrate ceiling: cumulative drift from baseline ≤ 0.30, per-epoch drift ≤ 0.05 (a quarter of the cluster's velocity gate, calibrated against the monotonic-run ceiling), AND a monotonic-run ceiling ≤ 10 epochs (so an attacker cannot string together arbitrarily many tiny up-steps without the agent's score crossing back down). Together the three sub-pins make the per-epoch-times-runs cap 1.05^10 - 1 ≈ 0.629 ≫ 0.30, so the cumulative ceiling fires BEFORE the per-epoch limits can be threaded. |

The three mitigations are orthogonal: each closes a substrate the
other two cannot reach. Defeating Path 2 requires defeating all
three AND surviving the on-chain VULN-06 anchor, the indexer-side
VULN-07 anchor, AND the cluster-side VULN-03 velocity gate.

---

## The ILS inventory

| #   | Substrate                                              | Mitigation                                                                                                                          | Pinned thresholds                                                                                                                                                                                                | Gate           |
|-----|--------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------|
| 1   | Baseline rotation cadence + cluster co-attestation     | `verify_baseline_rotation(proposal)` + `enforce_baseline_rotation(...)` — refuses any rotation faster than 30 epochs or solo-signed | `MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS = 30`, `MIN_BASELINE_COSIGNERS = 2`, `BASELINE_FUTURE_TOLERANCE_EPOCHS = 1`                                                                                                | ILS gate ILS-1 |
| 2   | Per-producer corroboration + record freshness          | `verify_feature_corroboration(aggregation, *, current_unix)` + `enforce_feature_corroboration(...)` — refuses solo / stale producers | `MIN_DISTINCT_PRODUCERS_PER_AGGREGATION = 2`, `MAX_PRODUCER_DOMINANCE_RATIO = 0.7`, `MAX_RECORD_AGE_SECONDS = 24 * 3600`, `RECORD_FUTURE_TOLERANCE_SECONDS = 60`                                                  | ILS gate ILS-2 |
| 3   | Cumulative score-drift ceiling                         | `verify_score_drift_ceiling(trajectory)` + `enforce_score_drift_ceiling(...)` — refuses cumulative / per-epoch / monotonic over-drift | `MAX_DRIFT_FROM_BASELINE_RATIO = 0.30`, `MAX_DRIFT_PER_EPOCH_RATIO = 0.05`, `MAX_MONOTONIC_DRIFT_EPOCHS = 10`, `DRIFT_FUTURE_TOLERANCE_EPOCHS = 1`                                                                | ILS gate ILS-3 |

---

## How each fix works

### ILS-1 — baseline-rotation cadence + co-attestation guard

The on-chain `BaselineEpochNotMonotonic` check is a spot-in-time
guarantee: it accepts `current_epoch + 1`. The on-chain
"authorised writer" set is one of K cluster keys, so a single
compromised key can grind the baseline up every single epoch.
ILS-1 reifies the rotation cadence + cosigner topology:

`oracle/baseline_rotation_guard.py`:

- `BaselineRotationProposal(agent_wallet, proposed_epoch,
  last_recorded_epoch, current_epoch, cosigners)` is the pure
  input — every active baseline-rotation proposal as recorded by
  the cluster bootstrap ceremony.
- `MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS = 30` — the hard rotation
  cadence floor. 30 epochs × 2h/epoch = 60 hours = 2.5 days
  between baseline rotations per agent. Any proposal whose delta
  from `last_recorded_epoch` is below this is REFUSED with
  `BASELINE_ROTATION_TOO_SOON`. The 30-epoch figure leaves room
  for 12 rotation slots per quarter — a generous budget for
  legitimate operational tuning, while making the per-epoch grind
  attack infeasible.
- `MIN_BASELINE_COSIGNERS = 2` — the cosigner floor. A baseline
  rotation MUST be co-signed by the agent's own wallet PLUS at
  least one cluster key. The on-chain "authorised writer" check
  is satisfied by a single cluster key alone; ILS-1 requires the
  agent's wallet to be PRESENT in the cosigners tuple
  (`BASELINE_AGENT_MISSING_FROM_COSIGNERS`) — a compromised
  cluster key alone cannot rotate the baseline.
- `BASELINE_FUTURE_TOLERANCE_EPOCHS = 1` — a single epoch of
  clock skew. A `proposed_epoch` ≤ `current_epoch + 1` is treated
  as same-epoch (epoch boundaries are real and benign). Any
  `proposed_epoch > current_epoch + 1` is REFUSED with
  `BASELINE_EPOCH_IN_FUTURE` — the epoch field has been
  tampered with.
- Special states: `proposed_epoch == 0` is REFUSED with
  `BASELINE_EPOCH_INVALID` (epoch zero is the bootstrap sentinel).
  `proposed_epoch <= last_recorded_epoch` (and `last_recorded_epoch
  != -1`) is REFUSED with `BASELINE_EPOCH_NOT_MONOTONIC`. Duplicate
  cosigners (`AGENT, AGENT`) are REFUSED with
  `BASELINE_DUPLICATE_COSIGNER`.
- `verify_baseline_rotation(proposal)` is pure; no logging, no
  I/O, no clock. Returns a `BaselineRotationReport` carrying the
  proposed/last epochs, cosigner count, distinct-cosigner count,
  epoch-delta, and reason codes.
- `enforce_baseline_rotation(...)` raises
  `BaselineRotationRefusedError` on any refusal with the report
  attached.

The boundary semantics are pinned by test: exactly 30 epochs gap
is OK (inclusive at the floor); 29 epochs is REFUSED. Exactly
`current_epoch + 1` is OK (inclusive at the tolerance); `current
+ 2` is REFUSED.

### ILS-2 — producer-corroboration + record-freshness floor

ILS-1 closes baseline-rotation cadence. What it does NOT close is
the PER-PRODUCER case: even with the baseline rotating slowly,
an attacker with one compromised trusted producer key can stamp
100% of records for a target agent's aggregation. The indexer's
`verify_record_headers` confirms each record's signature is valid
for a trusted producer pubkey — but the trusted set does not see
WHICH producer is supplying records, only that the signature
matches a known key. ILS-2 reifies the corroboration topology:

`oracle/feature_corroboration.py`:

- `FeatureRecord(producer_pubkey, produced_unix)` is the pure
  input record. `FeatureAggregation(agent_wallet, records)` is
  the per-agent aggregation passed to the verifier.
- `MIN_DISTINCT_PRODUCERS_PER_AGGREGATION = 2` — the producer-
  count floor. An aggregation drawn from fewer than 2 distinct
  producer pubkeys is REFUSED with `TOO_FEW_PRODUCERS`. The pin
  is 2 (not 3 or higher) so the cluster can still operate during
  legitimate producer-fleet outages, but a SOLO compromised
  producer key cannot dominate.
- `MAX_PRODUCER_DOMINANCE_RATIO = 0.7` — the per-producer
  dominance cap. The most-frequent producer in an aggregation
  MUST not supply more than 70% of records. Calibrated against
  observed indexer-fleet load distribution (35-50% busiest node
  in healthy operation); 70% is the cliff edge. A compromised
  producer + a complicit-but-balanced second producer cannot
  mint a forged-signal majority under this cap.
- `MAX_RECORD_AGE_SECONDS = 24 * 3600` — the freshness floor. A
  record whose `produced_unix` is more than 24h older than
  `current_unix` is REFUSED with `RECORDS_TOO_STALE`. This is
  the residual defence against a since-decommissioned producer
  key — even if the signature verifies, an attacker cannot
  backfill records claiming to be 30h+ old.
- `RECORD_FUTURE_TOLERANCE_SECONDS = 60` — a single minute of
  clock skew. A record up to 60s in the future is benign
  (timestamp generation is racy); past 60s is REFUSED with
  `RECORD_TIMESTAMP_IN_FUTURE`. The time-travel refusal closes
  the "record claims to be from the future so it cannot be stale"
  bypass.
- `verify_feature_corroboration(aggregation, *, current_unix)`
  is pure: builds a `collections.Counter` of producer pubkeys,
  computes the dominance ratio, compares timestamps against the
  freshness / future bounds. Returns a
  `FeatureCorroborationReport` carrying the producer count,
  dominance ratio, dominant producer, stale record count,
  future record count, and reason codes.
- `enforce_feature_corroboration(...)` raises
  `FeatureCorroborationError` on refusal.

The boundary semantics are pinned by test: exactly 0.7 dominance
is OK (inclusive at the cap); 0.71 is REFUSED. Exactly 24h old
is OK (inclusive at the freshness floor); 24h + 1s is REFUSED.

### ILS-3 — cumulative score-drift ceiling

ILS-1 closes baseline-rotation cadence; ILS-2 closes per-producer
corroboration. What neither closes is the CUMULATIVE DRIFT case:
an attacker who passes ILS-1 (legitimate baseline) and ILS-2
(multiple producers, fresh records) can still inflate a score
by feeding tiny per-epoch deltas that compound across many
epochs. The cluster's velocity gate (`VELOCITY_THRESHOLD = 0.20`)
refuses any per-epoch delta above 0.20 — but a 0.04 per-epoch
drip stays under it forever and compounds to ~0.48 over 10
epochs. ILS-3 reifies the cumulative-drift contract:

`oracle/score_drift_ceiling.py`:

- `ScoreHistoryEntry(epoch, score)` is one row of an agent's
  per-epoch score history.
  `AgentScoreTrajectory(agent_wallet, baseline_score, history,
  current_epoch)` is the full per-agent input. Each `score` is
  in `[0.0, 1.0]`.
- `MAX_DRIFT_FROM_BASELINE_RATIO = 0.30` — the hard cumulative
  ceiling. Any history entry whose score is more than 30% above
  the agent's pinned baseline (ratio computed as
  `(score - baseline) / baseline`) is REFUSED with
  `DRIFT_OVER_CUMULATIVE_CEILING`. Calibrated against the
  inflation magnitude a DeFi consumer would care about — a
  borrower whose Helixor score has inflated 30% above baseline
  has materially changed their risk profile.
- `MAX_DRIFT_PER_EPOCH_RATIO = 0.05` — the per-epoch sub-pin. A
  per-epoch jump above 5% (a quarter of the cluster's velocity
  gate) is REFUSED with `DRIFT_OVER_PER_EPOCH_CEILING`. Tighter
  than the cluster's velocity gate (0.20) because the velocity
  gate is the LAST line — ILS-3 catches the residual sub-velocity
  drips that the cluster gate cannot see in isolation.
- `MAX_MONOTONIC_DRIFT_EPOCHS = 10` — the monotonic-run cap. A
  monotonic upward run lasting more than 10 epochs is REFUSED
  with `DRIFT_MONOTONIC_TOO_LONG`. Calibrated jointly with the
  per-epoch sub-pin: at 5% per epoch over 10 monotonic epochs
  the maximum cumulative is `1.05^10 - 1 ≈ 0.629` — more than
  twice the 30% absolute ceiling. So an attacker who threads
  the needle between the per-epoch sub-pin and the monotonic-run
  cap will breach the cumulative ceiling FIRST. The three
  sub-pins compose into a single fail-closed shape.
- `DRIFT_FUTURE_TOLERANCE_EPOCHS = 1` — a single epoch of
  clock skew. A history entry with `epoch > current_epoch + 1`
  is REFUSED with `DRIFT_EPOCH_IN_FUTURE`.
- Special states: `baseline_score <= 0` is REFUSED with
  `DRIFT_BASELINE_NON_POSITIVE` (the ratio is undefined).
  An empty history is REFUSED with `DRIFT_HISTORY_EMPTY`. A
  non-monotonic-epoch history (an epoch lower than the previous)
  is REFUSED with `DRIFT_EPOCH_NOT_MONOTONIC`.
- Downward drift is ALWAYS allowed — the contract is about
  INFLATION, not change. A score that drops 50% from baseline is
  not refused.
- `verify_score_drift_ceiling(trajectory)` is pure: ratio
  arithmetic + monotonic-run accumulation. Returns a
  `ScoreDriftReport` carrying the peak ratio, the offending
  epochs, the longest monotonic run, and reason codes.
- `enforce_score_drift_ceiling(...)` raises
  `ScoreDriftCeilingError` on refusal.

The boundary semantics are pinned by test: exactly 30% drift is
OK (inclusive at the ceiling); 31% is REFUSED. Exactly 5%
per-epoch is OK; 6% is REFUSED. Exactly 10 monotonic epochs is
OK; 11 is REFUSED.

### Interaction between the three mitigations and the upstream anchors

- **ILS-1 ↔ VULN-06.** ILS-1 is the OFF-CHAIN pre-flight; the
  ON-CHAIN anchor is `is_authorised_baseline_writer` +
  `BaselineRotationTooSoon` + `BaselineEpochNotMonotonic` in
  `record_baseline.rs`. ILS-1 enforces the cadence and the
  cosigner floor BEFORE the on-chain tx is broadcast, sparing
  the cluster a refused on-chain submission. If a refactor
  removes the on-chain anchor, the ILS gate lights regardless of
  ILS-1's local state — ILS-1 cannot stand alone without the
  on-chain monotonicity guard.
- **ILS-2 ↔ VULN-07.** ILS-2 stands ON TOP of the indexer's
  `TrustedProducerSet` + `verify_record_headers` anchor in
  `consumer.py`. The indexer gate confirms each record's
  signature is valid for a trusted producer pubkey; ILS-2
  refuses the AGGREGATION if it is solo / dominated / stale.
  Together they form the producer-side defence: the indexer
  refuses individual unsigned records, ILS-2 refuses aggregations
  drawn from too narrow a producer set. If the indexer anchor
  drifts (the trusted set is unbounded or signature verification
  is skipped), ILS-2 cannot stand alone.
- **ILS-3 ↔ VULN-03.** ILS-3 is the CUMULATIVE drift defence;
  the cluster's `VELOCITY_THRESHOLD = 0.20` + `DRIFT_REASON_
  VELOCITY` in `drift_detector.py` is the PER-STEP defence. The
  cluster gate sees a single epoch in isolation and refuses
  >20% per-epoch jumps; ILS-3 sees the FULL history and refuses
  cumulative drift above 30% from baseline, per-epoch drift
  above 5% (a quarter of the cluster gate's threshold), and
  monotonic runs longer than 10 epochs. The two are calibrated
  in lockstep: the cluster gate's 0.20 velocity threshold and
  ILS-3's 0.05 per-epoch ratio are the FAST and SLOW lanes of
  the same defence. If the cluster gate is loosened, ILS-3
  catches the slow lane; if ILS-3 is loosened, the cluster gate
  catches the fast lane. Removing either re-opens one half of
  the velocity-vs-cumulative dimension.
- **ILS-1 ↔ FHS-1 / FHS-3.** FHS-1's 90-day key cadence and
  FHS-3's 1-key-per-ceremony rotation cap make a wholesale
  cluster-key replacement a 10-day public on-chain ceremony.
  ILS-1's 30-epoch baseline-rotation floor makes a wholesale
  baseline-rewrite a 2.5-day cadence floor per agent. The two
  are independent clocks at different substrates: FHS guards
  the SIGNING authority's rotation, ILS-1 guards the AGENT'S
  baseline rotation.
- **ILS-2 ↔ NSS-3.** NSS-3 imposes an agent-registration-age
  floor for GREEN certs (the cluster refuses to mint a GREEN
  cert against an agent whose wallet is younger than a few
  days). ILS-2 imposes a producer-set-distinctness floor for
  feature aggregations. The two are layered: NSS-3 catches
  newly-registered attacker-controlled agents, ILS-2 catches
  forged feature aggregations against any agent.
- **ILS-3 ↔ PDS-3.** PDS-3 (multi-epoch correlated-movement
  detector) and ILS-3 (per-agent cumulative drift) are
  complementary: PDS-3 sees CORRELATED inflation across the
  fleet, ILS-3 sees per-agent inflation. An attacker inflating
  ONE agent's score over 30 epochs would evade PDS-3 (only one
  agent moves) but hit ILS-3's cumulative ceiling; an attacker
  inflating MANY agents in lockstep would evade ILS-3's per-
  agent boundary (each agent stays below 30%) but hit PDS-3's
  correlation detector. The two are non-redundant.

---

## What the audit gate guarantees

`audit/inflate_score_check.py` runs three probes (ILS-1..ILS-3,
each with its paired upstream-anchor cross-check) against the
as-shipped tree. The gate fails the build if any of the following
goes wrong:

- A marker file is deleted (`baseline_rotation_guard.py`,
  `feature_corroboration.py`, `score_drift_ceiling.py`).
- A load-bearing function disappears (`verify_baseline_rotation`
  / `enforce_baseline_rotation`, `verify_feature_corroboration` /
  `enforce_feature_corroboration`, `verify_score_drift_ceiling` /
  `enforce_score_drift_ceiling`).
- A pinned threshold is silently changed
  (`MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS = 30`,
  `MIN_BASELINE_COSIGNERS = 2`,
  `MIN_DISTINCT_PRODUCERS_PER_AGGREGATION = 2`,
  `MAX_PRODUCER_DOMINANCE_RATIO = 0.7`,
  `MAX_RECORD_AGE_SECONDS = 24 * 3600`,
  `MAX_DRIFT_FROM_BASELINE_RATIO = 0.30`,
  `MAX_DRIFT_PER_EPOCH_RATIO = 0.05`,
  `MAX_MONOTONIC_DRIFT_EPOCHS = 10`).
- The status-label constants (`BASELINE_OK` / `BASELINE_REFUSED`,
  `CORROBORATION_OK` / `CORROBORATION_REFUSED`, `DRIFT_OK` /
  `DRIFT_REFUSED`) are renamed.
- The on-chain VULN-06 anchor drifts —
  `record_baseline.rs` missing or
  `is_authorised_baseline_writer` /
  `BaselineRotationTooSoon` / `BaselineEpochNotMonotonic`
  deleted.
- The indexer VULN-07 anchor drifts —
  `eventbus/consumer.py` missing or
  `TrustedProducerSet` / `verify_record_headers` deleted.
- The cluster VULN-03 anchor drifts —
  `oracle/cluster/drift_detector.py` missing or
  `VELOCITY_THRESHOLD = 0.20` / `DRIFT_REASON_VELOCITY` removed.

The gate is intentionally narrow at the CONTRACT layer — the
deeper validation lives in the per-module property tests
(`tests/oracle/test_ils[1-3]_*.py`, 53 tests total). The audit
gate is the canary that catches a contract-layer regression
BEFORE it reaches the test layer where it might be quietly
skipped or rewritten. The `audit/test_inflate_score_check.py`
self-test pins the gate to 0 hard / 0 soft findings on the
as-shipped tree.
