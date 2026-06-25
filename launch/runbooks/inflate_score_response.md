# Runbook — Inflate Legitimate Score mitigation response

**Severity:** Critical (any ILS gate red means a mitigation against
red-team Path 2 — "Inflate Legitimate Score" — has either been
removed from the tree or fired at runtime).
**Triggers:**
- `audit/inflate_score_check.py` gate fails in CI.
- Off-chain baseline-rotation coordinator raises
  `BaselineRotationRefusedError` (ILS-1) refusing to operate on a
  too-soon, solo-signed, or monotonically-invalid baseline
  rotation.
- Feature aggregator raises `FeatureCorroborationError` (ILS-2)
  refusing to ship an aggregation whose producer set is too narrow,
  too dominated, or stale.
- Score-formation pipeline raises `ScoreDriftCeilingError` (ILS-3)
  refusing to publish a score trajectory whose cumulative drift,
  per-epoch drift, or monotonic-run length is over the contract.

## What's happening

The Inflate Legitimate Score path (red-team Path 2) is the three-
sub-leaf drain in which an attacker inflates an agent's GREEN
score without forging the cert itself and uses the inflated score
to drain a DeFi protocol integrated with Phylanx:

  2a. Exploit VULN-06 (baseline overwrite)           [LOW EFFORT]
  2b. Exploit VULN-07 (feature poisoning)            [MEDIUM EFFORT]
  2c. Exploit VULN-03 (Byzantine slow drift)         [HIGH EFFORT, LONG TERM]

The on-chain `BaselineEpochNotMonotonic` check makes 2a hard
per-epoch, the indexer's `TrustedProducerSet` +
`verify_record_headers` Ed25519 signature check closes 2b's
unsigned-record poisoning, and the cluster's `VELOCITY_THRESHOLD =
0.20` gate closes 2c's per-epoch jump. What was missing pre-ILS
was the CUMULATIVE dimension — a baseline that can be ground
upward one epoch at a time (2a residual), an aggregation that can
be dominated by a single compromised producer key (2b residual),
and sub-velocity drips that compound into a 30%+ inflation across
many epochs (2c residual). The three mitigations in
`launch/design/inflate_score_resolution.md` close those residuals;
this runbook is the playbook for reacting when one of them fires
or regresses.

The two failure shapes need different responses:

- **CI gate red** — a refactor has REMOVED a mitigation. The code
  is not yet on mainnet. Block the merge and restore the anchor.
  DO NOT weaken the gate to make CI green.
- **Runtime fire** — the mitigation engaged and refused to ship an
  inflated-score artifact. Mainnet is protected; an attempt to
  inflate is in flight or the legitimate flow has produced a
  pathological shape. Investigate the score-formation substrate
  (NOT the ILS floor) before resuming.

---

## CI gate red — `audit/inflate_score_check.py` failed

### Triage (60s)

```bash
# 1. Run the gate locally to see which ILS family regressed.
python3 audit/inflate_score_check.py --json /tmp/ils.json
cat /tmp/ils.json | python3 -m json.tool | head -80

# 2. Each finding names the rule and the marker string the gate
#    could not find. The ILS-N tag tells you which family
#    regressed.
```

### Decision tree

- **Marker file deleted** (`baseline_rotation_guard.py`,
  `feature_corroboration.py`, `score_drift_ceiling.py`): the
  closing PR removed a mitigation the red-team closure assumes is
  present. RESTORE the file from `main`. The reviewer who approved
  the removal must justify the change in writing on the PR.
- **`verify_*` / `enforce_*` function disappeared**: a contract
  entry point is gone. Restore it. If the function was genuinely
  renamed in good faith, the audit gate's expected marker MUST be
  updated IN THE SAME PR and the PR description must call out the
  Inflate-Legitimate-Score closure impact.
- **ILS-1 threshold changed**
  (`MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS`,
  `MIN_BASELINE_COSIGNERS`,
  `BASELINE_FUTURE_TOLERANCE_EPOCHS`): a load-bearing baseline-
  rotation contract moved. Restore the pinned value. CRITICAL
  CHECKS:
  - `MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS = 30` is the cadence
    floor (30 epochs × 2h = 60h = 2.5 days). Lowering it re-opens
    the per-epoch baseline grind (the exact VULN-06 attack
    shape). Raising it constrains legitimate operator tuning. The
    pin is calibrated against the operator's expected baseline
    cadence (≤ 12 rotations/quarter); never tune without an
    explicit red-team closure review.
  - `MIN_BASELINE_COSIGNERS = 2` is the cosigner floor. Lowering
    to 1 re-opens 2a's solo-rotation residual (any single cluster
    key can rotate alone). The pin is non-negotiable.
  - The agent-presence rule is implicit in
    `BASELINE_AGENT_MISSING_FROM_COSIGNERS`: the agent's wallet
    MUST appear in the cosigners tuple. Never remove this
    check — a cluster-only rotation effectively rewrites the
    agent's baseline without the agent's consent.
- **ILS-1 status / reason label regression** (`BASELINE_OK` /
  `BASELINE_REFUSED`, `BASELINE_ROTATION_TOO_SOON`,
  `BASELINE_INSUFFICIENT_COSIGNERS`,
  `BASELINE_AGENT_MISSING_FROM_COSIGNERS`,
  `BASELINE_EPOCH_NOT_MONOTONIC`, `BASELINE_EPOCH_IN_FUTURE`,
  `BASELINE_EPOCH_INVALID`, `BASELINE_DUPLICATE_COSIGNER`): the
  off-chain coordinator and runbook greps key off these literals.
  Restore them; never rename.
- **ILS-2 threshold changed**
  (`MIN_DISTINCT_PRODUCERS_PER_AGGREGATION`,
  `MAX_PRODUCER_DOMINANCE_RATIO`, `MAX_RECORD_AGE_SECONDS`,
  `RECORD_FUTURE_TOLERANCE_SECONDS`): a load-bearing producer-
  corroboration contract moved. Restore the pinned value.
  CRITICAL CHECKS:
  - `MIN_DISTINCT_PRODUCERS_PER_AGGREGATION = 2` is the floor.
    Lowering to 1 re-opens 2b's solo-poisoning residual (a single
    compromised producer key can stamp 100% of records). Raising
    to 3+ false-fires during legitimate producer-fleet outages —
    the 2-floor is the minimum compatible with degraded operation.
  - `MAX_PRODUCER_DOMINANCE_RATIO = 0.7` is the per-producer cap.
    Calibrated against observed indexer-fleet load distribution
    (35-50% busiest node in healthy operation); 70% is the cliff
    edge. Raising to 1.0 effectively neutralises the dominance
    cap; lowering past 0.5 false-fires under normal load
    asymmetry.
  - `MAX_RECORD_AGE_SECONDS = 24 * 3600` is the freshness floor.
    The 24h figure is the lookback window — records older than
    this are by definition not part of the current decision
    cycle. Raising it re-opens the stale-backfill attack with a
    since-decommissioned producer key.
  - `RECORD_FUTURE_TOLERANCE_SECONDS = 60` is the clock-skew
    tolerance. Never raise to "let traffic through" — a wider
    future window lets an attacker time-stamp records to evade
    the freshness floor.
- **ILS-2 status / reason label regression**
  (`CORROBORATION_OK` / `CORROBORATION_REFUSED`,
  `TOO_FEW_PRODUCERS`, `PRODUCER_OVER_DOMINANCE`,
  `RECORDS_TOO_STALE`, `RECORD_TIMESTAMP_IN_FUTURE`,
  `NO_RECORDS`): operator dashboards and the feature-aggregator
  pipeline greps key off these literals. Restore them; never
  rename.
- **ILS-3 threshold changed**
  (`MAX_DRIFT_FROM_BASELINE_RATIO`, `MAX_DRIFT_PER_EPOCH_RATIO`,
  `MAX_MONOTONIC_DRIFT_EPOCHS`, `DRIFT_FUTURE_TOLERANCE_EPOCHS`):
  a load-bearing drift ceiling moved. Restore the pinned value.
  CRITICAL CHECKS:
  - `MAX_DRIFT_FROM_BASELINE_RATIO = 0.30` is the cumulative
    ceiling — a score 30% above baseline materially changes a
    DeFi consumer's risk model. Raising past 0.30 re-opens the
    slow-drift attack the gate exists to refuse.
  - `MAX_DRIFT_PER_EPOCH_RATIO = 0.05` is the per-epoch sub-pin
    (a quarter of the cluster's velocity gate's 0.20 threshold).
    Calibrated jointly with `MAX_MONOTONIC_DRIFT_EPOCHS` so the
    per-epoch × monotonic cap (1.05^10 - 1 ≈ 0.629) exceeds the
    cumulative ceiling, forcing the cumulative ceiling to fire
    first if an attacker threads the per-epoch limit. If the
    cluster's velocity gate is retuned, ILS-3's per-epoch pin
    MUST move in lockstep so the fast / slow lanes stay
    calibrated.
  - `MAX_MONOTONIC_DRIFT_EPOCHS = 10` is the monotonic-run cap.
    Calibrated so per-epoch × monotonic ≫ cumulative. Raising
    past 10 lets an attacker accumulate more monotonic up-steps
    even at the per-epoch sub-pin and breach the cumulative
    ceiling silently from a different direction.
  - `DRIFT_FUTURE_TOLERANCE_EPOCHS = 1` is the clock-skew
    tolerance. Never raise — a wider future-epoch window lets an
    attacker advance the history clock to evade the monotonic-run
    cap.
- **ILS-3 status / reason label regression** (`DRIFT_OK` /
  `DRIFT_REFUSED`, `DRIFT_OVER_CUMULATIVE_CEILING`,
  `DRIFT_OVER_PER_EPOCH_CEILING`, `DRIFT_MONOTONIC_TOO_LONG`,
  `DRIFT_BASELINE_NON_POSITIVE`, `DRIFT_HISTORY_EMPTY`,
  `DRIFT_EPOCH_NOT_MONOTONIC`, `DRIFT_EPOCH_IN_FUTURE`): the
  score-formation pipeline and operator dashboards grep these
  literals. Restore them; never rename.
- **VULN-06 anchor regression**
  (`record_baseline.rs` missing or
  `is_authorised_baseline_writer` /
  `BaselineRotationTooSoon` / `BaselineEpochNotMonotonic`
  deleted): the on-chain baseline-rotation gate has been
  removed. CATASTROPHIC regression — ILS-1 is the off-chain
  pre-flight and cannot stand alone without the on-chain
  monotonicity + authorised-writer guards. Restore the on-chain
  code AND raise the regression as a red-team-closure incident
  (the closing PR has fundamentally weakened Path 2's
  substrate).
- **VULN-07 anchor regression**
  (`eventbus/consumer.py` missing or `TrustedProducerSet` /
  `verify_record_headers` deleted): the indexer's per-record
  signature check has been removed. CATASTROPHIC regression —
  ILS-2 stands on top of this anchor and cannot stand alone
  without it. Restore the indexer code AND raise the regression
  as a red-team-closure incident.
- **VULN-03 anchor regression**
  (`oracle/cluster/drift_detector.py` missing or
  `VELOCITY_THRESHOLD = 0.20` / `DRIFT_REASON_VELOCITY`
  removed): the cluster's per-epoch velocity gate has been
  removed. CATASTROPHIC regression — ILS-3's per-epoch sub-pin
  is calibrated as a quarter of the cluster's velocity
  threshold; without the cluster anchor, ILS-3 cannot catch the
  fast lane. Restore the cluster code AND raise the regression
  as a red-team-closure incident.

### After every fix

```bash
python3 audit/inflate_score_check.py --json /tmp/ils.json && echo PASS
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest audit/test_inflate_score_check.py -v
```

Both MUST be green before the PR is mergeable.

---

## Runtime fire — ILS-1 `BaselineRotationRefusedError` on baseline rotation

### Triage (60s)

```bash
# Off-chain baseline-rotation coordinator side:
# The exception's .report carries:
#   - status (REFUSED), reasons (tuple of reason codes)
#   - proposed_epoch, last_recorded_epoch, current_epoch
#   - epoch_delta (proposed - last_recorded)
#   - cosigner_count, distinct_cosigner_count
# Each reason is one of:
#   ['BASELINE_ROTATION_TOO_SOON',
#    'BASELINE_INSUFFICIENT_COSIGNERS',
#    'BASELINE_AGENT_MISSING_FROM_COSIGNERS',
#    'BASELINE_DUPLICATE_COSIGNER',
#    'BASELINE_EPOCH_NOT_MONOTONIC',
#    'BASELINE_EPOCH_IN_FUTURE',
#    'BASELINE_EPOCH_INVALID']
```

### Action

The off-chain coordinator REFUSED to broadcast the baseline-rotation
tx. This is the 2a-residual fingerprint (an attempt to rotate an
agent's baseline outside the cadence + cosigner contract). The fix
depends on the reason:

1. **`BASELINE_ROTATION_TOO_SOON` and `epoch_delta < 30`**: the
   rotation is faster than the 30-epoch cadence floor (2.5 days
   per agent). TWO possibilities:
   - **The operator legitimately needs to rotate**: wait until
     `last_recorded_epoch + 30 ≤ current_epoch`. The 30-epoch
     floor is calibrated against the operator's quarterly
     budget (12 rotations/quarter) — within budget if you wait.
   - **The proposal is malicious or accidental**: a compromised
     coordinator is grinding the baseline up. Investigate WHO
     constructed the proposal (which cluster key signed); page
     security. DO NOT lower
     `MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS` to push through.
2. **`BASELINE_INSUFFICIENT_COSIGNERS` and `distinct_cosigner_
   count < 2`**: the rotation is solo-signed by a single
   cluster key. The exact VULN-06-residual attack shape. The
   cluster must co-attest WITH THE AGENT before this rotation
   can be broadcast. If the agent is unreachable, the rotation
   cannot proceed — the agent's wallet is the non-negotiable
   second signature.
3. **`BASELINE_AGENT_MISSING_FROM_COSIGNERS`**: the cosigners
   tuple has 2+ signatures but the agent's wallet is NOT
   among them. This is structurally identical to a solo cluster
   rotation — the agent has not consented. Add the agent's
   signature OR investigate why the off-chain coordinator
   omitted it.
4. **`BASELINE_DUPLICATE_COSIGNER`**: the cosigners tuple
   contains the same pubkey twice. Either a copy-paste error
   in the proposal or an attacker attempting to inflate the
   distinct-cosigner count. Deduplicate and re-attempt; if
   suspicious, page security.
5. **`BASELINE_EPOCH_NOT_MONOTONIC`**: `proposed_epoch ≤
   last_recorded_epoch`. The on-chain anchor would also refuse
   this; ILS-1 catches it pre-broadcast. Coordinator error —
   fix the proposal upstream.
6. **`BASELINE_EPOCH_IN_FUTURE`**: `proposed_epoch >
   current_epoch + 1`. Time-travel attempt. Investigate the
   coordinator's clock source; do NOT raise
   `BASELINE_FUTURE_TOLERANCE_EPOCHS` to "let it through".
7. **`BASELINE_EPOCH_INVALID`**: `proposed_epoch == 0`. The
   bootstrap sentinel is reserved. Fix the proposal upstream.

DO NOT raise `MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS`, lower
`MIN_BASELINE_COSIGNERS`, or remove the agent-cosigner check in
response to a fire. Each pin is load-bearing and neutralising any
one of them re-opens 2a's substrate.

---

## Runtime fire — ILS-2 `FeatureCorroborationError` on aggregation

### Triage (60s)

```bash
# Feature-aggregator side:
# The exception's .report carries:
#   - status (REFUSED), reasons (tuple of reason codes)
#   - producer_count, distinct producer pubkeys
#   - dominance_ratio, dominant_producer
#   - stale_record_count, future_record_count
# Each reason is one of:
#   ['TOO_FEW_PRODUCERS',
#    'PRODUCER_OVER_DOMINANCE',
#    'RECORDS_TOO_STALE',
#    'RECORD_TIMESTAMP_IN_FUTURE',
#    'NO_RECORDS']
```

### Action

The feature aggregator REFUSED to ship the aggregation. This is
the 2b-residual fingerprint (an aggregation whose producer set is
too narrow to corroborate, too dominated by one producer, or
contains stale / future-dated records). The fix depends on the
reason:

1. **`TOO_FEW_PRODUCERS` and `producer_count < 2`**: only one
   distinct producer pubkey signed the records in the
   aggregation. TWO possibilities:
   - **A legitimate producer-fleet outage**: the indexer fleet
     is degraded and only one producer is online. The cluster
     should NOT publish a corroborated aggregation against
     uncorroborated data. Wait for the fleet to recover; do NOT
     lower `MIN_DISTINCT_PRODUCERS_PER_AGGREGATION`.
   - **A compromised producer key stamping 100% of records**:
     the exact VULN-07-residual attack shape. Investigate the
     producer pubkey (rotate it out of `TrustedProducerSet`
     immediately) and page security.
2. **`PRODUCER_OVER_DOMINANCE` and `dominance_ratio > 0.7`**:
   the most-frequent producer supplied more than 70% of the
   records. Investigate `dominant_producer`: if it is a known
   high-throughput producer (legitimate cluster topology),
   the cluster's load balancer is misconfigured — fix
   upstream. If the dominant producer is unexpected, treat as
   a compromised-key signal and rotate the trusted set.
3. **`RECORDS_TOO_STALE` and `stale_record_count > 0`**: at
   least one record is more than 24h old. TWO possibilities:
   - **A legitimate ingest lag**: the indexer pipeline has
     fallen behind. Catch up the indexer; the freshness floor
     is unforgiving on purpose.
   - **A backfill attempt with a since-decommissioned key**:
     investigate the producer pubkey of the stale records — if
     it has been rotated out of `TrustedProducerSet` recently,
     this is the audit's exact backfill-attack shape. Page
     security.
4. **`RECORD_TIMESTAMP_IN_FUTURE` and `future_record_count >
   0`**: a record's `produced_unix` is more than 60s ahead of
   `current_unix`. Either an indexer clock drift (sync NTP) or
   a time-travel attempt to evade the freshness floor.
   Investigate the producer pubkey; do NOT raise
   `RECORD_FUTURE_TOLERANCE_SECONDS`.
5. **`NO_RECORDS`**: the aggregation is empty. The feature
   pipeline has produced nothing for this agent in the
   current window. Investigate upstream — this is rarely an
   attack but always an alarm.

DO NOT raise `MAX_PRODUCER_DOMINANCE_RATIO`, lower
`MIN_DISTINCT_PRODUCERS_PER_AGGREGATION`, or raise
`MAX_RECORD_AGE_SECONDS` in response to a fire. Each pin is
load-bearing.

---

## Runtime fire — ILS-3 `ScoreDriftCeilingError` on trajectory publish

### Triage (60s)

```bash
# Score-formation pipeline side:
# The exception's .report carries:
#   - status (REFUSED), reasons (tuple of reason codes)
#   - peak_ratio (max (score - baseline) / baseline observed)
#   - peak_epoch (epoch where peak_ratio occurred)
#   - longest_monotonic_run
#   - over_per_epoch_epochs (tuple of epochs whose per-epoch
#     delta exceeded the sub-pin)
#   - baseline_score, current_epoch
# Each reason is one of:
#   ['DRIFT_OVER_CUMULATIVE_CEILING',
#    'DRIFT_OVER_PER_EPOCH_CEILING',
#    'DRIFT_MONOTONIC_TOO_LONG',
#    'DRIFT_BASELINE_NON_POSITIVE',
#    'DRIFT_HISTORY_EMPTY',
#    'DRIFT_EPOCH_NOT_MONOTONIC',
#    'DRIFT_EPOCH_IN_FUTURE']
```

### Action

The score-formation pipeline REFUSED to publish the trajectory.
This is the 2c-residual fingerprint (sub-velocity drips that
compound into a 30%+ inflation, or a per-epoch jump just under
the cluster's velocity gate but over ILS-3's sub-pin, or a
monotonic run too long to be legitimate). The fix depends on the
reason:

1. **`DRIFT_OVER_CUMULATIVE_CEILING` and `peak_ratio > 0.30`**:
   the agent's score has drifted more than 30% above baseline.
   TWO possibilities:
   - **Legitimate score growth**: the agent has genuinely
     improved and now warrants a NEW BASELINE. The correct
     response is to ROTATE the baseline via the ILS-1
     gate — propose a fresh `BaselineRotationProposal` with
     `proposed_epoch = current_epoch` and the agent + 1
     cluster cosigner. After the rotation, the score is once
     again within the 30% drift window of the new baseline.
     DO NOT raise `MAX_DRIFT_FROM_BASELINE_RATIO` — the 30%
     ceiling is the contract DeFi consumers depend on.
   - **An inflation attack**: the cumulative drift fired but
     the score growth is not justified by feature-level
     evidence. Investigate the trajectory in
     `over_per_epoch_epochs` (which epochs accumulated the
     drift) and cross-check against feature-corroboration
     (ILS-2): if the aggregation that produced each up-step
     came from a narrow producer set, this is the audit's
     exact slow-drift attack. Page security.
2. **`DRIFT_OVER_PER_EPOCH_CEILING` and an epoch in
   `over_per_epoch_epochs`**: a per-epoch delta exceeded
   5%. This is the slow-lane catch — the cluster's velocity
   gate (0.20) would let it pass, but ILS-3 refuses. Same
   investigation as cumulative: was the up-step justified by
   the feature aggregation? If yes, rotate the baseline; if no,
   page security.
3. **`DRIFT_MONOTONIC_TOO_LONG` and `longest_monotonic_run >
   10`**: the agent's score went up for more than 10
   consecutive epochs without a single down-step. Legitimate
   score growth almost always has tiny pull-back epochs from
   noise; a 10+-epoch monotonic run is the fingerprint of
   carefully-shaped drips. Same investigation; if the run is
   genuinely organic, rotate the baseline.
4. **`DRIFT_BASELINE_NON_POSITIVE`**: `baseline_score <= 0`.
   The agent's baseline is uninitialised or corrupted. The
   ratio is undefined — re-initialise the baseline via the
   ILS-1 gate before publishing trajectories.
5. **`DRIFT_HISTORY_EMPTY`**: the trajectory has zero
   history entries. The score-formation pipeline produced
   nothing this epoch — investigate upstream; rarely an
   attack but always an alarm.
6. **`DRIFT_EPOCH_NOT_MONOTONIC`**: history epochs are not
   in increasing order. Pipeline bug — fix upstream.
7. **`DRIFT_EPOCH_IN_FUTURE`**: an entry's epoch is more
   than 1 ahead of `current_epoch`. Time-travel attempt;
   investigate the pipeline's clock source.

DO NOT raise `MAX_DRIFT_FROM_BASELINE_RATIO`,
`MAX_DRIFT_PER_EPOCH_RATIO`, or `MAX_MONOTONIC_DRIFT_EPOCHS`
in response to a fire. Each pin is load-bearing and they are
calibrated jointly — moving one without the others breaks the
"per-epoch × monotonic ≫ cumulative" invariant that ensures the
cumulative ceiling fires first.

The correct response to legitimate score growth above the 30%
ceiling is to ROTATE THE BASELINE via ILS-1, not to widen the
drift contract.

---

## Verifying the response

After every fix, re-run the gate and tests locally:

```bash
python3 audit/inflate_score_check.py --json /tmp/ils.json && echo PASS
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest audit/test_inflate_score_check.py -v
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest \
    phylanx-oracle/tests/oracle/test_ils1_baseline_rotation_guard.py \
    phylanx-oracle/tests/oracle/test_ils2_feature_corroboration.py \
    phylanx-oracle/tests/oracle/test_ils3_score_drift_ceiling.py -v
```

All three MUST be green before the PR is mergeable. For a runtime
fire, the additional bar is that the operator has documented the
root cause of the residual state (too-soon rotation, compromised
producer, slow-drift attack) in the incident channel — the gate is
the alarm, not the diagnosis.
