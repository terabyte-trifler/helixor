# Runbook — Forge High-Score Cert mitigation response

**Severity:** Critical (any FHS gate red means a mitigation against
red-team Path 1 — "Forge High-Score Cert" — has either been removed
from the tree or fired at runtime).
**Triggers:**
- `audit/forge_high_score_check.py` gate fails in CI.
- Cluster-boot / cluster-rotation coordinator raises
  `KeyRotationOverdueError` (FHS-1) refusing to operate with overdue
  keys.
- Certificate-issuance path raises `SignerProvenanceError` (FHS-2)
  refusing a threshold set whose K signatures share a physical host
  or violate the per-region cap.
- Off-chain rotation coordinator raises `RotationOverlapError`
  (FHS-3) refusing to broadcast a propose-rotation tx that would
  replace more than one cluster key in one ceremony.

## What's happening

The Forge High-Score Cert path (red-team Path 1) is the three-
sub-leaf drain in which an attacker mints a forged GREEN cert and
uses it to drain a DeFi protocol integrated with Phylanx:

  1a. Compromise 3 oracle keys                          [HIGH EFFORT]
  1b. Exploit VULN-01 (signature verification bypass)   [MEDIUM EFFORT]
  1c. Exploit VULN-13 (replace all oracle keys)         [HIGH EFFORT]

K-of-N already makes 1a hard per-compromise, on-chain
`verify_threshold_signatures` + `expected_digest` filtering closes
1b's signature bypass, and the 48h propose / attest / enact
ceremony closes 1c's wholesale replacement. What was missing
pre-FHS was the TIME dimension — a compromised key with permanent
validity (1a residual), a threshold set with no per-host
attestation (1b residual), and a rotation ceremony that could
wholesale-replace the cluster in one shot (1c residual). The three
mitigations in `launch/design/forge_high_score_resolution.md`
close those residuals; this runbook is the playbook for reacting
when one of them fires or regresses.

The two failure shapes need different responses:

- **CI gate red** — a refactor has REMOVED a mitigation. The code
  is not yet on mainnet. Block the merge and restore the anchor.
  DO NOT weaken the gate to make CI green.
- **Runtime fire** — the mitigation engaged and refused to act
  against an overdue key set, a same-host threshold set, or a
  wholesale-rotation proposal. Mainnet is protected; the cluster
  is genuinely in one of the residual-attack states. Investigate
  the cluster-key substrate (NOT the FHS floor) before resuming.

---

## CI gate red — `audit/forge_high_score_check.py` failed

### Triage (60s)

```bash
# 1. Run the gate locally to see which FHS family regressed.
python3 audit/forge_high_score_check.py --json /tmp/fhs.json
cat /tmp/fhs.json | python3 -m json.tool | head -80

# 2. Each finding names the rule and the marker string the gate
#    could not find. The FHS-N tag tells you which family
#    regressed.
```

### Decision tree

- **Marker file deleted** (`key_rotation_cadence.py`,
  `signer_provenance.py`, `rotation_overlap_guard.py`): the closing
  PR removed a mitigation the red-team closure assumes is present.
  RESTORE the file from `main`. The reviewer who approved the
  removal must justify the change in writing on the PR.
- **`verify_*` / `enforce_*` function disappeared**: a contract
  entry point is gone. Restore it. If the function was genuinely
  renamed in good faith, the audit gate's expected marker MUST be
  updated IN THE SAME PR and the PR description must call out the
  Forge-High-Score-Cert closure impact.
- **FHS-1 threshold changed** (`MAX_KEY_AGE_SECONDS`,
  `WARN_KEY_AGE_SECONDS`): a load-bearing cluster-key cadence
  floor moved. Restore the pinned value. The 60d / 90d cascade is
  calibrated against the NIST SP 800-57 cryptoperiod ceiling for
  high-impact signing keys and against the operator's expected
  ceremony cadence — the 30-day WARN window exists precisely so a
  missed ceremony does not produce an outage. Tightening below 60d
  / 90d false-fires; loosening past 90d re-opens 1a's dwell-time
  residual. If the cadence itself genuinely moves (e.g. devnet
  retunes for accelerated testing), update the audit gate's
  expected constants AND the per-module property tests
  IN THE SAME PR with the new cadence rationale on the PR
  description.
- **FHS-1 status-label regression** (`CADENCE_OK` / `CADENCE_WARN`
  / `CADENCE_OVERDUE`): the operator dashboards and alerting greps
  key off the literal status strings. Restore the constants. Never
  rename them — renaming silently breaks every operator's alert
  routing.
- **FHS-2 threshold changed** (`MAX_SIGNERS_PER_HOST`,
  `MAX_SIGNERS_PER_REGION`, `MIN_DISTINCT_HOSTS`): a load-bearing
  per-signer provenance floor moved. Restore the pinned value.
  CRITICAL CHECKS:
  - `MAX_SIGNERS_PER_HOST = 1` is non-negotiable — raising it to
    2 re-opens 1b's residual (one physical machine running two
    cluster HSMs both count toward the threshold). This pin is
    NEVER tunable.
  - `MAX_SIGNERS_PER_REGION = 2` must mirror NSS-1's per-cloud
    cap (`N - K = 5 - 3 = 2` for the canonical 3-of-5 cluster).
    The two are calibrated in lockstep — if NSS-1's per-cloud cap
    is retuned (e.g. the cluster grows to 5-of-9), FHS-2's
    per-region cap must move in step in the SAME PR.
  - `MIN_DISTINCT_HOSTS = 3` must equal K (the threshold). If K
    moves, this constant moves with it.
- **FHS-3 threshold changed** (`MAX_KEYS_REPLACED_PER_ROTATION =
  1`): the per-ceremony cap moved. RESTORE to 1. This pin is the
  load-bearing contract of the entire FHS-3 module — raising it
  to 2 lets an attacker with K=3 compromised keys replace the
  cluster in two ceremonies (96 hours of public on-chain
  activity), raising it to 5 re-opens 1c's wholesale-replacement
  attack entirely. NEVER tune this without an explicit red-team
  closure review.
- **FHS-3 status / reason label regression**
  (`OVERLAP_OK` / `OVERLAP_REFUSED`,
  `REASON_WHOLESALE_REPLACEMENT`,
  `REASON_INSUFFICIENT_OVERLAP`): the off-chain rotation
  coordinator and runbook greps key off these literals. Restore
  them; never rename.
- **VULN-01 anchor regression** (`certificate-issuer/src/signing.rs`
  missing or `pub fn verify_threshold_signatures` /
  `expected_digest` deleted): the on-chain threshold-signature
  verifier has been removed. This is a CATASTROPHIC regression —
  FHS-2 stands on top of this anchor and cannot stand alone.
  Restore the on-chain code AND raise the regression as a
  red-team-closure incident (the closing PR has fundamentally
  weakened Path 1's substrate).
- **VULN-13 anchor regression**
  (`pending_oracle_rotation.rs` missing or
  `MIN_TIMELOCK_SECONDS = 48 * 60 * 60` deleted): the on-chain
  48h rotation timelock has been lowered or removed. CATASTROPHIC
  regression — FHS-3 is the off-chain pre-flight and cannot stand
  alone without the on-chain timelock. Restore the on-chain code
  AND raise the regression as a red-team-closure incident.

### After every fix

```bash
python3 audit/forge_high_score_check.py --json /tmp/fhs.json && echo PASS
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest audit/test_forge_high_score_check.py -v
```

Both MUST be green before the PR is mergeable.

---

## Runtime fire — FHS-1 `KeyRotationOverdueError` on cluster boot

### Triage (60s)

```bash
# Cluster-bootstrap / aggregator side:
# The exception's .report carries:
#   - verdicts (per-key: pubkey, age_seconds, status, reasons)
#   - overdue_keys (tuple of pubkeys past MAX_KEY_AGE_SECONDS)
#   - warning_keys (tuple of pubkeys past WARN_KEY_AGE_SECONDS)
#   - max_age_seconds (90 * 24 * 3600)
#   - warn_seconds (60 * 24 * 3600)
# Each verdict's reasons include one of:
#   ['KEY_NEAR_ROTATION_FLOOR',
#    'KEY_PAST_ROTATION_FLOOR',
#    'KEY_BIRTH_IN_FUTURE']
```

### Action

The cluster REFUSED to operate because at least one cluster key has
aged past `MAX_KEY_AGE_SECONDS = 90 days`. This is the 1a-residual
fingerprint (a compromised key dwelling silently while the cluster
operates normally). The cluster is protected — no new threshold
signature is produced against an overdue key. The fix depends on
the substrate of the overdue state:

1. **One key OVERDUE, the others OK or WARN**: a single key is
   past the 90d floor. The cluster operator should immediately
   schedule a 1-key rotation ceremony via FHS-3 (which itself
   forces at-most-one-key-per-ceremony). The 48h on-chain timelock
   begins on `propose`; the cluster will be back to all-OK after
   the enact step. DO NOT lower `MAX_KEY_AGE_SECONDS` to push
   traffic through; the floor is calibrated against the NIST SP
   800-57 cryptoperiod ceiling and lowering it neutralises FHS-1.
2. **Multiple keys OVERDUE simultaneously**: the cluster has
   missed multiple rotation ceremonies. FHS-3 forces sequential
   rotation (max 1 key per ceremony × 48h timelock = 48h per
   rotation), so rotating M overdue keys takes M × 48h of
   on-chain activity. This is by design — wholesale replacement
   is exactly the 1c attack. Page the cluster on-call; the
   priority is the OLDEST key first (rotate by descending
   `age_seconds`). The other overdue keys remain blocked until
   each is rotated in turn. The operator runbook for the
   ceremony itself lives in the cluster ops handbook (out of
   scope for this runbook).
3. **`reasons` includes `KEY_BIRTH_IN_FUTURE`**: a key's
   `birth_unix` is past the 60s tolerance into the future.
   Either the cluster bootstrap recorded a future-dated key
   (clock skew at bootstrap) or the key birth field has been
   tampered with. Investigate IMMEDIATELY — a future-dated key
   that escapes detection effectively has infinite calendar
   life. Do NOT raise `CADENCE_FUTURE_TOLERANCE_SECONDS` to
   "let the cluster boot"; the time-travel refusal is the
   correct behaviour.

DO NOT raise `MAX_KEY_AGE_SECONDS` or `WARN_KEY_AGE_SECONDS` to
keep the cluster running past the floor. The whole point of FHS-1
is to refuse exactly this state — neutralising the floor re-opens
1a's dwell-time residual.

---

## Runtime fire — FHS-2 `SignerProvenanceError` on certificate-issuance

### Triage (60s)

```bash
# Certificate-issuance / aggregator side:
# The exception's .report carries:
#   - distinct_hosts (count)
#   - over_host_cap_hosts (tuple of host_ids with > 1 signer)
#   - over_region_cap_regions (tuple of regions with > 2 signers)
#   - missing_attestation (tuple of pubkeys with empty host/region)
#   - reasons: ['SIGNERS_SHARE_HOST',
#               'SIGNERS_OVER_REGION_CAP',
#               'INSUFFICIENT_DISTINCT_HOSTS',
#               'MISSING_ATTESTATION']
```

### Action

The certificate-issuance path REFUSED to mint a cert because the
attached threshold-signature set violates one of the per-signer
provenance caps. This is the 1b-residual fingerprint (a single
physical host or cloud region producing K of the K signatures).
The fix depends on the reason:

1. **`SIGNERS_SHARE_HOST` and a host_id in `over_host_cap_hosts`**:
   two cluster signers share a physical host fingerprint
   (machine serial + TPM measurement). The audit's exact attack
   shape: one machine running two HSMs. INVESTIGATE the
   compromised host IMMEDIATELY — either the cluster has been
   misconfigured (operator deployed two HSMs on one bare-metal
   box) or a host has been compromised and is running an
   unauthorized second cluster signer. The cluster on-call must
   evict the offending HSM and rotate the affected key via
   FHS-3 ceremony BEFORE the cluster can resume cert issuance.
   DO NOT raise `MAX_SIGNERS_PER_HOST` above 1 to "let traffic
   through".
2. **`SIGNERS_OVER_REGION_CAP` and a region in
   `over_region_cap_regions`**: three or more cluster signers
   are in the same `provider:zone`. This indicates NSS-1's
   per-cloud cap has slipped (or a node has migrated regions
   without bootcheck noticing). The cluster on-call must
   redeploy at least one node out of the overloaded region
   BEFORE the cluster can resume cert issuance. The 2-cap is
   calibrated against the canonical 3-of-5 cluster's `N - K =
   2`; for a 5-of-9 cluster the cap would be 4 — but the
   constant must be retuned in lockstep with NSS-1 (see CI
   section above).
3. **`INSUFFICIENT_DISTINCT_HOSTS` and `distinct_hosts < 3`**:
   the threshold set comes from fewer than K distinct hosts.
   The cluster has lost host diversity below the threshold
   floor; this is structurally identical to a `CLUSTER_BELOW_
   QUORUM` SOL-1 signal but from a different substrate. Page
   the cluster on-call; the cluster cannot mint a forged or
   honest cert until at least K distinct hosts are back online.
4. **`MISSING_ATTESTATION` and a pubkey in
   `missing_attestation`**: a cluster signer is missing its
   `host_id` or `cloud_region` attestation. Either the cluster
   bootstrap was incomplete (the cluster operator forgot to
   record the attestation) or the attestation field has been
   tampered with. Investigate before re-attempting; do NOT
   default the missing field to a synthetic value.

DO NOT raise `MAX_SIGNERS_PER_HOST`, `MAX_SIGNERS_PER_REGION`, or
lower `MIN_DISTINCT_HOSTS` in response to a fire. Each pin is
load-bearing and neutralising any one of them re-opens a residual
substrate of 1b.

---

## Runtime fire — FHS-3 `RotationOverlapError` on rotation coordinator

### Triage (60s)

```bash
# Off-chain rotation coordinator side (BEFORE the propose tx is
# broadcast):
# The exception's .report carries:
#   - current_size, proposed_size
#   - overlap_size, replaced_size, added_size
#   - keys_removed (sorted tuple)
#   - keys_added (sorted tuple)
#   - required_overlap (= max(threshold - 1, 0))
#   - threshold (echoed)
#   - reasons: ['WHOLESALE_REPLACEMENT',
#               'INSUFFICIENT_OVERLAP',
#               'NEW_KEYS_DUPLICATE',
#               'NEW_KEYS_EMPTY',
#               'THRESHOLD_INVALID']
```

### Action

The off-chain coordinator REFUSED to broadcast the propose-rotation
transaction. The whole point of FHS-3 is to catch this BEFORE the
48h on-chain timelock begins — refusing here saves the cluster two
days of waiting on a proposal that honest attesters would reject
anyway. The fix depends on the reason:

1. **`WHOLESALE_REPLACEMENT` and `replaced_size > 1`**: the
   proposal would replace more than one cluster key in one
   ceremony. This is the EXACT 1c-residual attack shape. TWO
   possibilities:
   - **The operator legitimately wants to rotate multiple keys**
     (e.g. catching up after a long pause). The correct response
     is to SPLIT the proposal: rotate ONE key at a time, waiting
     48h between each ceremony. Total clock time for an M-key
     rotation = M × 48h. This is by design — every ceremony is
     attestable by the still-honest remaining keys, giving the
     cluster an explicit refusal point per key.
   - **The proposal is malicious or accidental**: the propose-
     rotation tx was constructed by a compromised coordinator or
     by an operator who did not understand the contract.
     Investigate `keys_removed` and `keys_added` to see exactly
     which keys are being swapped; if any of the `keys_removed`
     are still in active use AND were not flagged OVERDUE by
     FHS-1, the proposal is suspicious. Page security.
2. **`INSUFFICIENT_OVERLAP` and `overlap_size < required_overlap`**:
   the intersection of current and proposed key sets is below
   `max(threshold - 1, 0)`. For a 3-of-5 cluster this means
   `overlap < 2`; for a 5-of-9 cluster this means `overlap < 4`.
   Same root cause as WHOLESALE_REPLACEMENT — the proposal
   removes too many keys at once. Same fix: split into multiple
   sequential ceremonies.
3. **`NEW_KEYS_DUPLICATE`**: the proposed key set contains a
   duplicate pubkey. The on-chain handler would also reject
   this, but FHS-3 catches it before the 48h timelock begins.
   The coordinator deduplicated incorrectly or a copy-paste
   error introduced a duplicate. Fix the proposal upstream.
4. **`NEW_KEYS_EMPTY`**: the proposal would set the cluster's
   key set to empty. This would leave the cluster with no
   signing capability at all. Catastrophic operator error;
   abort the ceremony and re-construct the proposal.
5. **`THRESHOLD_INVALID` and `threshold <= 0`**: the proposal
   pins an invalid K. Same as `NEW_KEYS_EMPTY` — catastrophic
   operator error; abort.

DO NOT raise `MAX_KEYS_REPLACED_PER_ROTATION` above 1 to push a
multi-key swap through. The 1-per-ceremony cap is the entire
load-bearing contract of FHS-3 — neutralising it re-opens 1c's
wholesale-replacement attack.

The off-chain pre-flight is BEFORE the on-chain anchor. If the
operator somehow bypasses FHS-3 (e.g. signs the propose tx
directly), the on-chain `pending_oracle_rotation.rs` still runs
the 48h timelock — but the proposal has burned 48h before the
honest attesters reject it. FHS-3 saves that 48h burn.

---

## Verifying the response

After every fix, re-run the gate and tests locally:

```bash
python3 audit/forge_high_score_check.py --json /tmp/fhs.json && echo PASS
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest audit/test_forge_high_score_check.py -v
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest \
    phylanx-oracle/tests/oracle/test_fhs1_key_rotation_cadence.py \
    phylanx-oracle/tests/oracle/test_fhs2_signer_provenance.py \
    phylanx-oracle/tests/oracle/test_fhs3_rotation_overlap_guard.py -v
```

All three MUST be green before the PR is mergeable. For a runtime
fire, the additional bar is that the cluster operator has
documented the root cause of the residual state (overdue ceremony,
compromised host, wholesale-rotation attempt) in the incident
channel — the gate is the alarm, not the diagnosis.
