# Runbook — Freeze Cert at High Score mitigation response

**Severity:** Critical (any FRP gate red means a mitigation against
red-team Path 3 — "Freeze Cert at High Score" — has either been
removed from the tree or fired at runtime).
**Triggers:**
- `audit/freeze_cert_check.py` gate fails in CI.
- Cert-issuance coordinator raises
  `ClusterParticipationFloorError` (FRP-1) refusing to mint a cert
  when the cluster's trailing run of barely-quorate rounds exceeds
  the cap.
- Cert-issuance coordinator raises `EpochAdvanceStallError`
  (FRP-2) refusing to mint a cert when the cluster's epoch has
  not advanced within 36 hours.
- High-tier cert-vouching path raises `CertReissueCadenceError`
  (FRP-3) refusing to declare an agent's cert valid for high-tier
  consumer operations when the cluster has not reissued it within
  4 hours.

## What's happening

The Freeze Cert at High Score path (red-team Path 3) is the three-
sub-leaf drain in which an attacker stalls the cluster's
LIVENESS — not its signing authority (Path 1) nor its
score-formation pipeline (Path 2) — and uses the frozen cert to
drain a DeFi protocol integrated with Helixor:

  3a. Exploit VULN-05 (commit-reveal block)             [LOW EFFORT]
  3b. Exploit VULN-02 (epoch advancement freeze)        [MEDIUM EFFORT]
  3c. Target DeFi protocol that doesn't check cert
      freshness                                         [LOW EFFORT]

The cluster-side `submit_reveal` + `non_revealers` +
`reveal_deadline` + `min_reveals` machinery enforces the per-round
commit-reveal contract (3a), the on-chain `verify_cluster_threshold`
+ `consensus_threshold` + `InsufficientAdvanceAttestations`
machinery enforces M-of-N attestations per advance and AW-02
provides Tier-2 fallback at 2× duration (3b), and the on-chain
`MAX_AGE_SECONDS = 48 * 60 * 60` + `is_fresh_default` ceiling caps
cert freshness for consumers that ask (3c). What was missing
pre-FRP was the CLUSTER-side refusal to KEEP MINTING new certs
against a stalled substrate — the residuals where the cluster is
degraded but the on-chain ceiling has not yet fired. The three
mitigations in `launch/design/freeze_cert_resolution.md` close
those residuals; this runbook is the playbook for reacting when
one of them fires or regresses.

The two failure shapes need different responses:

- **CI gate red** — a refactor has REMOVED a mitigation. The code
  is not yet on mainnet. Block the merge and restore the anchor.
  DO NOT weaken the gate to make CI green.
- **Runtime fire** — the mitigation engaged and refused to issue
  a cert (or declare one valid). Mainnet is protected; the cluster
  itself is in a degraded state OR an attack is in flight.
  Investigate the cluster's liveness substrate (NOT the FRP
  floor) before resuming.

---

## CI gate red — `audit/freeze_cert_check.py` failed

### Triage (60s)

```bash
# 1. Run the gate locally to see which FRP family regressed.
python3 audit/freeze_cert_check.py --json /tmp/frp.json
cat /tmp/frp.json | python3 -m json.tool | head -80

# 2. Each finding names the rule and the marker string the gate
#    could not find. The FRP-N tag tells you which family
#    regressed.
```

### Decision tree

- **Marker file deleted** (`cluster_participation_floor.py`,
  `epoch_advance_liveness.py`, `cert_reissue_cadence.py`): the
  closing PR removed a mitigation the red-team closure assumes is
  present. RESTORE the file from `main`. The reviewer who
  approved the removal must justify the change in writing on the
  PR.
- **`verify_*` / `enforce_*` function disappeared**: a contract
  entry point is gone. Restore it. If the function was genuinely
  renamed in good faith, the audit gate's expected marker MUST be
  updated IN THE SAME PR and the PR description must call out the
  Freeze-Cert-at-High-Score closure impact.
- **FRP-1 threshold changed**
  (`MIN_HEALTHY_PARTICIPATION_RATIO`,
  `MAX_BARELY_QUORATE_ROUNDS`, `BARELY_QUORATE_MARGIN`,
  `PARTICIPATION_FUTURE_TOLERANCE_EPOCHS`): a load-bearing
  participation contract moved. Restore the pinned value.
  CRITICAL CHECKS:
  - `MIN_HEALTHY_PARTICIPATION_RATIO = 0.8` is the participation
    floor. With N=5/K=3 this is 4-of-5 (single tolerated outage).
    Lowering past 0.8 re-opens 3a's bare-quorum residual; raising
    past 0.8 false-fires on legitimate single-node restarts.
  - `MAX_BARELY_QUORATE_ROUNDS = 3` is the trailing-run cap.
    Raising past 3 lets a sustained-withholding attack mint more
    certs before refusal; lowering false-fires on rolling
    upgrades and partition repairs.
  - `BARELY_QUORATE_MARGIN = 1` defines what counts as "barely
    quorate" (`participating <= quorum + 1`). Raising past 1
    widens the alarm to include healthy rounds; lowering to 0
    only fires at exact-quorum and misses the `quorum + 1`
    fingerprint.
- **FRP-1 status / reason label regression** (`PARTICIPATION_OK`
  / `PARTICIPATION_REFUSED`,
  `PARTICIPATION_BARELY_QUORATE_TOO_LONG`,
  `PARTICIPATION_BELOW_HEALTHY_FLOOR`,
  `PARTICIPATION_EPOCH_NOT_MONOTONIC`,
  `PARTICIPATION_EPOCH_IN_FUTURE`,
  `PARTICIPATION_HISTORY_EMPTY`,
  `PARTICIPATION_INVALID_QUORUM`): operator dashboards and the
  cert-issuance coordinator grep these literals. Restore them;
  never rename.
- **FRP-2 threshold changed**
  (`MAX_EPOCH_ADVANCE_STALL_SECONDS`,
  `EXPECTED_EPOCH_DURATION_SECONDS`,
  `EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS`): a load-bearing
  epoch-advance liveness contract moved. Restore the pinned
  value. CRITICAL CHECKS:
  - `MAX_EPOCH_ADVANCE_STALL_SECONDS = 36 * 3600` is the
    1.5×-cycle stall floor. AW-02's Tier-2 fallback opens at
    2× duration (48h); raising FRP-2 past 36h erodes the gap
    before Tier-2 engages; lowering false-fires on legitimate
    devnet outages (~28h historical max).
  - `EXPECTED_EPOCH_DURATION_SECONDS = 24 * 3600` is the MIRROR
    of on-chain `DEFAULT_DURATION_SECONDS = 86_400`. NEVER move
    one without the other — the audit gate cross-checks them
    and lights red on drift.
  - `EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS = 60` is the
    clock-skew tolerance. Never raise — a wider future window
    lets an attacker time-stamp advances to evade the stall
    detector.
- **FRP-2 status / reason label regression**
  (`EPOCH_ADVANCE_OK` / `EPOCH_ADVANCE_REFUSED`,
  `EPOCH_ADVANCE_STALL`, `EPOCH_ADVANCE_TIMESTAMP_INVALID`,
  `EPOCH_ADVANCE_TIMESTAMP_IN_FUTURE`,
  `EPOCH_ADVANCE_EPOCH_INVALID`,
  `EPOCH_ADVANCE_EPOCH_NOT_MONOTONIC`): operator dashboards and
  the cert-issuance coordinator grep these literals. Restore
  them; never rename.
- **FRP-3 threshold changed**
  (`MAX_CERT_REISSUE_INTERVAL_SECONDS`,
  `CERT_REISSUE_FUTURE_TOLERANCE_SECONDS`,
  `TA6_ONCHAIN_MAX_AGE_SECONDS`): a load-bearing reissue cadence
  contract moved. Restore the pinned value. CRITICAL CHECKS:
  - `MAX_CERT_REISSUE_INTERVAL_SECONDS = 4 * 3600` is the
    cluster-side cadence floor. Mirrors SOL-3's LOAN_ISSUE 4h
    freshness floor. Raising past 4h breaks the consumer-side
    expectation that the cluster keeps certs fresh enough for
    LOAN_ISSUE; lowering past 4h burdens the cluster with
    unnecessary work.
  - `TA6_ONCHAIN_MAX_AGE_SECONDS = 48 * 3600` is the on-chain
    TA-6 MIRROR. NEVER move it without also moving
    `health_certificate.rs::MAX_AGE_SECONDS` — the audit gate
    cross-checks the two and the 12× safety-margin calibration
    breaks if they drift apart.
  - `CERT_REISSUE_FUTURE_TOLERANCE_SECONDS = 60` is the
    clock-skew tolerance. Never raise.
- **FRP-3 status / reason label regression** (`CERT_REISSUE_OK`
  / `CERT_REISSUE_REFUSED`, `CERT_REISSUE_OVERDUE`,
  `CERT_REISSUE_TIMESTAMP_IN_FUTURE`,
  `CERT_REISSUE_TIMESTAMP_INVALID`,
  `CERT_REISSUE_AGENT_WALLET_MISSING`): operator dashboards
  grep these literals. Restore them; never rename.
- **VULN-05 anchor regression**
  (`oracle/cluster/commit_reveal_round.py` missing or
  `submit_reveal` / `non_revealers` / `reveal_deadline` /
  `min_reveals` deleted): the cluster-side per-round commit-
  reveal anchor has been removed. CATASTROPHIC regression —
  FRP-1 is the fleet-wide pre-flight and cannot stand alone
  without the per-round defence. Restore the cluster code AND
  raise the regression as a red-team-closure incident.
- **VULN-02 anchor regression**
  (`programs/health-oracle/src/instructions/advance_epoch.rs`
  missing or `verify_cluster_threshold` / `consensus_threshold`
  / `InsufficientAdvanceAttestations` deleted, or
  `epoch_state.rs::DEFAULT_DURATION_SECONDS = 86_400` drift):
  the on-chain advance-attestation anchor has been removed or
  drifted. CATASTROPHIC regression — FRP-2 is the off-chain
  pre-flight and cannot stand alone without the M-of-N
  defence. Restore the on-chain code AND raise the regression
  as a red-team-closure incident.
- **TA-6 anchor regression**
  (`programs/certificate-issuer/src/state/health_certificate.rs`
  missing or `MAX_AGE_SECONDS: i64 = 48 * 60 * 60` /
  `is_fresh_default` removed): the on-chain freshness ceiling
  has been removed. CATASTROPHIC regression — FRP-3's 12×
  safety-margin calibration is broken and the freshness-blind
  consumer residual reopens. Restore the on-chain code AND
  raise the regression as a red-team-closure incident.

### After every fix

```bash
python3 audit/freeze_cert_check.py --json /tmp/frp.json && echo PASS
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest audit/test_freeze_cert_check.py -v
```

Both MUST be green before the PR is mergeable.

---

## Runtime fire — FRP-1 `ClusterParticipationFloorError`

### Triage (60s)

```bash
# Cert-issuance coordinator side:
# The exception's .report carries:
#   - status (REFUSED), reasons (tuple of reason codes)
#   - sample_count, current_epoch
#   - barely_quorate_run, max_barely_quorate_run
#   - healthy_ratio_floor, min_participation_ratio_seen,
#     min_ratio_epoch
# Each reason is one of:
#   ['PARTICIPATION_BARELY_QUORATE_TOO_LONG',
#    'PARTICIPATION_BELOW_HEALTHY_FLOOR',
#    'PARTICIPATION_EPOCH_NOT_MONOTONIC',
#    'PARTICIPATION_EPOCH_IN_FUTURE',
#    'PARTICIPATION_HISTORY_EMPTY',
#    'PARTICIPATION_INVALID_QUORUM']
```

### Action

The cert-issuance coordinator REFUSED to mint the cert. This is
the 3a-residual fingerprint (the cluster has been operating at
bare-quorum participation for too long). The fix depends on the
reason:

1. **`PARTICIPATION_BARELY_QUORATE_TOO_LONG` and
   `barely_quorate_run > 3`**: the cluster has had 4+ consecutive
   rounds where participating_count is at or just above quorum.
   TWO possibilities:
   - **A legitimate sustained outage**: a partition, a multi-
     node restart, a hardware failure. Page the on-call to
     restore healthy participation. DO NOT raise
     `MAX_BARELY_QUORATE_ROUNDS` — the cluster's job during a
     sustained outage is to STOP MINTING certs, not to keep
     minting them.
   - **A VULN-05 withholding attack**: an attacker who has
     compromised K nodes is keeping the cluster pinned at bare
     quorum. Investigate `non_revealers()` strikes across the
     trailing window — the attacker's nodes will be either
     consistently absent OR consistently scraping past
     `min_reveals` by 1-2 reveals. Cross-check identities of the
     consistently-scraping nodes; rotate keys via FHS-1 if
     evidence suggests compromise.
2. **`PARTICIPATION_BELOW_HEALTHY_FLOOR` and
   `min_participation_ratio_seen < 0.8`**: a companion flag to
   `PARTICIPATION_BARELY_QUORATE_TOO_LONG`. Indicates the trailing
   run is dropping BELOW the healthy floor (not just barely-
   quorate). Same investigation as above; the additional signal
   helps disambiguate "one bad round at lower quorum" from
   "sustained low-participation pattern".
3. **`PARTICIPATION_EPOCH_NOT_MONOTONIC`**: history samples are
   out of order. Coordinator bug — fix upstream. If suspicious,
   investigate whether an attacker is injecting forged samples.
4. **`PARTICIPATION_EPOCH_IN_FUTURE`**: a sample's epoch is more
   than 1 ahead of `current_epoch`. Time-travel attempt;
   investigate the coordinator's clock source.
5. **`PARTICIPATION_HISTORY_EMPTY`**: the coordinator has no
   round-level samples to vet. The cluster has not closed any
   rounds in the lookback window — this IS a stall, just on the
   round substrate. Same response as a sustained outage: page
   on-call to recover round liveness.
6. **`PARTICIPATION_INVALID_QUORUM`**: at least one sample has
   `quorum_threshold <= 0` or `total_node_count <= 0`.
   Coordinator bug or attempt to forge a sample with bogus
   topology; fix upstream and investigate.

DO NOT raise `MAX_BARELY_QUORATE_ROUNDS`, lower
`MIN_HEALTHY_PARTICIPATION_RATIO`, or widen `BARELY_QUORATE_MARGIN`
in response to a fire. Each pin is load-bearing and neutralising
any one of them re-opens 3a's substrate.

---

## Runtime fire — FRP-2 `EpochAdvanceStallError`

### Triage (60s)

```bash
# Cert-issuance coordinator side:
# The exception's .report carries:
#   - status (REFUSED), reasons (tuple of reason codes)
#   - seconds_since_last, stall_floor, expected_epoch_duration
#   - epoch_delta (current_epoch - last_advanced_epoch)
#   - current_unix, last_epoch_advance_unix
# Each reason is one of:
#   ['EPOCH_ADVANCE_STALL',
#    'EPOCH_ADVANCE_TIMESTAMP_INVALID',
#    'EPOCH_ADVANCE_TIMESTAMP_IN_FUTURE',
#    'EPOCH_ADVANCE_EPOCH_INVALID',
#    'EPOCH_ADVANCE_EPOCH_NOT_MONOTONIC']
```

### Action

The cert-issuance coordinator REFUSED to mint the cert. This is
the 3b-residual fingerprint (the cluster has not advanced its
epoch in longer than 36 hours). The fix depends on the reason:

1. **`EPOCH_ADVANCE_STALL` and `seconds_since_last > 36*3600`**:
   the cluster has not successfully executed
   `advance_epoch` in 36+ hours. TWO possibilities:
   - **A legitimate sustained outage**: a regional failure or
     a Solana-side incident. The Tier-2 AW-02 fallback engages
     at 48h to recover the cluster's epoch advancement; until
     it does, FRP-2 holds cert issuance closed. DO NOT raise
     `MAX_EPOCH_ADVANCE_STALL_SECONDS` — the cluster's job
     during a sustained outage is to STOP MINTING certs against
     a stalled epoch.
   - **A VULN-02 withholding attack**: an attacker who has
     compromised N-M+1 cluster nodes is withholding advance
     attestations. Investigate which cluster keys are NOT
     signing the most recent advance attempts; cross-check
     against `non_revealers()` strikes from the round substrate.
     Page security and rotate keys via FHS-1 if compromise is
     suspected.
2. **`EPOCH_ADVANCE_TIMESTAMP_INVALID` and
   `last_epoch_advance_unix < 1`**: the cluster is reporting
   `last_epoch_advance_unix = 0` (the bootstrap sentinel). The
   cluster cannot mint certs against an uninitialised epoch
   state. Investigate why the coordinator's view of the cluster
   is uninitialised; almost always a bootstrap-time error.
3. **`EPOCH_ADVANCE_TIMESTAMP_IN_FUTURE` and
   `last_epoch_advance_unix > current_unix + 60`**: the advance
   timestamp is more than 60s ahead of wall clock.
   Investigate clock drift OR a time-travel attempt; do NOT
   raise `EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS`.
4. **`EPOCH_ADVANCE_EPOCH_INVALID` and `last_advanced_epoch <
   0`**: the cluster's view of `last_advanced_epoch` is
   negative. Coordinator bug — fix upstream.
5. **`EPOCH_ADVANCE_EPOCH_NOT_MONOTONIC` and `current_epoch <
   last_advanced_epoch`**: the cluster believes the current
   epoch is BEHIND the most recently advanced one. Either a
   coordinator state-management bug or an attempt to roll back
   the epoch. Fix upstream and investigate.

DO NOT raise `MAX_EPOCH_ADVANCE_STALL_SECONDS` in response to a
fire. Past historical legitimate outages topped out around 28h
on devnet — the 36h floor leaves 8h of headroom and AW-02's
Tier-2 fallback engages at 48h for recovery.

---

## Runtime fire — FRP-3 `CertReissueCadenceError`

### Triage (60s)

```bash
# Cert-vouching path:
# The exception's .report carries:
#   - status (REFUSED), reasons (tuple of reason codes)
#   - agent_wallet
#   - seconds_since_last, reissue_floor
#   - ta6_onchain_ceiling, safety_margin_factor (= 12)
#   - current_unix, last_reissue_unix
# Each reason is one of:
#   ['CERT_REISSUE_OVERDUE',
#    'CERT_REISSUE_TIMESTAMP_IN_FUTURE',
#    'CERT_REISSUE_TIMESTAMP_INVALID',
#    'CERT_REISSUE_AGENT_WALLET_MISSING']
```

### Action

The cert-vouching path REFUSED to declare the agent's cert valid
for high-tier consumer operations. This is the 3c-residual
fingerprint (the cluster has slipped its 4h reissue cadence for
the named agent). The fix depends on the reason:

1. **`CERT_REISSUE_OVERDUE` and `seconds_since_last > 4*3600`**:
   the cluster has not reissued this agent's cert in more than
   4 hours. TWO possibilities:
   - **Legitimate reissue-pipeline lag**: the cluster is busy
     or partially-degraded (often correlated with FRP-1 / FRP-2
     fires for the same incident). Catch up the reissue
     pipeline; the 4h floor is unforgiving on purpose. The
     12× safety margin against TA-6 (48h on chain) means
     consumers calling `is_fresh_default` are still safe; the
     refusal here is the cluster's commitment to fail-closed
     before a freshness-blind consumer eats stale data.
   - **A targeted reissue-stall attack against this specific
     agent**: rare but possible. Investigate whether the
     reissue pipeline is healthy for OTHER agents — if yes,
     the stall is targeted and warrants security
     investigation.
2. **`CERT_REISSUE_TIMESTAMP_IN_FUTURE` and
   `last_reissue_unix > current_unix + 60`**: the reissue
   timestamp is more than 60s ahead of wall clock. Clock drift
   OR time-travel attempt; do NOT raise
   `CERT_REISSUE_FUTURE_TOLERANCE_SECONDS`.
3. **`CERT_REISSUE_TIMESTAMP_INVALID` and `last_reissue_unix <
   1`**: the cluster has never recorded a reissue for this
   agent. The agent has never had a cert issued; the cert-
   vouching path must NOT declare such a cert valid for any
   operation. Investigate why the agent is being vouched for
   without a cert issuance record.
4. **`CERT_REISSUE_AGENT_WALLET_MISSING`**: empty
   `agent_wallet`. Caller bug — fix upstream.

DO NOT raise `MAX_CERT_REISSUE_INTERVAL_SECONDS` or
`TA6_ONCHAIN_MAX_AGE_SECONDS` in response to a fire. The 4h
floor mirrors SOL-3's LOAN_ISSUE floor (the most-demanding
consumer operation), and the 12× safety margin against TA-6's
48h is the contract DeFi consumers depend on.

---

## Verifying the response

After every fix, re-run the gate and tests locally:

```bash
python3 audit/freeze_cert_check.py --json /tmp/frp.json && echo PASS
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest audit/test_freeze_cert_check.py -v
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest \
    helixor-oracle/tests/oracle/test_frp1_cluster_participation_floor.py \
    helixor-oracle/tests/oracle/test_frp2_epoch_advance_liveness.py \
    helixor-oracle/tests/oracle/test_frp3_cert_reissue_cadence.py -v
```

All three MUST be green before the PR is mergeable. For a
runtime fire, the additional bar is that the operator has
documented the root cause of the cluster's degraded liveness
(sustained outage, withholding attack, reissue-pipeline lag) in
the incident channel — the gate is the alarm, not the diagnosis.
