# Runbook — Stale Oracle Lock mitigation response

**Severity:** Critical (any SOL gate red means a mitigation against
the audit's catastrophic Scenario C — Stale Oracle Lock — has either
been removed from the tree or fired at runtime).
**Triggers:**
- `audit/stale_oracle_check.py` gate fails in CI.
- Consumer-side / aggregator boot raises `ClusterSilentError` (SOL-1)
  refusing to act against a silent cluster.
- SDK consumer observes a `StalenessReport` with effective tier
  downgraded (SOL-2) — NOT an exception, a behavioural signal.
- DeFi consumer / aggregator raises `StaleForOperationError` (SOL-3)
  refusing a specific operation against an aged cert.

## What's happening

The Stale Oracle Lock (audit Scenario C) is the 5-step catastrophic-
failure mode in which all 5 oracle nodes are disrupted simultaneously
(coordinated DDoS or infrastructure failure), no new certs are issued,
DeFi protocols keep using last-issued certs, agents whose behaviour
degrades never get updated certs, and mass defaults follow with no
warning. The three mitigations in
`launch/design/stale_oracle_resolution.md` are the load-bearing
reifications of the audit's claim that each substrate of the lock has
a fail-closed defence visible BEFORE TA-6's 48h ceiling. This runbook
is the playbook for reacting when one of them fires or regresses.

The two failure shapes need different responses:

- **CI gate red** — a refactor has REMOVED a mitigation. The code is
  not yet on mainnet. Block the merge and restore the anchor. DO NOT
  weaken the gate to make CI green.
- **Runtime fire** — the mitigation engaged and refused to act on a
  silent cluster, a stale cert, or a high-stakes operation against an
  aged cert. Mainnet is protected; the cluster is silent or the cert
  is genuinely too old for the operation. Investigate the cluster-
  liveness substrate (NOT the cert-age threshold) before resuming.

---

## CI gate red — `audit/stale_oracle_check.py` failed

### Triage (60s)

```bash
# 1. Run the gate locally to see which SOL family regressed.
python3 audit/stale_oracle_check.py --json /tmp/sol.json
cat /tmp/sol.json | python3 -m json.tool | head -80

# 2. Each finding names the rule and the marker string the gate could
#    not find. The SOL-N tag tells you which family regressed.
```

### Decision tree

- **Marker file deleted** (`cluster_liveness.py`,
  `staleness_escalator.py`, `operation_freshness.py`): the closing PR
  removed a mitigation the audit assumes is present. RESTORE the file
  from `main`. The reviewer who approved the removal must justify
  the change in writing on the PR.
- **`verify_*` / `enforce_*` function disappeared**: a contract entry
  point is gone. Restore it. If the function was genuinely renamed in
  good faith, the audit gate's expected marker MUST be updated IN THE
  SAME PR and the PR description must call out the Stale-Oracle-Lock
  closure impact.
- **SOL-1 threshold changed** (`WARN_QUIET_SECONDS`,
  `SILENT_QUIET_SECONDS`, `MIN_RECENT_NODES_FOR_ALIVE`): a load-bearing
  cluster-liveness floor moved. Restore the pinned value. The 2h /
  4h cadence is calibrated against the cluster's canonical 2h epoch
  cadence (`WARN` = 1 cadence; `SILENT` = 2 cadences); a tighter
  floor false-fires on normal cluster jitter, a looser floor delays
  consumer visibility past the point where SOL-3 can help. If the
  cadence itself genuinely moves (e.g. devnet retunes to a different
  epoch length), update the audit gate's expected constants AND the
  per-module property tests IN THE SAME PR with the new cadence
  rationale on the PR description.
- **SOL-1 band-label regression** (`ALIVE` / `DEGRADED` / `SILENT`):
  the consumer SDK and the alerting greps key off the literal band
  strings. Restore the constants. Never rename them — renaming
  silently breaks every consumer's alert routing.
- **SOL-2 threshold changed** (`GREEN_TO_YELLOW_AFTER_SECONDS`,
  `YELLOW_TO_RED_AFTER_SECONDS`, `REFUSE_AFTER_SECONDS`): a per-agent
  staleness floor moved. Restore the pinned value. CRITICAL CHECK:
  the cascade MUST stay 6h < 12h < 24h with strict inequalities — the
  property test pins transitive downgrade (GREEN at 13h → YELLOW →
  RED in one call). If the half-life of TA-6 (`REFUSE_AFTER_SECONDS =
  24h`) is genuinely being retuned, the change must be discussed with
  the audit team before merging — the floor is calibrated to refuse
  certs that TA-6 would still accept, on the principle that a 24h-old
  cert from a previously-healthy cluster CANNOT be trusted for the
  per-agent endorsement layer.
- **SOL-2 tier-label regression** (`GREEN` / `YELLOW` / `RED` /
  `REFUSE`): same as SOL-1 — the consumer SDK and runbook greps key
  off the literals. Restore them. Never rename.
- **SOL-3 threshold changed** (`LOAN_ISSUE_MAX_AGE_SECONDS`,
  `LOAN_INCREASE_MAX_AGE_SECONDS`, `LIQUIDATION_CHECK_MAX_AGE_SECONDS`,
  `STATUS_READ_MAX_AGE_SECONDS`): a per-operation freshness floor
  moved. Restore the pinned value. CRITICAL CHECK:
  `STATUS_READ_MAX_AGE_SECONDS == 48 * 3600` MUST equal TA-6's on-
  chain `MAX_AGE_SECONDS = 48 * 60 * 60` in
  `programs/certificate-issuer/src/state/health_certificate.rs`. The
  gate's `ta6-mirror-48h-lockstep` rule exists exactly to catch the
  refactor where one is changed without the other; never make CI
  green by changing one of them in isolation. The risk-asymmetric
  cascade MUST stay `LOAN_ISSUE < LOAN_INCREASE < LIQUIDATION_CHECK
  < STATUS_READ` — softening LOAN_ISSUE above LOAN_INCREASE inverts
  the risk asymmetry the floor is calibrated to enforce.
- **SOL-3 Operation enum regression**: a canonical operation
  (`LOAN_ISSUE`, `LOAN_INCREASE`, `LIQUIDATION_CHECK`, `STATUS_READ`)
  was removed or its wire label was changed. Restore it. The DeFi
  consumer SDK logs operations by these labels; the audit gate's
  scan looks for the literal strings; the runbook below refers to
  them by name. Adding a new operation is fine; removing or renaming
  one is not — it silently degrades the consumer-side enforcement
  surface.

### After every fix

```bash
python3 audit/stale_oracle_check.py --json /tmp/sol.json && echo PASS
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest audit/test_stale_oracle_check.py -v
```

Both MUST be green before the PR is mergeable.

---

## Runtime fire — SOL-1 `ClusterSilentError` on consumer-side gate

### Triage (60s)

```bash
# Consumer-side aggregator / DeFi protocol:
# The exception's .report carries:
#   - band ("SILENT")
#   - seconds_since_last_cert (e.g. 14_400+ = 4h+)
#   - last_cert_epoch
#   - nodes_recently_active (and MIN_RECENT_NODES_FOR_ALIVE)
#   - reasons: ['CLUSTER_QUIET_PAST_SILENT_THRESHOLD',
#               'CLUSTER_BELOW_QUORUM',
#               'CLUSTER_TIME_TRAVEL',
#               'CLUSTER_NO_CERTS_EVER']
```

### Action

The consumer REFUSED to act because `verify_cluster_liveness` decided
the cluster has been silent past `SILENT_QUIET_SECONDS = 4h` OR fewer
than 3 nodes were recently active. This is the audit's step 1-2
fingerprint (all nodes disrupted simultaneously). The consumer is
protected — no new operation acts on a cert from a structurally
unreliable cluster. The next move depends on the substrate of the
silence:

1. **`CLUSTER_QUIET_PAST_SILENT_THRESHOLD` (no node has signed in 4+
   hours)**: the cluster is genuinely down. Page the cluster on-call.
   Cross-check the cluster operator's monitoring: are any nodes
   reachable on their heartbeat ports? Is the upstream RPC fleet
   reachable from the operator side? The most common root causes are
   (a) coordinated DDoS against the cluster's public ingresses,
   (b) shared infrastructure failure (single-cloud outage, single-
   region power event), (c) a programs upgrade that broke the
   cluster's signing path. Do NOT attempt to lower
   `SILENT_QUIET_SECONDS` to "let traffic through" — the lock is
   designed to refuse exactly this state. The cluster has to come back
   up; consumer-side enforcement is the consumer's choice to refuse
   acting against silent data.
2. **`CLUSTER_BELOW_QUORUM` (recent nodes < 3)**: even if a recent
   cert exists, the cluster has lost K-of-N capability and cannot
   produce a new honest cert. SOL-1 forces the band to SILENT
   regardless of cert age. The action is the same as
   `CLUSTER_QUIET_PAST_SILENT_THRESHOLD` (page cluster on-call), but
   the underlying topology is BROKEN in a way that quiet-cadence
   alone doesn't capture. Investigate which nodes are gone — if it's
   K of N nodes in the same cloud / same jurisdiction, the
   correlated-loss substrate from NSS-1 has also engaged.
3. **`CLUSTER_TIME_TRAVEL` (most recent cert is in the future past
   60s tolerance)**: clock skew or a forged cert. Investigate. The
   cluster MUST resolve the clock divergence BEFORE the consumer can
   trust the next cert; SOL-1 refusing here is the correct behaviour.
4. **`CLUSTER_NO_CERTS_EVER` (no cert ever observed)**: the consumer
   is wired but the cluster has not yet emitted a cert. On mainnet
   this should NEVER happen post-launch — investigate why the
   consumer was wired against an oracle that has never produced
   output.

DO NOT lower `WARN_QUIET_SECONDS`, `SILENT_QUIET_SECONDS`, or
`MIN_RECENT_NODES_FOR_ALIVE` to push the consumer through a silent
cluster. The whole point of SOL-1 is to make the silence visible to
the consumer hours BEFORE TA-6's 48h hard ceiling — neutralising the
signal re-opens Scenario C step 3 (DeFi continues to use stale certs).

---

## Runtime signal — SOL-2 effective-tier downgrade on consumer view

### Triage (60s)

```bash
# SOL-2 does NOT raise — it returns a StalenessReport. The DeFi
# consumer (or the SDK wrapper) inspects:
#   - issued_tier (e.g. "GREEN" — what the cluster stamped)
#   - effective_tier (e.g. "YELLOW", "RED", or "REFUSE")
#   - cert_age_seconds
#   - reasons: ['AGE_DOWNGRADE_GREEN_TO_YELLOW',
#               'AGE_DOWNGRADE_YELLOW_TO_RED',
#               'AGE_REFUSE',
#               'CERT_ISSUED_IN_FUTURE']
# The CONSUMER decides the per-tier behaviour change — SOL-2 only
# emits the report.
```

### Action

SOL-2 fired BECAUSE an individual agent's cert has aged past one of
the 6h / 12h / 24h floors. The cluster as a whole may still be ALIVE
(SOL-1 not raised) — this is the audit's step 3-4 fingerprint (an
individual agent's behaviour degrades while its cert sits stale on
chain). The DeFi consumer's response depends on `effective_tier`:

1. **`effective_tier = "YELLOW"` (6h ≤ age < 12h, issued GREEN)**:
   the agent has not been re-stamped in three full cadences. The
   consumer should treat the cert as YELLOW — accept routine reads,
   refuse new collateral-grade lending. This is the INTENDED
   behaviour; no action is needed beyond honouring the downgrade in
   the loan-decision code. The cluster's lack of refresh might be
   normal (the agent is below the cluster's per-epoch refresh quota),
   but it might also be a degraded-cluster signal — cross-check
   against SOL-1's band on the same consumer.
2. **`effective_tier = "RED"` (12h ≤ age < 24h)**: six full cadences.
   The cert is structurally stale; the agent's behaviour could have
   changed materially since the last endorsement. The consumer should
   REFUSE new loans against the agent and consider closing existing
   positions per the consumer's risk policy. Do NOT extend an
   existing position (`LOAN_INCREASE` will refuse anyway via SOL-3,
   but the consumer SDK should not even attempt the call).
3. **`effective_tier = "REFUSE"` (age > 24h)**: twelve full cadences,
   half-life of TA-6. The cert is structurally unusable for any
   per-agent endorsement. SOL-3 will also refuse most operations
   against it (every Operation except STATUS_READ has a max-age
   floor below 24h). The consumer's only sane behaviour is to wait
   for a fresh cert; lending operations against a REFUSE-tier cert
   are a deliberate violation of the contract.
4. **`reasons` includes `CERT_ISSUED_IN_FUTURE`**: the cert's
   `issued_at_unix` is past the 60s tolerance into the future. Either
   the cluster's clock is skewed, the cert was forged, or the
   consumer's clock is skewed. Investigate BEFORE acting; the age
   field clamps to 0 in the report so downstream telemetry stays
   sane, but the cert itself should not be trusted until the clock
   divergence is resolved.

DO NOT raise `GREEN_TO_YELLOW_AFTER_SECONDS` or
`YELLOW_TO_RED_AFTER_SECONDS` to "keep more agents GREEN" — the
per-agent floors close the gap between TA-6's 48h ceiling and the
real consumer risk. An aged GREEN cert IS structurally stale even if
the cluster as a whole stays alive; that's the substrate SOL-2 is
calibrated for.

---

## Runtime fire — SOL-3 `StaleForOperationError` on DeFi consumer

### Triage (60s)

```bash
# DeFi consumer / aggregator side:
# The exception's .report carries:
#   - operation (Operation.LOAN_ISSUE / .LOAN_INCREASE /
#                .LIQUIDATION_CHECK / .STATUS_READ)
#   - cert_age_seconds, max_age_seconds (per operation)
#   - reasons: ['OPERATION_CERT_TOO_OLD', 'OPERATION_CERT_IN_FUTURE']
```

### Action

The consumer REFUSED to perform a specific operation because the
cert's age exceeded the per-operation freshness floor. This is the
audit's step 5 defence — even if the cert is "fresh" by TA-6's 48h
ceiling and the cluster is technically ALIVE under SOL-1, a high-
stakes operation (LOAN_ISSUE) against a 5h-old cert is refused. The
fix depends on the operation and the reason:

1. **`operation == LOAN_ISSUE` and `cert_age_seconds >= 4h`**: the
   most common SOL-3 fire. A new collateralised loan was attempted
   against a cert that is past two full cluster cadences without
   refresh. This is by-design: the LOAN_ISSUE floor is the TIGHTEST
   floor in the system because opening a new position against
   structurally stale data is the riskiest operation a DeFi consumer
   performs. The correct response is to WAIT for the cluster to
   refresh the cert and re-attempt. If the cluster is silent (SOL-1
   in DEGRADED or SILENT), the actual root cause is SOL-1 — follow
   the SOL-1 runbook section above.
2. **`operation == LOAN_INCREASE` and `cert_age_seconds >= 8h`**:
   adjusting an existing position against a cert past four cadences.
   Less common (positions usually get re-evaluated against fresher
   data), but possible when an aggregator's snapshot has gone stale.
   Refresh the snapshot and re-attempt; if the cluster is silent the
   substrate is SOL-1, not SOL-3.
3. **`operation == LIQUIDATION_CHECK` and `cert_age_seconds >= 12h`**:
   a liquidation in flight refuses. The half-life is generous (six
   cadences) because the operator has already decided the position
   is at risk, and a slightly stale cert is acceptable evidence. If
   the floor still refuses, the cluster has been silent for half a
   day — SOL-1 has also fired and the actual root cause is the
   silent cluster.
4. **`operation == STATUS_READ` and `cert_age_seconds >= 48h`**: the
   cert is past TA-6's hard ceiling. By construction TA-6 will also
   refuse this cert at the contract layer; SOL-3 mirrors that floor
   exactly so the consumer's most permissive operation does not
   accept what the on-chain certificate-issuer would refuse. There
   is no consumer-side action — the cert is over the on-chain
   ceiling.
5. **`reasons` includes `OPERATION_CERT_IN_FUTURE`**: same as the
   SOL-2 time-travel case — clock skew or a forged cert. Investigate
   before acting.

DO NOT raise `LOAN_ISSUE_MAX_AGE_SECONDS`, `LOAN_INCREASE_MAX_AGE_SECONDS`,
or `LIQUIDATION_CHECK_MAX_AGE_SECONDS` to "let one transaction through"
in response to a fire. The risk asymmetry exists precisely so that
high-stakes operations refuse first; lowering the floor on LOAN_ISSUE
re-opens audit step 5 (mass defaults with no warning). The correct
response is to refresh the cert OR (if SOL-1 is also lit) to invoke
the cluster-down playbook above.

`STATUS_READ_MAX_AGE_SECONDS` is the SPECIAL case: it MUST equal
TA-6's `MAX_AGE_SECONDS = 48 * 60 * 60` exactly. Changing one without
the other lets the consumer refuse a cert TA-6 would accept (or vice
versa) — the audit gate's `ta6-mirror-48h-lockstep` rule will fail
the build if the two drift.

---

## Verifying the response

After every fix, re-run the gate and tests locally:

```bash
python3 audit/stale_oracle_check.py --json /tmp/sol.json && echo PASS
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest audit/test_stale_oracle_check.py -v
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest \
    helixor-oracle/tests/oracle/test_sol1_cluster_liveness.py \
    helixor-oracle/tests/oracle/test_sol2_staleness_escalator.py \
    helixor-oracle/tests/oracle/test_sol3_operation_freshness.py -v
```

All three MUST be green before the PR is mergeable. For a runtime
fire, the additional bar is that the cluster operator has documented
the root cause of the silence (DDoS, infra failure, programs upgrade
bug) in the incident channel — the gate is the alarm, not the
diagnosis.
