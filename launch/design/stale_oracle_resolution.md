# Stale Oracle Lock Resolution — audit Scenario C

**Status:** IMPLEMENTED.
**Audit finding:** Scenario C from the catastrophic-failure inventory
— "Stale Oracle Lock" — the 5-step attack chain in which all five
oracle nodes are disrupted simultaneously (coordinated DDoS or
infrastructure failure), no new certs are issued, DeFi protocols
continue to use last-issued certs, agents whose behaviour degrades
never get updated certs, and mass defaults follow with no warning.
**Owners:** oracle engineering (SOL-1, SOL-2, SOL-3); SDK / consumer
integration mirrors SOL-2 + SOL-3 in TypeScript.
**Related code / config:**
- `helixor-oracle/oracle/cluster_liveness.py` (SOL-1)
- `helixor-oracle/oracle/staleness_escalator.py` (SOL-2)
- `helixor-oracle/oracle/operation_freshness.py` (SOL-3)
- `helixor-oracle/tests/oracle/test_sol1_cluster_liveness.py`
- `helixor-oracle/tests/oracle/test_sol2_staleness_escalator.py`
- `helixor-oracle/tests/oracle/test_sol3_operation_freshness.py`
- `audit/stale_oracle_check.py` + `audit/test_stale_oracle_check.py`
  (mechanical regression gate)

---

## The attack the audit named

Scenario C is the THIRD catastrophic failure mode and the one whose
substrate is not adversarial but operational: the cluster cannot be
relied on to keep producing certs forever. Reproduced verbatim from
the audit:

1. All 5 oracle nodes are disrupted simultaneously (coordinated DDoS
   or infrastructure failure).
2. No new certs are issued.
3. DeFi protocols continue to use last-issued certs (stale data).
4. Agents whose behaviour degrades never get updated certs.
5. Mass defaults with no warning.

TA-6's 48-hour cert-freshness contract (`MAX_AGE_SECONDS = 172800`)
is the BACKSTOP that bounds the worst-case window, but its time
constant is too coarse to be the only defence:

- A cluster outage that lasts 6 hours produces certs that are still
  "fresh" by TA-6's clock — the consumer has no signal that the
  cluster is silent.
- A single agent's behaviour can deteriorate over 12 hours while its
  GREEN cert sits unchanged on chain. TA-6 says "fresh"; the cert
  still says "collateral-grade"; the consumer has no signal that the
  endorsement is becoming structurally stale.
- A high-stakes new loan and a routine status read are gated by the
  same 48h threshold — there is no risk-asymmetric refusal.

The Stale Oracle Lock therefore needs THREE new mitigations at three
different substrates of the consumer/cluster boundary, each
fail-closed.

---

## Why a three-mitigation closure

The five steps cluster into three independent substrates:

| Substrate | Steps it spans | Why a single mitigation cannot reach it |
| --- | --- | --- |
| Cluster-wide silence (cluster clock) | steps 1, 2 | The cluster is not signing certs. TA-6's 48h ceiling doesn't fire for the first 48 hours; SOL-1 makes the silence visible hours earlier on a separate cluster-wide clock that runs from "most recent cert anywhere in the system," not "this particular agent's most recent cert." |
| Per-agent silence under a healthy cluster (per-agent clock) | steps 3, 4 | An individual agent's cert can age silently between successful refreshes even while the cluster as a whole stays alive. SOL-2 degrades the EFFECTIVE tier (GREEN → YELLOW → RED → REFUSE) on the per-agent age axis so a degrading agent's stale cert progressively loses weight rather than staying GREEN until the cliff-edge. |
| Operation-level risk asymmetry (operation clock) | step 5 | Opening a new collateralised loan against a 6-hour-old cert is fundamentally riskier than reading a status display from the same cert. SOL-3 maps each operation type to its own max-cert-age: LOAN_ISSUE 4h, INCREASE 8h, LIQUIDATION 12h, STATUS_READ 48h (matches TA-6). New high-stakes positions cannot be opened against silent-cluster data even within TA-6's window. |

The three mitigations are orthogonal: each closes a substrate the
other two cannot reach. Defeating the lock requires defeating all
three — including the FACT that SOL-1 is observable on the
cluster-wide clock and SOL-3 makes the consumer's behaviour
risk-asymmetric on the operation clock.

---

## The SOL inventory

| #   | Substrate                              | Mitigation                                                                                                          | Pinned thresholds                                                                                                                            | Gate           |
|-----|----------------------------------------|---------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|----------------|
| 1   | Cluster-wide silence                   | `verify_cluster_liveness(context, *, current_unix)` — emits a band (ALIVE / DEGRADED / SILENT) from cluster cadence | `WARN_QUIET_SECONDS = 2*3600`, `SILENT_QUIET_SECONDS = 4*3600`, `MIN_RECENT_NODES_FOR_ALIVE = 3`, `LIVENESS_FUTURE_TOLERANCE_SECONDS = 60`     | SOL gate SOL-1 |
| 2   | Per-agent silence                      | `escalate_for_age(snapshot, *, current_unix)` — returns effective tier after age-based downgrade                    | `GREEN_TO_YELLOW_AFTER_SECONDS = 6*3600`, `YELLOW_TO_RED_AFTER_SECONDS = 12*3600`, `REFUSE_AFTER_SECONDS = 24*3600`                            | SOL gate SOL-2 |
| 3   | Operation-level risk asymmetry         | `verify_operation_freshness(operation=..., issued_at_unix=..., current_unix=...)` — per-operation max-age check     | `LOAN_ISSUE = 4h`, `LOAN_INCREASE = 8h`, `LIQUIDATION_CHECK = 12h`, `STATUS_READ = 48h` (mirrors TA-6's `MAX_AGE_SECONDS`)                     | SOL gate SOL-3 |

---

## How each fix works

### SOL-1 — cluster-liveness signal

The cluster's signing cadence is the canonical liveness signal. When
that cadence stops, every consumer should learn about it hours BEFORE
TA-6's hard 48h ceiling. SOL-1 reifies the signal:

`oracle/cluster_liveness.py`:

- `ClusterLivenessContext(last_cert_unix, last_cert_epoch,
  nodes_recently_active)` is the pure input — the cluster's most
  recent threshold-signed cert (MAX across all agents), the epoch of
  that cert, and a count of distinct nodes that produced a heartbeat
  in the current or previous epoch (sourced from the
  `oracle_node_heartbeat` table consumed by
  `helixor-api/api/cluster_health.py`).
- `WARN_QUIET_SECONDS = 2 * 3600` (2 hours) — one full canonical
  cluster cadence has elapsed without a new cert. The cluster
  MIGHT just have skipped one epoch; the band moves to DEGRADED and
  consumers should treat the signal as suspicious but not refuse
  routine reads.
- `SILENT_QUIET_SECONDS = 4 * 3600` (4 hours) — two full cadences
  have passed in silence. The band moves to SILENT and consumer-side
  SOL-3 enforcement refuses LOAN_ISSUE / LOAN_INCREASE outright.
- `MIN_RECENT_NODES_FOR_ALIVE = 3` — the cluster's K-of-N threshold.
  If fewer than three nodes were recently active, the band is forced
  to SILENT regardless of how recent the last cert claims to be: a
  cluster that lost K-of-N capability cannot have produced an honest
  cert.
- `LIVENESS_FUTURE_TOLERANCE_SECONDS = 60` — a single epoch's worth
  of clock skew. A cert whose `last_cert_unix` is more than 60s in
  the future is structurally suspect and the band is forced to
  SILENT (`REASON_LIVENESS_TIME_TRAVEL`).
- `verify_cluster_liveness(context, *, current_unix)` is pure; no
  logging, no I/O. Returns a `ClusterLivenessReport` carrying the
  band, the elapsed seconds, the floors, and reason codes.
- `enforce_cluster_alive(...)` raises `ClusterSilentError` on SILENT
  with the report attached. ALIVE and DEGRADED return the report.

The signal is the OUTER GATE of the consumer. DeFi consumers wire
SOL-1 BEFORE SOL-2 / SOL-3 — a SILENT cluster terminates the request
without inspecting any individual cert.

### SOL-2 — per-agent age-based tier degradation escalator

SOL-1 closes cluster-wide silence. What it does NOT close is the
PER-AGENT case: even under a healthy cluster, an individual agent's
cert can age between successful refreshes. The cluster might sign
agents X and Y at epoch N but skip agent Z; then Z's old cert sits
unchanged on chain while the cluster as a whole stays ALIVE. If Z's
behaviour is deteriorating in real time, the consumer has no signal
that the GREEN endorsement is structurally stale.

`oracle/staleness_escalator.py`:

- `CertSnapshot(agent_wallet, issued_tier, issued_at_unix)` is the
  pure input — one agent's most recent cert summary as the SDK
  consumer sees it.
- `GREEN_TO_YELLOW_AFTER_SECONDS = 6 * 3600` — three full cadences.
  A GREEN endorsement that hasn't been refreshed in three epochs is
  downgraded to YELLOW on the consumer's view. The agent is still
  acceptable for routine reads; new collateral-grade operations are
  no longer at GREEN trust level.
- `YELLOW_TO_RED_AFTER_SECONDS = 12 * 3600` — six full cadences.
  EFFECTIVE YELLOW downgrades to RED. The downgrade is TRANSITIVE:
  a GREEN cert at 13 hours has passed both floors and is treated as
  RED.
- `REFUSE_AFTER_SECONDS = 24 * 3600` — twelve full cadences. Half-
  life-of-TA-6. Any cert older than 24 hours is REFUSED outright by
  the escalator regardless of its original tier; the consumer cannot
  act on it for any operation.
- `escalate_for_age(snapshot, *, current_unix)` is pure: integer
  arithmetic on `(issued_at_unix, current_unix)` + tier-string
  normalisation (`" green "` → `GREEN`). Returns a `StalenessReport`
  carrying the issued tier, the effective tier, the cert age, the
  three floors, and reason codes (`AGE_DOWNGRADE_GREEN_TO_YELLOW`,
  `AGE_DOWNGRADE_YELLOW_TO_RED`, `AGE_REFUSE`,
  `CERT_ISSUED_IN_FUTURE`).
- The escalation is ONE-DIRECTIONAL: a tier is only ever downgraded,
  never upgraded. RED input stays RED until REFUSE; a cert whose
  effective tier is already RED is not "softened" by being relatively
  young for its tier.
- A future-dated cert (`issued_at_unix > current_unix + 60s`) is
  REFUSED with `REASON_ESCALATOR_TIME_TRAVEL`. The age field clamps
  to zero so downstream telemetry stays sane.

### SOL-3 — per-operation freshness floors

SOL-1 closes cluster-wide silence; SOL-2 degrades the per-agent
effective tier. What neither closes is the ASYMMETRIC consumer
behaviour: opening a new collateralised loan is fundamentally riskier
than reading a status display, but pre-SOL-3 both were gated by the
same TA-6 threshold.

`oracle/operation_freshness.py`:

- `Operation` enum enumerates `LOAN_ISSUE`, `LOAN_INCREASE`,
  `LIQUIDATION_CHECK`, `STATUS_READ`. The string value is the stable
  wire label the consumer logs and the audit gate cross-references.
- `LOAN_ISSUE_MAX_AGE_SECONDS = 4 * 3600` — two cadences. The cluster
  has had ample opportunity to refresh; if it hasn't, refuse the new
  loan.
- `LOAN_INCREASE_MAX_AGE_SECONDS = 8 * 3600` — four cadences.
  Adjusting an existing position is risk-mid: more permissive than a
  brand-new loan, less than a passive read.
- `LIQUIDATION_CHECK_MAX_AGE_SECONDS = 12 * 3600` — six cadences. A
  liquidation in progress already implies the operator has decided
  the position is at risk; a 12h-old cert is acceptable evidence.
- `STATUS_READ_MAX_AGE_SECONDS = 48 * 3600` — twenty-four cadences.
  Matches TA-6's on-chain `MAX_AGE_SECONDS = 48 * 60 * 60` exactly so
  SOL-3 never refuses a cert TA-6 would accept for the most
  permissive operation.
- `OPERATION_MAX_AGE_SECONDS` is a frozen mapping from the enum to
  the floors. The audit gate cross-checks every entry.
- `verify_operation_freshness(*, operation, issued_at_unix,
  current_unix)` is pure. Returns `OperationFreshnessReport`
  carrying the operation, the cert age, the max age, an allow flag,
  and reason codes (`OPERATION_CERT_TOO_OLD`,
  `OPERATION_CERT_IN_FUTURE`).
- `enforce_operation_freshness(...)` raises `StaleForOperationError`
  with the report attached on refusal.

### Interaction between the three mitigations

- **SOL-1 ↔ SOL-3**: SOL-1 fires when the CLUSTER has been quiet.
  SOL-3 fires when a SPECIFIC CERT is too old for a SPECIFIC
  OPERATION. A SILENT cluster typically also produces stale certs
  for high-stakes operations, but the two fire on different clocks
  so a cluster that is just-past-SILENT but had a cert at hour
  3.5 still triggers SOL-3 for LOAN_ISSUE while SOL-1 says SILENT.
- **SOL-2 ↔ SOL-3**: SOL-2's `REFUSE_AFTER_SECONDS = 24h` is strictly
  greater than every SOL-3 max-age except `STATUS_READ`. A cert
  refused by SOL-2 is therefore refused by SOL-3 for every operation
  except `STATUS_READ` (which itself refuses at 48h). The two are
  not redundant: SOL-2 governs WHICH TIER the consumer treats the
  cert as (passive read behaviour); SOL-3 governs WHETHER THE
  OPERATION may proceed at all (active write behaviour).
- **SOL-3 ↔ TA-6**: TA-6's 48h `MAX_AGE_SECONDS` is the BACKSTOP.
  SOL-3's `STATUS_READ` floor mirrors it for the most permissive
  operation; all higher-stakes operations refuse much earlier. The
  audit gate cross-checks the TA-6 constant in
  `programs/certificate-issuer/src/state/health_certificate.rs` and
  fails the build if the two drift out of lockstep.
- **SOL-1 ↔ AW-02 distributed-epoch-advancement**: AW-02 already
  ships an on-chain liveness fallback (`EpochState.liveness_fallback_
  elapsed`, 2× duration). That fires at the CLUSTER LEVEL after 48
  hours of no epoch advancement; SOL-1 fires at the CONSUMER LEVEL
  after 4 hours of no NEW CERT. The two are independent — SOL-1 is
  load-bearing for the consumer-visibility-of-silence substrate even
  when AW-02 has not yet fired.

---

## What the audit gate guarantees

`audit/stale_oracle_check.py` runs three probes (SOL-1..SOL-3)
against the as-shipped tree. The gate fails the build if any of the
following goes wrong:

- A marker file is deleted (`cluster_liveness.py`,
  `staleness_escalator.py`, `operation_freshness.py`).
- A load-bearing function disappears (`verify_cluster_liveness` /
  `enforce_cluster_alive`, `escalate_for_age`,
  `verify_operation_freshness` / `enforce_operation_freshness`).
- A pinned threshold is silently changed (`WARN_QUIET_SECONDS=2*3600`,
  `SILENT_QUIET_SECONDS=4*3600`, `MIN_RECENT_NODES_FOR_ALIVE=3`,
  `GREEN_TO_YELLOW_AFTER_SECONDS=6*3600`,
  `YELLOW_TO_RED_AFTER_SECONDS=12*3600`,
  `REFUSE_AFTER_SECONDS=24*3600`,
  `LOAN_ISSUE_MAX_AGE_SECONDS=4*3600`,
  `LOAN_INCREASE_MAX_AGE_SECONDS=8*3600`,
  `LIQUIDATION_CHECK_MAX_AGE_SECONDS=12*3600`,
  `STATUS_READ_MAX_AGE_SECONDS=48*3600`).
- The band-label constants (`ALIVE` / `DEGRADED` / `SILENT`) or the
  tier-label constants (`GREEN` / `YELLOW` / `RED` / `REFUSE`) are
  renamed.
- The `Operation` enum loses any of the four canonical operations or
  their wire labels.
- The lockstep cross-check
  `programs/certificate-issuer/src/state/health_certificate.rs`
  `MAX_AGE_SECONDS = 48 * 60 * 60` drifts — SOL-3's `STATUS_READ`
  floor is supposed to mirror it. A change in either alone is a
  HARD finding.

The gate is intentionally narrow at the CONTRACT layer — the deeper
validation lives in the per-module property tests
(`tests/oracle/test_sol[1-3]_*.py`, 47 tests total). The audit gate
is the canary that catches a contract-layer regression BEFORE it
reaches the test layer where it might be quietly skipped or rewritten.
The `audit/test_stale_oracle_check.py` self-test pins the gate to
0 hard / 0 soft findings on the as-shipped tree.
