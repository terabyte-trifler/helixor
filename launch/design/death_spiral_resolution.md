# Protocol Death Spiral Resolution — audit Scenario A

**Status:** IMPLEMENTED.
**Audit finding:** Scenario A from the catastrophic-failure inventory
— "Protocol Death Spiral" — the 7-step attack chain that compromises
two oracle nodes, runs VULN-03 slow-drift inflation for 30 epochs,
saturates the agent universe in the GREEN tier, drains DeFi loan
capacity, and detonates correlated agent failures so every loan
defaults at once.
**Owners:** oracle engineering (PDS-1, PDS-3), platform / SDK
engineering (PDS-2).
**Related code / config:**
- `phylanx-oracle/oracle/cluster/saturation_gate.py` (PDS-1)
- `phylanx-oracle/oracle/score_velocity.py` (PDS-2)
- `phylanx-oracle/oracle/cluster/correlated_inflation.py` (PDS-3)
- `phylanx-oracle/tests/oracle/test_pds1_saturation_gate.py`
- `phylanx-oracle/tests/oracle/test_pds2_score_velocity.py`
- `phylanx-oracle/tests/oracle/test_pds3_correlated_inflation.py`
- `audit/death_spiral_check.py` + `audit/test_death_spiral_check.py`
  (mechanical regression gate)

---

## The attack the audit named

The audit's catastrophic Scenario A is the FIRST failure mode that
defeats the protocol's per-agent defences without defeating the
per-agent math. Reproduced verbatim from the audit:

1. Attacker compromises two oracle nodes (cluster threshold is 3-of-5;
   two nodes alone cannot forge a cert).
2. The two compromised nodes run VULN-03 slow-drift inflation — each
   epoch they push every agent's score up by ~30 points, an amount
   that sits BELOW the per-epoch `MAX_SCORE_DELTA = 200` clamp but
   ABOVE the `DIRECTIONAL_MIN_DELTA = 25` noise floor. The honest
   majority (3 nodes) still wins the threshold, but the cluster median
   already drifted because the honest nodes are reading the SAME
   poisoned upstream RPC data the attacker is. No single agent
   deviates from the cluster median — there is no honest median to
   deviate from.
3. After ~30 epochs the WHOLE agent universe lives in the 900+ band.
   Every cert is fresh, threshold-signed, individually within the
   per-epoch clamp, and cryptographically indistinguishable from an
   honest cert.
4. DeFi protocols that gate loans against the cert (the 0..1000
   composite) issue MAXIMUM collateralised loans against the saturated
   scores. No single consumer can detect the inflation — they have
   nothing to compare against.
5. Attacker triggers mass agent failures simultaneously. The honest
   nodes report the crash truthfully; the cert batch reflects
   correlated drops of 300+ points across the majority of the
   population.
6. Every collateralised loan defaults at once. Lenders cannot
   liquidate fast enough — the drop is system-wide.
7. The protocol's credibility is destroyed: certified scores are now
   provably divorced from reality, and the audit's "no single point of
   trust" guarantee evaporates because the trust was on the SHARED
   UPSTREAM, not on the cluster keys.

Each individual on-chain defence is intact end-to-end through this
chain. What is broken is the assumption that PER-AGENT clamps detect
a CROSS-AGENT poisoning event — they don't, by construction. The
death spiral therefore needs THREE new mitigations at three different
substrates of the protocol, each fail-closed.

---

## Why a three-mitigation closure

The seven steps cluster into three independent substrates:

| Substrate | Steps it spans | Why a single mitigation cannot reach it |
| --- | --- | --- |
| Cluster signing pre-issue (per-epoch, cross-agent) | step 3 | Per-agent defences can't see a population-wide migration into the GREEN tier. The cluster must refuse to SIGN a batch whose distribution is structurally implausible, BEFORE the cert is emitted. |
| SDK / DeFi-consumer (per-cert, cross-epoch) | step 4 | The cluster's internal 200-point clamp does not protect a consumer who trusts the cluster blindly. The consumer needs a CANONICAL velocity contract that the cluster mirrors but that the consumer can enforce independently — defence-in-depth across the trust boundary. |
| Forensic / multi-epoch (rolling window) | steps 2 and 5 | A slow drift below the 25-point noise floor and a coordinated mass failure both leave their fingerprint in a ROLLING-WINDOW directional tally. The single-epoch saturation gate (PDS-1) cannot see the drift; the per-cert velocity contract (PDS-2) cannot see the correlation; PDS-3 sees both. |

The three mitigations are orthogonal: each closes a substrate the
other two cannot reach. Defeating the death spiral requires defeating
all three simultaneously — including the offline forensic-grade
evidence hash PDS-3 produces.

---

## The PDS inventory

| #   | Substrate                             | Mitigation                                                                                                              | Pinned thresholds                                                                                                              | Gate           |
|-----|---------------------------------------|-------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|----------------|
| 1   | Cluster signing pre-issue             | `verify_saturation(snapshot, prior)` — refuses cert batch when the agent distribution saturates HIGH band               | `HIGH_BAND_FLOOR=700`, `MAX_HIGH_BAND_MIGRATION_FRACTION=0.40`, `ABSOLUTE_HIGH_BAND_CEILING=0.80`, `VARIANCE_COLLAPSE_THRESHOLD=0.50` | PDS gate PDS-1 |
| 2   | SDK consumer-side velocity contract   | `verify_score_velocity(curr, prev)` — caps per-epoch delta AND per-hour velocity for adjacent-epoch cert pairs           | `MAX_SCORE_DELTA_PER_EPOCH=200` (in lockstep with `scoring/_gaming.MAX_SCORE_DELTA=200`), `MAX_SCORE_VELOCITY_PER_HOUR=100`, `ABSURD_VELOCITY_PER_HOUR=500` | PDS gate PDS-2 |
| 3   | Forensic / rolling-window correlation | `verify_correlated_movement(snapshots)` + `verify_mass_failure(curr, prior)` — rolling-window directional + crash tally with deterministic evidence hash | `CORRELATION_WINDOW=5`, `DIRECTIONAL_MIN_DELTA=25`, `MAX_DIRECTIONAL_SHARE=0.85`, `MASS_FAILURE_DROP=200`, `MASS_FAILURE_AGENT_FRACTION=0.50` | PDS gate PDS-3 |

---

## How each fix works

### PDS-1 — cluster score-band saturation gate

The drift detector (`oracle/cluster/drift_detector.py`) closes the
PER-AGENT case: a single node consistently above the cluster median
is named. What it cannot close is the SYSTEM-WIDE case where every
honest node is reading identically-poisoned upstream RPC data — no
node deviates from the cluster median because the median itself is
poisoned.

`oracle/cluster/saturation_gate.py` reifies the population-distribution
contract:

- `AgentScore(agent_wallet, score)` and `EpochSnapshot(epoch, agents)`
  are pure dataclasses. The snapshot exposes `high_band_count`,
  `high_band_fraction`, and `std_dev` as derived properties — no
  clock, no I/O, no randomness, so two cluster members produce
  byte-identical verdicts.
- `HIGH_BAND_FLOOR = 700` matches the GREEN-tier floor in
  `scoring/composite.py` — the range DeFi protocols treat as
  collateral-grade. A cross-agent migration INTO this band is the
  substrate of step 3 of the death spiral.
- `MAX_HIGH_BAND_MIGRATION_FRACTION = 0.40` — the gate refuses if
  more than 40% of the agent universe migrates into the HIGH band
  within ONE epoch. Chosen to permit a legitimate market-wide
  good-news event (a bullish cycle that genuinely lifts ~30% of
  agents) while refusing the 60-90% migration that fingerprints
  coordinated poisoning.
- `ABSOLUTE_HIGH_BAND_CEILING = 0.80` — a hard ceiling on the
  fraction of the agent universe that may be in HIGH at all. Even a
  slow climb that does NOT trip the per-epoch migration cap is
  refused if the steady-state density crosses this floor. A healthy
  ecosystem has agents in every tier; >80% in GREEN is structurally
  implausible.
- `VARIANCE_COLLAPSE_THRESHOLD = 0.50` — if the score-distribution
  std dev drops by more than half against the rolling mean of prior
  epochs, the gate refuses. The death spiral's late stage collapses
  every agent onto similar inflated values — the variance signature
  shows up before the absolute-ceiling does.
- `verify_saturation(snapshot, prior_snapshots)` returns a
  `SaturationReport`; `enforce_saturation(...)` raises
  `ScoreSaturationError` with the report attached. The cluster
  pre-issue hook calls the `enforce_*` variant — a saturated batch
  never gets a threshold signature.

`MIN_AGENTS_FOR_GATE = 5` and `MIN_PRIOR_EPOCHS_FOR_VARIANCE = 3`
fail OPEN on bootstrap so the gate does not refuse a healthy
brand-new cluster.

### PDS-2 — SDK-consumer score-velocity contract

The on-chain `HealthCertificate` is keyed per-(agent, epoch); seed =
`["cert", agent_wallet, epoch_le]`. The PREVIOUS epoch's cert is
already permanently on-chain — a DeFi consumer can read it. What was
missing was a CANONICAL contract that says "two certs (this-epoch,
prev-epoch) where the score moved more than X points OR more than Y
points/hour MUST be treated as a velocity anomaly — even if both are
individually fresh and signed."

`oracle/score_velocity.py` reifies the velocity contract:

- `MAX_SCORE_DELTA_PER_EPOCH = 200` — mirrors
  `scoring/_gaming.MAX_SCORE_DELTA = 200`. The cluster clamps to this
  internally; the SDK rejects pairs that exceed it externally. The
  PDS audit gate cross-checks the two constants and FAILS if they
  drift out of lockstep (`scoring-gaming-cap-in-lockstep`).
- `MAX_SCORE_VELOCITY_PER_HOUR = 100` — the cluster runs ~12
  epochs/day (2h cadence), so a sustained 100 points/hour means the
  cluster is moving its full per-epoch cap continuously. Anything
  beyond that, the slow-drift detector should already have fired —
  PDS-2 is the defence-in-depth boundary.
- `ABSURD_VELOCITY_PER_HOUR = 500` — half the 0..1000 scale per hour.
  No legitimate operational scenario produces this; the reject reason
  supersedes the standard `VELOCITY_EXCEEDED` so the consumer's logs
  surface the structural-impossibility case distinctly.
- `MIN_ELAPSED_SECONDS_FOR_VELOCITY = 60` — below this elapsed floor
  the per-hour math is dominated by clock jitter; the per-epoch delta
  check still applies.
- Reasons enumerated: `EPOCH_DELTA_EXCEEDS_CAP`, `VELOCITY_EXCEEDS_CAP`,
  `ABSURD_VELOCITY`, `PREVIOUS_AFTER_CURRENT`. The last one catches
  clock-rewind / certificate-replay where `previous_issued_at >
  current_issued_at` — a structural impossibility that PDS-2 refuses
  outright.

The Python is the CANONICAL form; the TypeScript SDK mirrors the same
constants and arithmetic so the cluster pre-issue gate and the DeFi
consumer reach the same verdict on the same cert pair. The trust
boundary is: the cluster can lie about its INTERNAL clamp, but it
cannot lie about the on-chain cert pair — and the SDK reads only the
on-chain pair.

### PDS-3 — multi-epoch correlated-movement + mass-failure detector

PDS-1 catches a single-epoch saturation event. PDS-2 catches a
single-cert velocity anomaly. Neither sees the FINGERPRINT of a 30-
epoch slow drift in which each epoch moves +30 — below the per-hour
velocity cap (PDS-2 passes), below the per-epoch migration fraction
(PDS-1 passes if no big migration happens in any one epoch), but
unambiguous if you watch the rolling window.

`oracle/cluster/correlated_inflation.py` reifies the rolling-window
contract:

- `CORRELATION_WINDOW = 5` — the rolling window over which directional
  share is computed. Five adjacent-epoch pairs is enough to
  distinguish honest noise from coordinated drift.
- `DIRECTIONAL_MIN_DELTA = 25` — agents that move less than 25 points
  epoch-over-epoch don't count toward the up/down tally. Above the
  honest-noise threshold; below the per-epoch clamp. The death
  spiral's signature is `30 points/epoch` sustained — JUST above this
  floor by design (the attacker's exact threshold-evasion point).
  PDS-3 catches it because the directional share is what's anomalous,
  not the magnitude.
- `MAX_DIRECTIONAL_SHARE = 0.85` — if more than 85% of movers in the
  window go the SAME way, the report flags `is_correlated` with the
  direction (`UP` or `DOWN`). 85% is conservative enough that an
  honest market-wide cycle (where genuine signal pulls a majority in
  one direction) is not falsely flagged, but coordinated poisoning
  (where the share approaches 100%) is.
- `MASS_FAILURE_DROP = 200` — a single agent that drops 200+ points
  in one epoch counts as a "failed agent" in the mass-failure tally.
  Matches the per-epoch clamp.
- `MASS_FAILURE_AGENT_FRACTION = 0.50` — if 50%+ of the population
  hits the mass-failure drop in ONE epoch, `verify_mass_failure`
  flags. This is the terminal-phase fingerprint (step 5 of the
  spiral): a correlated detonation of the inflated population.
- `MIN_AGENTS_FOR_CORRELATION = 5` — fails OPEN on small populations
  (bootstrap, pre-launch); the rolling-window math has too much
  variance under N=4.
- The evidence hash is intentionally COUNT-based (`(epoch, up_count,
  down_count, movers)` per pair) so two cluster members producing
  the same window produce the same 64-hex SHA-256 — even though the
  magnitudes may differ. Identical UP-direction attacks at different
  magnitudes produce identical evidence hashes; flipping UP→DOWN
  produces different hashes. This is what makes the report
  forensic-grade: any honest cluster member who reproduces the
  window can prove the attack happened.

`verify_correlated_movement(snapshots)` returns a
`CorrelatedMovementReport`; `verify_mass_failure(snapshot, prior)`
returns a `MassFailureReport`;
`enforce_no_correlated_inflation(snapshots)` raises
`CorrelatedInflationError` (with `.report` attached) for the
fail-closed call path.

### Interaction between the three mitigations

- **PDS-1 ↔ PDS-3**: PDS-1 is the SINGLE-EPOCH refusal gate (pre-
  signing). PDS-3 is the MULTI-EPOCH forensic detector (post-signing,
  forensic). The death spiral that PDS-1 catches in epoch N is the
  same event PDS-3 already flagged in epochs N−5..N−1 as a
  rolling-window correlation. PDS-1 stops the cluster from emitting
  the cert; PDS-3 produces the evidence hash an external auditor can
  reproduce.
- **PDS-2 ↔ PDS-1**: PDS-2 is on the DeFi-consumer side of the trust
  boundary. Even if the cluster were entirely captured and emitted
  a saturated batch (PDS-1 silenced or bypassed), the SDK consumer
  refuses the cert pair locally. This is the only defence that
  survives a cluster-side compromise of all five oracle keys
  simultaneously.
- **PDS-2 ↔ TA-6**: TA-6 enforces `MAX_AGE_SECONDS = 48h` (cert
  freshness). PDS-2 enforces velocity. The two are orthogonal: TA-6
  catches the consumer who acts on STALE data; PDS-2 catches the
  consumer who acts on FRESH data that arrived TOO FAST to be honest.

---

## What the audit gate guarantees

`audit/death_spiral_check.py` runs three probes (PDS-1..PDS-3)
against the as-shipped tree. The gate fails the build if any of the
following goes wrong:

- A marker file is deleted (`saturation_gate.py`, `score_velocity.py`,
  `correlated_inflation.py`).
- A load-bearing function disappears (`verify_saturation` /
  `enforce_saturation`, `verify_score_velocity` /
  `enforce_score_velocity`, `verify_correlated_movement` /
  `verify_mass_failure`).
- A pinned threshold is silently changed (`HIGH_BAND_FLOOR=700`,
  `MAX_HIGH_BAND_MIGRATION_FRACTION=0.40`,
  `ABSOLUTE_HIGH_BAND_CEILING=0.80`,
  `VARIANCE_COLLAPSE_THRESHOLD=0.50`,
  `MAX_SCORE_DELTA_PER_EPOCH=200`,
  `MAX_SCORE_VELOCITY_PER_HOUR=100`,
  `ABSURD_VELOCITY_PER_HOUR=500`, `CORRELATION_WINDOW=5`,
  `MAX_DIRECTIONAL_SHARE=0.85`, `MASS_FAILURE_DROP=200`,
  `MASS_FAILURE_AGENT_FRACTION=0.50`).
- The lockstep cross-check `scoring/_gaming.MAX_SCORE_DELTA = 200`
  drifts — PDS-2's SDK cap is supposed to mirror it. A change in
  either alone is a HARD finding.

The gate is intentionally narrow at the CONTRACT layer — the deeper
validation lives in the per-module property tests
(`tests/oracle/test_pds[1-3]_*.py`, 54 tests total). The audit gate
is the canary that catches a contract-layer regression BEFORE it
reaches the test layer where it might be quietly skipped or rewritten.
The `audit/test_death_spiral_check.py` self-test pins the gate to
0 hard / 0 soft findings on the as-shipped tree.
