"""
oracle/baseline_rotation_guard.py — ILS-1: baseline-rotation cadence
and co-attestation guard for red-team Path 2 sub-leaf 2a ("Exploit
VULN-06: baseline overwrite").

THE ATTACK PATH (Inflate-Legitimate-Score Path 2, sub-leaf 2a)
--------------------------------------------------------------
VULN-06 is the "single signer rotates an agent's baseline to an
arbitrary hash" family. The on-chain defence
(`programs/certificate-issuer/src/instructions/record_baseline.rs`)
already ships three orthogonal mitigations:

  * Broadened authority (`is_authorised_baseline_writer`) — signer
    must be EITHER the agent itself OR a cluster key. No single key
    controls all baselines.
  * Append-only epoch monotonicity — once recorded at epoch E, the
    next rotation must carry `epoch > E`; same-epoch rotation is
    rejected with `BaselineRotationTooSoon`, earlier with
    `BaselineEpochNotMonotonic`.
  * Non-zero epoch — `epoch >= 1`, sentinel ambiguity closed.

What none of those defences see is the RATE and the WITNESS COUNT
of the rotation. An attacker who has compromised a single cluster
key can still rotate any agent's baseline ONCE EVERY EPOCH (the
on-chain monotonicity check accepts `epoch + 1` immediately) and
do so unilaterally (the broadened authority permits a single cluster
signer). Over a 30-epoch campaign the attacker can grind the
baseline to whatever value inflates the resulting score most. The
on-chain handler sees each rotation in isolation and waves it
through.

ILS-1 closes the rotation-rate and witness-count substrates:

  * `MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS = 30` — a baseline
    cannot rotate more often than once per 30 epochs (60h at the
    canonical 2h epoch cadence). The attacker's per-epoch baseline
    grind becomes a per-30-epoch grind — 30x slower, 30x more
    visible to honest operators, and meaningfully bounded by
    FHS-1's 90-day cluster-key rotation floor (an attacker who
    compromised a key has at most ~30 rotation windows before
    their key ages out).
  * `MIN_BASELINE_COSIGNERS = 2` — a baseline rotation needs the
    agent's signature AND at least one cluster signer, i.e. the
    SUM of distinct signing principals must be >= 2. A single
    compromised cluster key acting alone cannot rotate any
    baseline; a single compromised agent key acting alone cannot
    either. The attacker needs to compromise BOTH a cluster key
    AND the specific agent's key, which transforms VULN-06 from
    LOW EFFORT into HIGH EFFORT and pins it behind FHS-1/2/3.

CALIBRATION
-----------
- `MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS = 30` — 30 epochs at the
  2h epoch cadence = 60h = 2.5 days. Calibrated against operator
  expectation: a legitimate baseline rotation is a deliberate
  ceremony (the agent's strategy has changed enough that the
  cluster needs to re-baseline), not a continuous adjustment. The
  2.5-day floor leaves 12 rotation slots per quarter and 48 per
  year, well within legitimate-rotation budget.
- `MIN_BASELINE_COSIGNERS = 2` — matches the on-chain
  `is_authorised_baseline_writer` policy (agent OR cluster), but
  promotes it to (agent AND cluster). Pinned as a constant so the
  audit gate can grep for it.
- `BASELINE_FUTURE_TOLERANCE_EPOCHS = 1` — one epoch's worth of
  clock skew. A baseline whose `epoch` is more than 1 epoch past
  the cluster's current epoch is REFUSED as structurally suspect.

INTERACTION WITH VULN-06 / ILS-2 / ILS-3 / FHS-1
------------------------------------------------
- VULN-06's on-chain `record_baseline.rs` does the per-rotation
  validation (authority, epoch monotonicity, non-zero epoch). THIS
  module is the OFF-CHAIN pre-flight that the propose-rotation
  coordinator runs BEFORE broadcasting; a refusal here saves the
  rotation tx and the associated cluster signature.
- ILS-2 (`feature_corroboration.py`) closes the producer-key
  poisoning substrate — even if a baseline rotates, the FEATURES
  it summarises must be backed by >=2 distinct producers. ILS-1
  bounds the RATE of baseline rotations; ILS-2 bounds the
  PROVENANCE of the features that get baked in.
- ILS-3 (`score_drift_ceiling.py`) closes the cumulative-drift
  substrate — even if a baseline rotates and the features pass
  corroboration, the SCORE that issues against the new baseline
  cannot inflate beyond a hard ceiling. The three are independent.
- FHS-1 (`key_rotation_cadence.py`) bounds the lifetime of any
  compromised cluster key to 90 days. With ILS-1's 2.5-day
  rotation floor, an attacker has at most ~36 baseline-rotation
  windows per compromised key — and ILS-1's co-signer floor
  forces them to also compromise the agent's key per agent they
  want to baseline-grind.

DETERMINISM
-----------
Pure stdlib. Integer arithmetic on `(last_epoch, current_epoch)`
and length checks on the cosigner tuple. No clock, no network, no
randomness.
"""

from __future__ import annotations

from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

#: Minimum number of epochs between consecutive baseline rotations
#: for the same agent. A baseline cannot rotate more often than this.
MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS = 30

#: Minimum number of DISTINCT signing principals required to attest a
#: baseline rotation. Pinned at 2: the agent + at least one cluster
#: signer. A single compromised cluster key cannot rotate alone.
MIN_BASELINE_COSIGNERS = 2

#: Future-skew tolerance in epochs. A baseline whose proposed `epoch`
#: is more than this many epochs past `current_epoch` is REFUSED.
BASELINE_FUTURE_TOLERANCE_EPOCHS = 1

#: Status labels. Stable strings the audit gate + operator runbook
#: grep for.
BASELINE_OK = "OK"
BASELINE_REFUSED = "REFUSED"

#: Reason codes.
REASON_BASELINE_ROTATION_TOO_SOON = "BASELINE_ROTATION_TOO_SOON"
REASON_BASELINE_INSUFFICIENT_COSIGNERS = "BASELINE_INSUFFICIENT_COSIGNERS"
REASON_BASELINE_DUPLICATE_COSIGNER = "BASELINE_DUPLICATE_COSIGNER"
REASON_BASELINE_AGENT_MISSING_FROM_COSIGNERS = (
    "BASELINE_AGENT_MISSING_FROM_COSIGNERS"
)
REASON_BASELINE_EPOCH_NOT_MONOTONIC = "BASELINE_EPOCH_NOT_MONOTONIC"
REASON_BASELINE_EPOCH_IN_FUTURE = "BASELINE_EPOCH_IN_FUTURE"
REASON_BASELINE_EPOCH_INVALID = "BASELINE_EPOCH_INVALID"


# =============================================================================
# Errors
# =============================================================================

class BaselineRotationRefusedError(RuntimeError):
    """
    Raised by `enforce_baseline_rotation` when a proposed baseline
    rotation fails the cadence-or-cosigner contract.

    `.report` carries the structured verdict so the on-call operator
    can decide whether to wait for the cadence window or whether the
    cluster genuinely needs to add a cosigner.
    """

    def __init__(self, message: str, report: "BaselineRotationReport"):
        super().__init__(message)
        self.report = report


# =============================================================================
# Records
# =============================================================================

@dataclass(frozen=True, slots=True)
class BaselineRotationProposal:
    """
    One baseline-rotation proposal as it arrives at the off-chain
    coordinator.

    `agent_wallet`         the agent whose baseline would rotate.
    `proposed_epoch`       the `epoch` field of the new baseline
                           record (the cluster's view of the epoch
                           at which the new baseline becomes
                           effective).
    `last_recorded_epoch`  the agent's currently-effective
                           baseline's `epoch_recorded`. -1 if the
                           agent has never had a baseline.
    `current_epoch`        the cluster's current epoch (so the
                           verifier can refuse future-dated
                           proposals).
    `cosigners`            tuple of distinct signing principals
                           attesting to the rotation. Convention:
                           the agent's wallet appears first; cluster
                           signers follow.
    """
    agent_wallet:         str
    proposed_epoch:       int
    last_recorded_epoch:  int
    current_epoch:        int
    cosigners:            tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BaselineRotationReport:
    """
    Verdict of one ILS-1 check.

    `status`            BASELINE_OK / BASELINE_REFUSED.
    `agent_wallet`      echoed.
    `proposed_epoch`    echoed.
    `last_recorded_epoch`  echoed.
    `current_epoch`     echoed.
    `epoch_delta`       proposed - last_recorded (negative if first
                        baseline ever).
    `cosigner_count`    |distinct cosigners|.
    `required_cosigners` MIN_BASELINE_COSIGNERS.
    `min_epoch_delta`   MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS.
    `reasons`           reason codes; empty when OK.
    """
    status:              str
    agent_wallet:        str
    proposed_epoch:      int
    last_recorded_epoch: int
    current_epoch:       int
    epoch_delta:         int
    cosigner_count:      int
    required_cosigners:  int
    min_epoch_delta:     int
    reasons:             tuple[str, ...]

    @property
    def is_allowed(self) -> bool:
        return self.status == BASELINE_OK


# =============================================================================
# Verifier (pure)
# =============================================================================

def verify_baseline_rotation(
    proposal: BaselineRotationProposal,
) -> BaselineRotationReport:
    """
    Decide whether a proposed baseline rotation respects the cadence
    and co-attestation contract.

    The rules:
      * `proposed_epoch < 1` -> REFUSED, BASELINE_EPOCH_INVALID
        (mirrors on-chain `epoch >= 1` from `record_baseline.rs`).
      * `proposed_epoch > current_epoch + BASELINE_FUTURE_TOLERANCE_
        EPOCHS` -> REFUSED, BASELINE_EPOCH_IN_FUTURE.
      * `proposed_epoch <= last_recorded_epoch` (and the agent has
        a prior baseline) -> REFUSED, BASELINE_EPOCH_NOT_MONOTONIC
        (mirrors the on-chain monotonicity check).
      * `proposed_epoch - last_recorded_epoch <
        MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS` (and the agent has a
        prior baseline) -> REFUSED, BASELINE_ROTATION_TOO_SOON.
        This is the ILS-1 cadence floor that the on-chain handler
        does NOT enforce.
      * `len(set(cosigners)) < MIN_BASELINE_COSIGNERS` -> REFUSED,
        BASELINE_INSUFFICIENT_COSIGNERS.
      * `len(cosigners) != len(set(cosigners))` -> REFUSED,
        BASELINE_DUPLICATE_COSIGNER (a duplicate signature does not
        count as an additional cosigner).
      * `agent_wallet not in cosigners` -> REFUSED,
        BASELINE_AGENT_MISSING_FROM_COSIGNERS (the agent's own
        attestation is required; a baseline rotation by cluster
        signers alone is refused).

    Pure: no logging, no I/O.
    """
    reasons: list[str] = []

    proposed = proposal.proposed_epoch
    last = proposal.last_recorded_epoch
    current = proposal.current_epoch

    if proposed < 1:
        reasons.append(REASON_BASELINE_EPOCH_INVALID)
    if proposed > current + BASELINE_FUTURE_TOLERANCE_EPOCHS:
        reasons.append(REASON_BASELINE_EPOCH_IN_FUTURE)

    epoch_delta = proposed - last
    has_prior = last >= 1
    if has_prior:
        if proposed <= last:
            reasons.append(REASON_BASELINE_EPOCH_NOT_MONOTONIC)
        elif epoch_delta < MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS:
            reasons.append(REASON_BASELINE_ROTATION_TOO_SOON)

    cosigners = proposal.cosigners
    cosigner_set = set(cosigners)
    if len(cosigner_set) != len(cosigners):
        reasons.append(REASON_BASELINE_DUPLICATE_COSIGNER)
    if len(cosigner_set) < MIN_BASELINE_COSIGNERS:
        reasons.append(REASON_BASELINE_INSUFFICIENT_COSIGNERS)
    if proposal.agent_wallet not in cosigner_set:
        reasons.append(REASON_BASELINE_AGENT_MISSING_FROM_COSIGNERS)

    status = BASELINE_OK if not reasons else BASELINE_REFUSED

    return BaselineRotationReport(
        status=status,
        agent_wallet=proposal.agent_wallet,
        proposed_epoch=proposed,
        last_recorded_epoch=last,
        current_epoch=current,
        epoch_delta=epoch_delta,
        cosigner_count=len(cosigner_set),
        required_cosigners=MIN_BASELINE_COSIGNERS,
        min_epoch_delta=MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS,
        reasons=tuple(reasons),
    )


# =============================================================================
# Enforcement (fail-closed wrapper)
# =============================================================================

def enforce_baseline_rotation(
    proposal: BaselineRotationProposal,
) -> BaselineRotationReport:
    """
    Run `verify_baseline_rotation` and raise on any violation.

    Returns the report when status == BASELINE_OK. Raises
    `BaselineRotationRefusedError` otherwise — the propose-baseline
    tx should NOT be broadcast.
    """
    report = verify_baseline_rotation(proposal)
    if report.is_allowed:
        return report
    raise BaselineRotationRefusedError(
        f"ILS-1: baseline rotation refused — "
        f"agent={report.agent_wallet!r}, "
        f"proposed_epoch={report.proposed_epoch}, "
        f"last_recorded={report.last_recorded_epoch}, "
        f"current={report.current_epoch}, "
        f"epoch_delta={report.epoch_delta} (need >= "
        f"{report.min_epoch_delta}), "
        f"cosigners={report.cosigner_count} (need >= "
        f"{report.required_cosigners}), "
        f"reasons={list(report.reasons)!r}. "
        f"A baseline rotation MAY happen at most once per "
        f"{MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS} epochs and MUST "
        f"be co-attested by the agent + at least one cluster "
        f"signer.",
        report,
    )


__all__ = [
    "BASELINE_FUTURE_TOLERANCE_EPOCHS",
    "BASELINE_OK",
    "BASELINE_REFUSED",
    "BaselineRotationProposal",
    "BaselineRotationRefusedError",
    "BaselineRotationReport",
    "MIN_BASELINE_COSIGNERS",
    "MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS",
    "REASON_BASELINE_AGENT_MISSING_FROM_COSIGNERS",
    "REASON_BASELINE_DUPLICATE_COSIGNER",
    "REASON_BASELINE_EPOCH_INVALID",
    "REASON_BASELINE_EPOCH_IN_FUTURE",
    "REASON_BASELINE_EPOCH_NOT_MONOTONIC",
    "REASON_BASELINE_INSUFFICIENT_COSIGNERS",
    "REASON_BASELINE_ROTATION_TOO_SOON",
    "enforce_baseline_rotation",
    "verify_baseline_rotation",
]
