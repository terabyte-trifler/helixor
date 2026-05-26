"""
oracle/epoch_advance_liveness.py — FRP-2: epoch-advance liveness
floor for red-team Path 3 sub-leaf 3b ("Exploit VULN-02: epoch
advancement freeze").

THE ATTACK PATH (Freeze-Cert-at-High-Score Path 3, sub-leaf 3b)
---------------------------------------------------------------
VULN-02 is the "attacker stalls epoch advancement to freeze certs at
a high score" family. The existing on-chain defence
(`programs/health-oracle/src/instructions/advance_epoch.rs`) requires
M-of-N cluster signatures (`verify_advance_attestations` +
`config.consensus_threshold()`) and AW-02 provides Tier-2 fallback
recovery at 2× the epoch duration. Together they ensure the cluster
CAN advance — but they do NOT refuse to MINT NEW CERTS during the
stall window itself.

The attacker shape this leaves open:

  1. Compromise/disable N-M+1 cluster nodes so the on-chain advance
     never reaches the M-of-N threshold.
  2. The on-chain epoch clock freezes at E. The DeFi-consumer-facing
     certs at epoch E (issued just before the stall) remain on chain.
  3. The cluster's REMAINING nodes continue to produce per-round
     cert work — but every round signs against the FROZEN epoch.
     DeFi protocols that re-read the cert see the same high score
     for as long as the stall persists.
  4. Past TA-6's 48h `MAX_AGE_SECONDS` ceiling the on-chain freshness
     check fires — but for a 24-hour cycle that's 2× the normal
     interval, well within an attack-attempt window.

FRP-2 closes the cluster-side issuance-during-stall substrate:

  * `MAX_EPOCH_ADVANCE_STALL_SECONDS = 36 * 3600` — 36 hours = 1.5×
    the canonical 24h epoch cycle (matches on-chain
    `DEFAULT_DURATION_SECONDS = 86_400` in
    `health-oracle/src/state/epoch_state.rs`). When the cluster has
    not advanced for longer than this, the off-chain coordinator
    REFUSES to mint any new certs, regardless of the round-level
    state. AW-02's Tier-2 fallback opens at 2× duration (48h), so
    FRP-2's 1.5× floor catches the residual BEFORE Tier-2 even
    needs to engage.
  * `EXPECTED_EPOCH_DURATION_SECONDS = 24 * 3600` — the canonical
    24h epoch duration, mirrored from on-chain
    `DEFAULT_DURATION_SECONDS`. Pinned here so the audit gate can
    cross-check the two clocks have not drifted out of lockstep.
  * `EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS = 60` — single-minute
    clock skew. A `last_epoch_advance_unix` more than 60s ahead of
    `current_unix` is REFUSED as structurally suspect.

CALIBRATION
-----------
- `MAX_EPOCH_ADVANCE_STALL_SECONDS = 36 * 3600`. 1.5× the 24h
  cycle. The canonical operator playbook is "epoch advances on the
  hour" — a 36-hour gap is past the longest historical legitimate
  outage (a maintenance window we observed at ~28h on devnet) and
  well before AW-02's Tier-2 fallback engages at 48h.
- `EXPECTED_EPOCH_DURATION_SECONDS = 24 * 3600`. Mirrors on-chain
  `DEFAULT_DURATION_SECONDS = 86_400`. Audit gate cross-checks the
  two constants so a refactor of one without the other lights red.
- `EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS = 60`. Same tolerance as
  TA-6, ILS-2, and the cluster's other timestamp checks.

INTERACTION WITH VULN-02 / AW-02 / FRP-1 / FRP-3
------------------------------------------------
- VULN-02's on-chain `advance_epoch.rs` enforces M-of-N attestation
  per advance. AW-02 layers Tier-2 fallback at 2× duration. FRP-2
  refuses to mint NEW certs in the gap between the stall starting
  and Tier-2 engaging.
- FRP-1 (`cluster_participation_floor.py`) detects the ROUND-level
  stall (commit-reveal withholding). FRP-2 detects the EPOCH-level
  stall (advance attestation withholding). The two are independent
  substrates of the same VULN-05/VULN-02 attack family — a
  determined attacker may attempt one or the other.
- FRP-3 (`cert_reissue_cadence.py`) closes the per-agent cert-
  reissue cadence — even if the cluster's epoch advances and rounds
  succeed, individual agent certs must be refreshed at least every
  4h.
- AW-02's Tier-2 fallback is the RECOVERY path; FRP-2 is the
  REFUSAL path. They are layered: when the cluster has stalled
  beyond MAX_EPOCH_ADVANCE_STALL_SECONDS, FRP-2 refuses to issue
  certs against the stalled epoch; AW-02's Tier-2 fallback can
  still execute to recover the cluster's epoch advancement and
  return to a healthy state where FRP-2 no longer fires.

DETERMINISM
-----------
Pure stdlib. Integer arithmetic on `(current_unix,
last_epoch_advance_unix)`. No clock, no network, no randomness.
"""

from __future__ import annotations

from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

#: Maximum tolerated seconds between successful epoch advances.
#: 36h = 1.5× the canonical 24h epoch cycle. Stalls beyond this
#: refuse cert issuance until the cluster advances.
MAX_EPOCH_ADVANCE_STALL_SECONDS = 36 * 3600

#: Canonical epoch duration in seconds. Mirrors the on-chain
#: `DEFAULT_DURATION_SECONDS = 86_400` in
#: `programs/health-oracle/src/state/epoch_state.rs`. Cross-checked
#: by the audit gate.
EXPECTED_EPOCH_DURATION_SECONDS = 24 * 3600

#: Single-minute clock-skew tolerance for the advance timestamp.
EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS = 60

#: Status labels.
EPOCH_ADVANCE_OK = "OK"
EPOCH_ADVANCE_REFUSED = "REFUSED"

#: Reason codes.
REASON_EPOCH_ADVANCE_STALL = "EPOCH_ADVANCE_STALL"
REASON_EPOCH_ADVANCE_TIMESTAMP_IN_FUTURE = (
    "EPOCH_ADVANCE_TIMESTAMP_IN_FUTURE"
)
REASON_EPOCH_ADVANCE_TIMESTAMP_INVALID = (
    "EPOCH_ADVANCE_TIMESTAMP_INVALID"
)
REASON_EPOCH_ADVANCE_EPOCH_NOT_MONOTONIC = (
    "EPOCH_ADVANCE_EPOCH_NOT_MONOTONIC"
)
REASON_EPOCH_ADVANCE_EPOCH_INVALID = "EPOCH_ADVANCE_EPOCH_INVALID"


# =============================================================================
# Errors
# =============================================================================

class EpochAdvanceStallError(RuntimeError):
    """
    Raised by `enforce_epoch_advance_liveness` when the cluster has
    not advanced its epoch in longer than
    MAX_EPOCH_ADVANCE_STALL_SECONDS.
    """

    def __init__(
        self, message: str, report: "EpochAdvanceLivenessReport"
    ):
        super().__init__(message)
        self.report = report


# =============================================================================
# Records
# =============================================================================

@dataclass(frozen=True, slots=True)
class EpochAdvanceState:
    """
    The cluster's epoch-advance liveness state at the moment a cert
    is about to be issued.

    `last_epoch_advance_unix`  unix-seconds timestamp of the most
                               recent successful epoch advance.
    `current_unix`             unix-seconds NOW (wall clock at the
                               coordinator).
    `last_advanced_epoch`      the epoch the cluster advanced INTO
                               at `last_epoch_advance_unix`.
    `current_epoch`            the cluster's view of "the epoch we
                               are in now" — for an unstalled
                               cluster this == last_advanced_epoch.
    """
    last_epoch_advance_unix: int
    current_unix:            int
    last_advanced_epoch:     int
    current_epoch:           int


@dataclass(frozen=True, slots=True)
class EpochAdvanceLivenessReport:
    """
    Verdict of one FRP-2 check.

    `status`              EPOCH_ADVANCE_OK / EPOCH_ADVANCE_REFUSED.
    `seconds_since_last`  current_unix - last_epoch_advance_unix.
    `stall_floor`         MAX_EPOCH_ADVANCE_STALL_SECONDS.
    `epoch_delta`         current_epoch - last_advanced_epoch
                          (typically 0 in healthy state).
    `current_unix`        echoed.
    `last_epoch_advance_unix` echoed.
    `reasons`             reason codes; empty when OK.
    """
    status:                  str
    seconds_since_last:      int
    stall_floor:             int
    expected_epoch_duration: int
    epoch_delta:             int
    current_unix:            int
    last_epoch_advance_unix: int
    reasons:                 tuple[str, ...]

    @property
    def is_allowed(self) -> bool:
        return self.status == EPOCH_ADVANCE_OK


# =============================================================================
# Verifier (pure)
# =============================================================================

def verify_epoch_advance_liveness(
    state: EpochAdvanceState,
) -> EpochAdvanceLivenessReport:
    """
    Decide whether the cluster's epoch-advance liveness permits
    cert issuance.

    Rules:
      * `last_epoch_advance_unix < 1` -> REFUSED,
        EPOCH_ADVANCE_TIMESTAMP_INVALID (uninitialised cluster).
      * `last_epoch_advance_unix > current_unix +
        EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS` -> REFUSED,
        EPOCH_ADVANCE_TIMESTAMP_IN_FUTURE.
      * `last_advanced_epoch < 0` -> REFUSED,
        EPOCH_ADVANCE_EPOCH_INVALID.
      * `current_epoch < last_advanced_epoch` -> REFUSED,
        EPOCH_ADVANCE_EPOCH_NOT_MONOTONIC.
      * `current_unix - last_epoch_advance_unix >
        MAX_EPOCH_ADVANCE_STALL_SECONDS` -> REFUSED,
        EPOCH_ADVANCE_STALL. (Inclusive at the floor — exactly
        36h is still OK, 36h + 1s is REFUSED.)

    Pure: no logging, no I/O.
    """
    reasons: list[str] = []

    last = state.last_epoch_advance_unix
    now = state.current_unix

    if last < 1:
        reasons.append(REASON_EPOCH_ADVANCE_TIMESTAMP_INVALID)

    if last > now + EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS:
        reasons.append(REASON_EPOCH_ADVANCE_TIMESTAMP_IN_FUTURE)

    if state.last_advanced_epoch < 0:
        reasons.append(REASON_EPOCH_ADVANCE_EPOCH_INVALID)

    if state.current_epoch < state.last_advanced_epoch:
        reasons.append(REASON_EPOCH_ADVANCE_EPOCH_NOT_MONOTONIC)

    seconds_since = max(now - last, 0)
    if seconds_since > MAX_EPOCH_ADVANCE_STALL_SECONDS:
        reasons.append(REASON_EPOCH_ADVANCE_STALL)

    status = (
        EPOCH_ADVANCE_OK if not reasons else EPOCH_ADVANCE_REFUSED
    )

    return EpochAdvanceLivenessReport(
        status=status,
        seconds_since_last=seconds_since,
        stall_floor=MAX_EPOCH_ADVANCE_STALL_SECONDS,
        expected_epoch_duration=EXPECTED_EPOCH_DURATION_SECONDS,
        epoch_delta=state.current_epoch - state.last_advanced_epoch,
        current_unix=now,
        last_epoch_advance_unix=last,
        reasons=tuple(reasons),
    )


# =============================================================================
# Enforcement (fail-closed wrapper)
# =============================================================================

def enforce_epoch_advance_liveness(
    state: EpochAdvanceState,
) -> EpochAdvanceLivenessReport:
    """
    Run `verify_epoch_advance_liveness` and raise on any violation.
    Returns the report when status == EPOCH_ADVANCE_OK.
    """
    report = verify_epoch_advance_liveness(state)
    if report.is_allowed:
        return report
    raise EpochAdvanceStallError(
        f"FRP-2: epoch-advance liveness refused — "
        f"seconds_since_last_advance={report.seconds_since_last} "
        f"(stall floor {report.stall_floor}), "
        f"epoch_delta={report.epoch_delta}, "
        f"reasons={list(report.reasons)!r}. "
        f"The cluster MUST NOT mint certs while epoch advancement "
        f"has been stalled past {MAX_EPOCH_ADVANCE_STALL_SECONDS}s "
        f"(1.5× the canonical 24h cycle) — this is the fingerprint "
        f"of a VULN-02 advance-attestation withholding attack.",
        report,
    )


__all__ = [
    "EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS",
    "EPOCH_ADVANCE_OK",
    "EPOCH_ADVANCE_REFUSED",
    "EXPECTED_EPOCH_DURATION_SECONDS",
    "EpochAdvanceLivenessReport",
    "EpochAdvanceStallError",
    "EpochAdvanceState",
    "MAX_EPOCH_ADVANCE_STALL_SECONDS",
    "REASON_EPOCH_ADVANCE_EPOCH_INVALID",
    "REASON_EPOCH_ADVANCE_EPOCH_NOT_MONOTONIC",
    "REASON_EPOCH_ADVANCE_STALL",
    "REASON_EPOCH_ADVANCE_TIMESTAMP_INVALID",
    "REASON_EPOCH_ADVANCE_TIMESTAMP_IN_FUTURE",
    "enforce_epoch_advance_liveness",
    "verify_epoch_advance_liveness",
]
