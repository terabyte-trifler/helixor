"""
oracle/rotation_overlap_guard.py — FHS-3: cluster-key rotation
overlap guard for red-team Path 1 sub-leaf 1c ("Exploit VULN-13:
replace all oracle keys").

THE ATTACK PATH (Forge-High-Score-Cert Path 1, sub-leaf 1c)
-----------------------------------------------------------
VULN-13 is the "single admin replaces all 5 cluster keys at once"
family. The on-chain defence
(`programs/health-oracle/src/state/pending_oracle_rotation.rs`)
already removes the single-admin override and ships a propose /
attest / enact ceremony with a 48-hour timelock and an N-of-M
attestation gate computed against the LIVE cluster. The
`slash-authority::update_authorities` instruction also returns
`SingleAdminUpdateRemoved` on every call.

What none of those defences see is the SHAPE of the proposed new
key set. An attacker who has compromised K = 3 of the 5 cluster
keys can still propose `new_keys = [attacker0, attacker1,
attacker2, attacker3, attacker4]` — five attacker-controlled keys.
The proposal needs K attestations from the LIVE cluster, which the
attacker has. After the 48h timelock the rotation enacts, and the
attacker now owns the entire cluster.

FHS-3 closes the wholesale-replacement substrate. The verifier
refuses any rotation whose `new_keys` set does not overlap with the
`current_keys` set by at least `threshold - 1` keys (i.e. K - 1 of
the original keys must remain). For a 3-of-5 cluster the rotation
can replace AT MOST ONE key per ceremony. Combined with the 48h
timelock, replacing the whole cluster takes a minimum of
5 ceremonies * 48h = 10 days of public on-chain activity — every
ceremony is an opportunity for the honest operators of the
remaining keys (who would never attest to having their own keys
removed) to refuse.

CALIBRATION
-----------
The overlap floor is derived from the threshold, not pinned as an
absolute constant:

    required_overlap = max(threshold - 1, 0)

For a 3-of-5 cluster this gives `required_overlap = 2`. For a
5-of-9 cluster this gives `required_overlap = 4`. The principle is
"at most ONE key may change per rotation cycle, regardless of
cluster size or threshold".

Additional sanity constants:

- `MAX_KEYS_REPLACED_PER_ROTATION = 1` — the contract this module
  enforces. Pinned as a constant so the audit gate can grep for it.
- `MIN_NEW_KEYS_REPRESENTATION` is intentionally NOT defined — the
  caller's existing on-chain `pending_oracle_rotation` validator
  already refuses empty / undersized new sets via Anchor account
  size constraints.

INTERACTION WITH NSS-1 / NSS-2 / FHS-1 / VULN-13
------------------------------------------------
- VULN-13's on-chain `pending_oracle_rotation.rs` enforces the 48h
  timelock + N-of-M attestation. THIS module is the OFF-CHAIN
  pre-flight that the propose-ceremony coordinator runs BEFORE
  broadcasting the propose tx; a refusal here saves the cluster
  the 48h timelock on a proposal that would later be rejected by
  honest attesters.
- FHS-1 (`key_rotation_cadence.py`) forces the cluster to rotate
  keys every 90 days — this module ensures EVERY ROTATION CEREMONY
  CHANGES AT MOST ONE KEY. Without FHS-3, FHS-1 would actually
  re-enable the wholesale-replacement attack by encouraging large
  multi-key rotations.
- NSS-1 (`cloud_diversity.py`) constrains the NODE topology — this
  module constrains the PROPOSAL diff.

DETERMINISM
-----------
Pure stdlib. Builds two sets and computes their intersection. No
clock, no network, no randomness.
"""

from __future__ import annotations

from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

#: The pinned contract this module enforces: at most ONE cluster key
#: may be replaced per rotation ceremony, regardless of cluster size.
MAX_KEYS_REPLACED_PER_ROTATION = 1

#: Status labels.
OVERLAP_OK = "OK"
OVERLAP_REFUSED = "REFUSED"

#: Reason codes.
REASON_WHOLESALE_REPLACEMENT = "WHOLESALE_REPLACEMENT"
REASON_INSUFFICIENT_OVERLAP = "INSUFFICIENT_OVERLAP"
REASON_NEW_KEYS_DUPLICATE = "NEW_KEYS_DUPLICATE"
REASON_NEW_KEYS_EMPTY = "NEW_KEYS_EMPTY"
REASON_THRESHOLD_INVALID = "THRESHOLD_INVALID"


# =============================================================================
# Errors
# =============================================================================

class RotationOverlapError(RuntimeError):
    """
    Raised by `enforce_rotation_overlap` when a proposed rotation
    fails the overlap contract.

    `.report` carries the structured verdict (current vs proposed
    sets, intersection size, threshold) so the on-call operator can
    decide whether to split the rotation into multiple ceremonies.
    """

    def __init__(self, message: str, report: "RotationOverlapReport"):
        super().__init__(message)
        self.report = report


# =============================================================================
# Records
# =============================================================================

@dataclass(frozen=True, slots=True)
class RotationProposal:
    """
    One rotation proposal as it arrives at the off-chain coordinator.

    `current_keys` the cluster's currently-active key set (the LIVE
                   `OracleConfig.oracle_keys`).
    `proposed_keys` the set the propose-rotation transaction would
                   set the cluster to once enacted.
    `threshold`    the cluster's K (computed by `consensus_threshold(
                   current_keys)` in the Rust handler). Pinned in
                   the proposal so the off-chain verifier knows the
                   required overlap floor.
    """
    current_keys:  tuple[str, ...]
    proposed_keys: tuple[str, ...]
    threshold:     int


@dataclass(frozen=True, slots=True)
class RotationOverlapReport:
    """
    Verdict of one FHS-3 check.

    `status`            OVERLAP_OK / REFUSED.
    `current_size`      |current_keys|.
    `proposed_size`     |proposed_keys|.
    `overlap_size`      |current_keys ∩ proposed_keys|.
    `replaced_size`     |current_keys - proposed_keys|.
    `added_size`        |proposed_keys - current_keys|.
    `required_overlap`  max(threshold - 1, 0) — derived from the
                        proposal's threshold.
    `threshold`         echoed.
    `keys_removed`      sorted tuple of `current - proposed`.
    `keys_added`        sorted tuple of `proposed - current`.
    `reasons`           reason codes; empty when OK.
    """
    status:           str
    current_size:     int
    proposed_size:    int
    overlap_size:     int
    replaced_size:    int
    added_size:       int
    required_overlap: int
    threshold:        int
    keys_removed:     tuple[str, ...]
    keys_added:       tuple[str, ...]
    reasons:          tuple[str, ...]

    @property
    def is_allowed(self) -> bool:
        return self.status == OVERLAP_OK


# =============================================================================
# Verifier (pure)
# =============================================================================

def verify_rotation_overlap(
    proposal: RotationProposal,
) -> RotationOverlapReport:
    """
    Decide whether a proposed cluster-key rotation respects the
    overlap contract.

    The rule:
      * `threshold <= 0` -> REFUSED, reason THRESHOLD_INVALID.
      * `proposed_keys` empty -> REFUSED, reason NEW_KEYS_EMPTY.
      * Any duplicate inside `proposed_keys` -> REFUSED, reason
        NEW_KEYS_DUPLICATE. The on-chain handler also rejects this
        but the off-chain pre-flight catches it before the 48h
        timelock burns.
      * `replaced_size > MAX_KEYS_REPLACED_PER_ROTATION` ->
        REFUSED, reason WHOLESALE_REPLACEMENT. The principle is "at
        most one key changes per ceremony".
      * `overlap_size < max(threshold - 1, 0)` -> REFUSED, reason
        INSUFFICIENT_OVERLAP. Belt-and-braces with the previous rule
        for unusual cluster geometries.

    Pure: no logging, no environment reads, no I/O.
    """
    reasons: list[str] = []

    threshold = proposal.threshold
    current = tuple(proposal.current_keys)
    proposed = tuple(proposal.proposed_keys)
    current_set = set(current)
    proposed_set = set(proposed)

    if threshold <= 0:
        reasons.append(REASON_THRESHOLD_INVALID)

    if not proposed:
        reasons.append(REASON_NEW_KEYS_EMPTY)

    if len(proposed_set) != len(proposed):
        reasons.append(REASON_NEW_KEYS_DUPLICATE)

    overlap = current_set & proposed_set
    removed = current_set - proposed_set
    added = proposed_set - current_set

    required_overlap = max(threshold - 1, 0)

    if len(removed) > MAX_KEYS_REPLACED_PER_ROTATION:
        reasons.append(REASON_WHOLESALE_REPLACEMENT)
    if len(overlap) < required_overlap:
        reasons.append(REASON_INSUFFICIENT_OVERLAP)

    status = OVERLAP_OK if not reasons else OVERLAP_REFUSED

    return RotationOverlapReport(
        status=status,
        current_size=len(current),
        proposed_size=len(proposed),
        overlap_size=len(overlap),
        replaced_size=len(removed),
        added_size=len(added),
        required_overlap=required_overlap,
        threshold=threshold,
        keys_removed=tuple(sorted(removed)),
        keys_added=tuple(sorted(added)),
        reasons=tuple(reasons),
    )


# =============================================================================
# Enforcement (fail-closed wrapper)
# =============================================================================

def enforce_rotation_overlap(
    proposal: RotationProposal,
) -> RotationOverlapReport:
    """
    Run `verify_rotation_overlap` and raise on any violation.

    Returns the report when status == OVERLAP_OK. Raises
    `RotationOverlapError` otherwise — the propose-rotation tx
    should NOT be broadcast.
    """
    report = verify_rotation_overlap(proposal)
    if report.is_allowed:
        return report
    raise RotationOverlapError(
        f"FHS-3: rotation overlap refused — "
        f"replaced={report.replaced_size} > "
        f"{MAX_KEYS_REPLACED_PER_ROTATION}, "
        f"overlap={report.overlap_size} < {report.required_overlap}, "
        f"removed={list(report.keys_removed)!r}, "
        f"added={list(report.keys_added)!r}, "
        f"reasons={list(report.reasons)!r}. "
        f"A rotation MAY change at most one cluster key per "
        f"ceremony — split the proposal into multiple sequential "
        f"rotations.",
        report,
    )


__all__ = [
    "MAX_KEYS_REPLACED_PER_ROTATION",
    "OVERLAP_OK",
    "OVERLAP_REFUSED",
    "REASON_INSUFFICIENT_OVERLAP",
    "REASON_NEW_KEYS_DUPLICATE",
    "REASON_NEW_KEYS_EMPTY",
    "REASON_THRESHOLD_INVALID",
    "REASON_WHOLESALE_REPLACEMENT",
    "RotationOverlapError",
    "RotationOverlapReport",
    "RotationProposal",
    "enforce_rotation_overlap",
    "verify_rotation_overlap",
]
