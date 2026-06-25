"""
oracle/cluster_participation_floor.py — FRP-1: cluster participation
floor for red-team Path 3 sub-leaf 3a ("Exploit VULN-05: commit-reveal
block").

THE ATTACK PATH (Freeze-Cert-at-High-Score Path 3, sub-leaf 3a)
---------------------------------------------------------------
VULN-05 is the "attacker withholds commit-reveal shares to stall the
cluster" family. The existing cluster-side defence
(`oracle/cluster/commit_reveal_round.py`) already ships:

  * Hard `reveal_deadline` — reveals at-or-after the deadline are
    rejected unconditionally.
  * Partial-reveal quorum — round closes early when
    `verified_count >= min_reveals`, so a stalling minority cannot
    block the round forever.
  * `non_revealers()` strike tracking — committed-but-silent nodes
    accumulate strikes for downstream eviction.

What none of those defences see is the FLEET-WIDE pattern: an
attacker who has compromised K nodes can keep submitting JUST ENOUGH
reveals to scrape past `min_reveals` every round while keeping the
participating-node count pinned at the bare-quorum floor. The cluster
keeps closing rounds and minting certs — but every cert is signed by
a "minimum quorum" set. An honest cluster never sustains minimum-
quorum operation; it only happens during a real attack or a real
outage. Either way, MINTING CERTS in that state freezes the score at
whatever value the few participants agree on, which is exactly the
attacker's goal.

FRP-1 closes the fleet-wide participation substrate:

  * `MIN_HEALTHY_PARTICIPATION_RATIO = 0.8` — an honest cluster
    operates with at least 80% of nodes participating per round.
    Sustained participation below this ratio is the attacker's
    fingerprint.
  * `MAX_BARELY_QUORATE_ROUNDS = 3` — at most 3 consecutive rounds
    may close at the bare-quorum margin. A 4th consecutive
    barely-quorate round REFUSES cert issuance entirely. This
    forces the cluster to fail-closed during a sustained stall
    rather than continuing to mint certs at minimum quorum.
  * `BARELY_QUORATE_MARGIN = 1` — a round is "barely quorate" when
    `participating_node_count <= quorum_threshold + 1`. The
    +1 margin lets an honest cluster with one transient outage
    sneak through; a sustained pattern of exactly-quorum or
    quorum+1 rounds is what FRP-1 refuses.

CALIBRATION
-----------
- `MIN_HEALTHY_PARTICIPATION_RATIO = 0.8`. The cluster operates with
  N=5 nodes and a quorum of K=3 in canonical configuration. 80% =
  4-of-5 = a single tolerated outage. Lower ratios (3-of-5 = 60%)
  ARE the bare-quorum state FRP-1 is alarmed about.
- `MAX_BARELY_QUORATE_ROUNDS = 3`. Three consecutive rounds at
  bare-quorum margin are tolerated (transient: a node restart, a
  partition repair, an upgrade window). Four consecutive rounds is
  the cliff edge — by then any honest outage would have been
  noticed and recovered.
- `BARELY_QUORATE_MARGIN = 1`. With N=5 / K=3 this means rounds
  with participating_count ∈ {3, 4} are "barely quorate"; 5 is
  "healthy". With N=9 / K=5 it means {5, 6} are barely quorate;
  7+ is healthy.

INTERACTION WITH VULN-05 / FRP-2 / FRP-3 / SOL-1
------------------------------------------------
- VULN-05's `commit_reveal_round.py` enforces the per-round timeout
  and per-node strikes. THIS module is the FLEET-WIDE pre-flight
  that the cert-issuance coordinator runs after the round closes
  but BEFORE submitting the cert tx. A refusal here saves the
  cluster from broadcasting a cert that would freeze an inflated
  score.
- FRP-2 (`epoch_advance_liveness.py`) closes the epoch-advance
  substrate — when the epoch clock itself stalls (not just one
  round but the whole advance pipeline). FRP-1 detects the round-
  level pattern; FRP-2 detects the epoch-level stall.
- FRP-3 (`cert_reissue_cadence.py`) closes the per-agent cert-
  reissue cadence — even if the cluster is healthy, individual
  agent certs must be refreshed at least every 4h.
- SOL-1 (`cluster_liveness.py`) is the CONSUMER-side signal that
  the cluster IS in a degraded state (so DeFi protocols can fall
  back). FRP-1 is the CLUSTER-side refusal that PREVENTS a
  degraded-state cert from being issued in the first place.

DETERMINISM
-----------
Pure stdlib. Integer arithmetic on per-round samples + ratio compare
against MIN_HEALTHY_PARTICIPATION_RATIO. No clock, no network, no
randomness.
"""

from __future__ import annotations

from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

#: Minimum healthy participation ratio. An honest cluster operates
#: with at least this fraction of nodes participating per round.
MIN_HEALTHY_PARTICIPATION_RATIO = 0.8

#: Maximum number of consecutive rounds that may close at the
#: bare-quorum margin. A 4th consecutive barely-quorate round
#: refuses cert issuance.
MAX_BARELY_QUORATE_ROUNDS = 3

#: A round is "barely quorate" when
#: `participating_node_count <= quorum_threshold + BARELY_QUORATE_MARGIN`.
BARELY_QUORATE_MARGIN = 1

#: Future-skew tolerance in epochs. A history sample whose `epoch`
#: is more than this many epochs past `current_epoch` is REFUSED.
PARTICIPATION_FUTURE_TOLERANCE_EPOCHS = 1

#: Status labels.
PARTICIPATION_OK = "OK"
PARTICIPATION_REFUSED = "REFUSED"

#: Reason codes.
REASON_PARTICIPATION_BARELY_QUORATE_TOO_LONG = (
    "PARTICIPATION_BARELY_QUORATE_TOO_LONG"
)
REASON_PARTICIPATION_BELOW_HEALTHY_FLOOR = (
    "PARTICIPATION_BELOW_HEALTHY_FLOOR"
)
REASON_PARTICIPATION_EPOCH_NOT_MONOTONIC = (
    "PARTICIPATION_EPOCH_NOT_MONOTONIC"
)
REASON_PARTICIPATION_EPOCH_IN_FUTURE = "PARTICIPATION_EPOCH_IN_FUTURE"
REASON_PARTICIPATION_HISTORY_EMPTY = "PARTICIPATION_HISTORY_EMPTY"
REASON_PARTICIPATION_INVALID_QUORUM = "PARTICIPATION_INVALID_QUORUM"


# =============================================================================
# Errors
# =============================================================================

class ClusterParticipationFloorError(RuntimeError):
    """
    Raised by `enforce_cluster_participation_floor` when the cluster's
    recent rounds show a sustained barely-quorate pattern.
    """

    def __init__(
        self, message: str, report: "ClusterParticipationReport"
    ):
        super().__init__(message)
        self.report = report


# =============================================================================
# Records
# =============================================================================

@dataclass(frozen=True, slots=True)
class ClusterParticipationSample:
    """
    One round's participation as observed at round close.

    `epoch`                     the cluster epoch this round belongs
                                to (rounds are monotonic in epoch).
    `participating_node_count`  nodes that revealed (or otherwise
                                contributed) by `reveal_deadline`.
    `total_node_count`          cluster's full node count for this
                                epoch (may shift between rounds if
                                a node has been evicted).
    `quorum_threshold`          K for this round (the on-chain
                                threshold required for the round to
                                close).
    """
    epoch:                    int
    participating_node_count: int
    total_node_count:         int
    quorum_threshold:         int


@dataclass(frozen=True, slots=True)
class ClusterParticipationHistory:
    """
    A window of recent rounds plus the cluster's current epoch.
    `history` is ordered oldest-first.
    """
    history:       tuple[ClusterParticipationSample, ...]
    current_epoch: int


@dataclass(frozen=True, slots=True)
class ClusterParticipationReport:
    """
    Verdict of one FRP-1 check.

    `status`                       PARTICIPATION_OK / PARTICIPATION_REFUSED.
    `sample_count`                 |history|.
    `barely_quorate_run`           length of the trailing run of
                                   consecutive barely-quorate rounds.
    `min_participation_ratio_seen` lowest ratio across history.
    `min_ratio_epoch`              epoch where the lowest ratio
                                   occurred (or -1 if history empty).
    `reasons`                      reason codes; empty when OK.
    """
    status:                        str
    sample_count:                  int
    barely_quorate_run:            int
    max_barely_quorate_run:        int
    healthy_ratio_floor:           float
    min_participation_ratio_seen:  float
    min_ratio_epoch:               int
    current_epoch:                 int
    reasons:                       tuple[str, ...]

    @property
    def is_allowed(self) -> bool:
        return self.status == PARTICIPATION_OK


# =============================================================================
# Verifier (pure)
# =============================================================================

def _is_barely_quorate(sample: ClusterParticipationSample) -> bool:
    return sample.participating_node_count <= (
        sample.quorum_threshold + BARELY_QUORATE_MARGIN
    )


def verify_cluster_participation_floor(
    state: ClusterParticipationHistory,
) -> ClusterParticipationReport:
    """
    Decide whether the cluster's recent rounds satisfy the
    participation floor.

    Rules:
      * Empty history -> REFUSED, PARTICIPATION_HISTORY_EMPTY.
      * Any sample with `quorum_threshold <= 0` or
        `total_node_count <= 0` -> REFUSED,
        PARTICIPATION_INVALID_QUORUM.
      * Non-monotonic epoch order -> REFUSED,
        PARTICIPATION_EPOCH_NOT_MONOTONIC.
      * Any sample with
        `epoch > current_epoch + PARTICIPATION_FUTURE_TOLERANCE_EPOCHS`
        -> REFUSED, PARTICIPATION_EPOCH_IN_FUTURE.
      * Any sample with
        `participation_ratio = participating / total
         < MIN_HEALTHY_PARTICIPATION_RATIO` and not barely-quorate
        in an isolated way -> tracked.
      * Trailing run of barely-quorate rounds longer than
        MAX_BARELY_QUORATE_ROUNDS -> REFUSED,
        PARTICIPATION_BARELY_QUORATE_TOO_LONG.
      * Any sample whose ratio is below the healthy floor AND the
        trailing run is at MAX_BARELY_QUORATE_ROUNDS -> REFUSED,
        PARTICIPATION_BELOW_HEALTHY_FLOOR (additional flag, not
        independent).

    Pure: no logging, no I/O.
    """
    reasons: list[str] = []
    history = state.history
    current = state.current_epoch

    if not history:
        return ClusterParticipationReport(
            status=PARTICIPATION_REFUSED,
            sample_count=0,
            barely_quorate_run=0,
            max_barely_quorate_run=MAX_BARELY_QUORATE_ROUNDS,
            healthy_ratio_floor=MIN_HEALTHY_PARTICIPATION_RATIO,
            min_participation_ratio_seen=0.0,
            min_ratio_epoch=-1,
            current_epoch=current,
            reasons=(REASON_PARTICIPATION_HISTORY_EMPTY,),
        )

    # Validate per-sample shape.
    invalid_quorum = any(
        s.quorum_threshold <= 0 or s.total_node_count <= 0
        for s in history
    )
    if invalid_quorum:
        reasons.append(REASON_PARTICIPATION_INVALID_QUORUM)

    # Epoch monotonicity (non-strict — multiple rounds may share an
    # epoch).
    non_monotonic = any(
        history[i].epoch < history[i - 1].epoch
        for i in range(1, len(history))
    )
    if non_monotonic:
        reasons.append(REASON_PARTICIPATION_EPOCH_NOT_MONOTONIC)

    future = any(
        s.epoch > current + PARTICIPATION_FUTURE_TOLERANCE_EPOCHS
        for s in history
    )
    if future:
        reasons.append(REASON_PARTICIPATION_EPOCH_IN_FUTURE)

    # Trailing barely-quorate run.
    run = 0
    for s in reversed(history):
        if _is_barely_quorate(s):
            run += 1
        else:
            break

    if run > MAX_BARELY_QUORATE_ROUNDS:
        reasons.append(REASON_PARTICIPATION_BARELY_QUORATE_TOO_LONG)

    # Min ratio across history (for observability + healthy-floor
    # signal).
    min_ratio = 1.0
    min_ratio_epoch = history[0].epoch
    for s in history:
        if s.total_node_count <= 0:
            continue
        ratio = s.participating_node_count / s.total_node_count
        if ratio < min_ratio:
            min_ratio = ratio
            min_ratio_epoch = s.epoch

    # PARTICIPATION_BELOW_HEALTHY_FLOOR is a complementary signal
    # raised when the min ratio is below the healthy floor AND
    # the trailing run is already at-or-past the barely-quorate cap.
    # It is reported in addition to BARELY_QUORATE_TOO_LONG so the
    # operator dashboard can distinguish "one bad round at lower
    # quorum" from "sustained low-participation pattern".
    if (
        min_ratio < MIN_HEALTHY_PARTICIPATION_RATIO
        and run >= MAX_BARELY_QUORATE_ROUNDS
    ):
        reasons.append(REASON_PARTICIPATION_BELOW_HEALTHY_FLOOR)

    status = PARTICIPATION_OK if not reasons else PARTICIPATION_REFUSED

    return ClusterParticipationReport(
        status=status,
        sample_count=len(history),
        barely_quorate_run=run,
        max_barely_quorate_run=MAX_BARELY_QUORATE_ROUNDS,
        healthy_ratio_floor=MIN_HEALTHY_PARTICIPATION_RATIO,
        min_participation_ratio_seen=min_ratio,
        min_ratio_epoch=min_ratio_epoch,
        current_epoch=current,
        reasons=tuple(reasons),
    )


# =============================================================================
# Enforcement (fail-closed wrapper)
# =============================================================================

def enforce_cluster_participation_floor(
    state: ClusterParticipationHistory,
) -> ClusterParticipationReport:
    """
    Run `verify_cluster_participation_floor` and raise on any
    violation. Returns the report when status == PARTICIPATION_OK.
    """
    report = verify_cluster_participation_floor(state)
    if report.is_allowed:
        return report
    raise ClusterParticipationFloorError(
        f"FRP-1: cluster participation floor refused — "
        f"trailing barely-quorate run={report.barely_quorate_run} "
        f"(cap {report.max_barely_quorate_run}), "
        f"min participation ratio={report.min_participation_ratio_seen:.3f} "
        f"(floor {report.healthy_ratio_floor:.3f}), "
        f"min ratio epoch={report.min_ratio_epoch}, "
        f"reasons={list(report.reasons)!r}. "
        f"The cluster MUST NOT mint certs while sustained "
        f"barely-quorate operation persists — this is the "
        f"fingerprint of a VULN-05 withholding attack.",
        report,
    )


__all__ = [
    "BARELY_QUORATE_MARGIN",
    "ClusterParticipationFloorError",
    "ClusterParticipationHistory",
    "ClusterParticipationReport",
    "ClusterParticipationSample",
    "MAX_BARELY_QUORATE_ROUNDS",
    "MIN_HEALTHY_PARTICIPATION_RATIO",
    "PARTICIPATION_FUTURE_TOLERANCE_EPOCHS",
    "PARTICIPATION_OK",
    "PARTICIPATION_REFUSED",
    "REASON_PARTICIPATION_BARELY_QUORATE_TOO_LONG",
    "REASON_PARTICIPATION_BELOW_HEALTHY_FLOOR",
    "REASON_PARTICIPATION_EPOCH_IN_FUTURE",
    "REASON_PARTICIPATION_EPOCH_NOT_MONOTONIC",
    "REASON_PARTICIPATION_HISTORY_EMPTY",
    "REASON_PARTICIPATION_INVALID_QUORUM",
    "enforce_cluster_participation_floor",
    "verify_cluster_participation_floor",
]
