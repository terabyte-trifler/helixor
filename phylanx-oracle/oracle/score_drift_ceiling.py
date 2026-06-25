"""
oracle/score_drift_ceiling.py — ILS-3: cumulative score-drift
ceiling for red-team Path 2 sub-leaf 2c ("Exploit VULN-03:
Byzantine drift").

THE ATTACK PATH (Inflate-Legitimate-Score Path 2, sub-leaf 2c)
--------------------------------------------------------------
VULN-03 is the "slow drift over 30 epochs" family. Each epoch the
attacker pushes the score up by ~12-15%, just below the per-epoch
velocity gate (~30%). The cluster's median shifts, the attacker
stays close to the new median, and over 30 epochs the agent's
score has inflated by ~37% from baseline without any single
epoch's submission breaking the per-epoch detector.

The cluster-side defence in `oracle/cluster/drift_detector.py`
already ships four cross-epoch detectors:

  * Velocity gate (0.20 inter-epoch movement)
  * Rolling baseline (10-epoch exponentially-decayed, 0.25 drift
    threshold)
  * Per-node signed-deviation attribution (0.08 mean signed
    deviation across rolling window)
  * Activity cross-check (score velocity vs on-chain tx velocity)

Each of those is a CALIBRATED detector — they catch the attack
shape that the audit named, but their thresholds are tunable. An
attacker who knows the calibration (it's open-source) can shape
their drift to stay below every one of them simultaneously. The
detectors are calibrated against the cluster's per-epoch tolerance
for honest score movement; they have NO concept of CUMULATIVE
drift from the agent's baseline_score across the agent's lifetime.

ILS-3 closes the cumulative-drift substrate with a hard ceiling
that does NOT depend on per-epoch calibration:

  * `MAX_DRIFT_FROM_BASELINE_RATIO = 0.30` — an agent's effective
    score may not exceed `baseline_score * (1 +
    MAX_DRIFT_FROM_BASELINE_RATIO)` regardless of how slowly the
    score crept up. Any cert that would issue a score past this
    ceiling is REFUSED; the agent must undergo an explicit
    re-baseline ceremony (subject to ILS-1's cadence) to legitimately
    move past the ceiling.
  * `MAX_MONOTONIC_DRIFT_EPOCHS = 10` — strictly-upward drift over
    10 consecutive epochs is REFUSED even if no single epoch
    movement exceeds the per-epoch cap and the cumulative drift
    is under the absolute ceiling. Catches the "stairstep upward"
    attack pattern where each step is small but the integral is
    large.
  * `MAX_DRIFT_PER_EPOCH_RATIO = 0.05` — belt-and-braces with the
    cluster's per-epoch velocity gate. The cluster's
    `drift_detector.py` carries the bulk of per-epoch detection;
    ILS-3 adds a HARD 5% per-epoch ceiling that does not depend
    on the cluster's median or any cluster-side calibration.

CALIBRATION
-----------
- `MAX_DRIFT_FROM_BASELINE_RATIO = 0.30` — 30% is the audit's
  exact threshold from the attack description: "30 epochs of
  12-15% per epoch compounds to ~37%". 30% is the cliff edge.
  Past it the cert refuses; the agent must be re-baselined.
  Pinned at 0.30 deliberately to be LESS THAN the 37% the
  attacker is documented to achieve — the ceiling refuses
  exactly the attack shape the audit names.
- `MAX_MONOTONIC_DRIFT_EPOCHS = 10` — calibrated against typical
  honest behaviour. An agent's score genuinely improving over
  many consecutive epochs is rare; an agent improving STRICTLY
  monotonically over 10 epochs is statistically improbable. 10
  epochs at 2h cadence = 20h, which is well within an attack
  window but past any honest "good streak".
- `MAX_DRIFT_PER_EPOCH_RATIO = 0.05` — 5% per epoch is the
  honest-movement ceiling. The cluster's drift_detector.py
  carries the per-epoch detection at 0.20 velocity; ILS-3's
  0.05 is the ABSOLUTE floor, calibrated against the audit's
  attack value (12-15% per epoch). At 5% per epoch the maximum
  10-epoch monotonic drift is 1.05^10 - 1 = 0.629, which is well
  beyond the 0.30 absolute ceiling — i.e. an attacker pushing
  exactly to ILS-3's per-epoch and monotonic-epoch limits
  CANNOT exceed the absolute drift ceiling without re-baselining.
- `DRIFT_FUTURE_TOLERANCE_EPOCHS = 1` — one epoch's worth of
  clock skew. A score history entry whose epoch is more than 1
  epoch past current is REFUSED with `DRIFT_EPOCH_IN_FUTURE`.

INTERACTION WITH VULN-03 / ILS-1 / ILS-2 / cluster.drift_detector
-----------------------------------------------------------------
- VULN-03's `cluster/drift_detector.py` does the per-epoch
  cross-epoch detection (velocity gate, rolling baseline,
  signed-deviation attribution). ILS-3 is the off-chain cert-
  issuance pre-flight that runs AFTER the cluster's detection
  passes — it refuses on cumulative cross-LIFETIME drift, which
  the per-epoch detectors do not see.
- ILS-1 (`baseline_rotation_guard.py`) bounds the frequency at
  which a new baseline_score can be installed. Without ILS-1,
  an attacker could just re-baseline every epoch to reset
  ILS-3's measurement. With ILS-1's 30-epoch floor, a re-
  baseline is rare and visible.
- ILS-2 (`feature_corroboration.py`) closes the producer-key
  poisoning substrate that would let an attacker feed
  fraudulent inputs to the score. ILS-3 closes the residual
  where the inputs are honest but the output of the scoring
  function has slowly drifted.

DETERMINISM
-----------
Pure stdlib. Float arithmetic on score ratios; integer comparison
on epoch numbers; one linear pass over the score history. No
clock (the verifier takes the history's epoch numbers as input),
no network, no randomness. Score values are accepted as floats;
all comparisons are inequality-based and stable.
"""

from __future__ import annotations

from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

#: Maximum cumulative drift ratio from the agent's baseline score.
#: A cert that would issue a score past `baseline * (1 +
#: MAX_DRIFT_FROM_BASELINE_RATIO)` is REFUSED. Calibrated to refuse
#: exactly the audit's documented 37% inflation attack.
MAX_DRIFT_FROM_BASELINE_RATIO = 0.30

#: Maximum number of consecutive epochs of strictly-upward score
#: drift permitted. >= this many monotonic upward steps -> REFUSED.
MAX_MONOTONIC_DRIFT_EPOCHS = 10

#: Maximum single-epoch score change (as a ratio of the previous
#: epoch's score). Belt-and-braces with the cluster's velocity gate.
MAX_DRIFT_PER_EPOCH_RATIO = 0.05

#: Future-skew tolerance in epochs.
DRIFT_FUTURE_TOLERANCE_EPOCHS = 1

#: Status labels.
DRIFT_OK = "OK"
DRIFT_REFUSED = "REFUSED"

#: Reason codes.
REASON_DRIFT_OVER_CUMULATIVE_CEILING = "DRIFT_OVER_CUMULATIVE_CEILING"
REASON_DRIFT_OVER_PER_EPOCH_CEILING = "DRIFT_OVER_PER_EPOCH_CEILING"
REASON_DRIFT_MONOTONIC_TOO_LONG = "DRIFT_MONOTONIC_TOO_LONG"
REASON_DRIFT_BASELINE_NON_POSITIVE = "DRIFT_BASELINE_NON_POSITIVE"
REASON_DRIFT_HISTORY_EMPTY = "DRIFT_HISTORY_EMPTY"
REASON_DRIFT_EPOCH_NOT_MONOTONIC = "DRIFT_EPOCH_NOT_MONOTONIC"
REASON_DRIFT_EPOCH_IN_FUTURE = "DRIFT_EPOCH_IN_FUTURE"


# =============================================================================
# Errors
# =============================================================================

class ScoreDriftCeilingError(RuntimeError):
    """
    Raised by `enforce_score_drift_ceiling` when an agent's proposed
    score would exceed the cumulative-drift ceiling, per-epoch
    ceiling, or monotonic-epoch streak ceiling.

    `.report` carries the structured verdict so the on-call operator
    can decide whether a re-baseline is warranted or whether the
    cluster's per-epoch detectors have missed an active attack.
    """

    def __init__(self, message: str, report: "ScoreDriftReport"):
        super().__init__(message)
        self.report = report


# =============================================================================
# Records
# =============================================================================

@dataclass(frozen=True, slots=True)
class ScoreHistoryEntry:
    """
    One entry in an agent's score history.

    `epoch`  the on-chain epoch the score was certified at. Strictly
             monotonic upward across the history.
    `score`  the certified score value (post-cluster-aggregation,
             post-detection). Float >= 0.
    """
    epoch:  int
    score:  float


@dataclass(frozen=True, slots=True)
class AgentScoreTrajectory:
    """
    An agent's full score trajectory at cert-issuance time.

    `agent_wallet`     the agent.
    `baseline_score`   the score at the agent's most recent baseline
                       rotation. > 0 (a zero or negative baseline
                       would make every drift ratio undefined and is
                       refused upfront).
    `history`          tuple of ScoreHistoryEntry, ordered by
                       strictly-increasing epoch. Includes the
                       proposed new score as the LAST entry.
    `current_epoch`    the cluster's current epoch (so future-dated
                       entries can be refused).
    """
    agent_wallet:     str
    baseline_score:   float
    history:          tuple[ScoreHistoryEntry, ...]
    current_epoch:    int


@dataclass(frozen=True, slots=True)
class ScoreDriftReport:
    """
    Verdict of one ILS-3 check.

    `status`                  DRIFT_OK / DRIFT_REFUSED.
    `agent_wallet`            echoed.
    `baseline_score`          echoed.
    `latest_score`            the proposed score (last history entry).
    `cumulative_drift_ratio`  (latest - baseline) / baseline. Negative
                              for downward drift; positive for upward.
    `max_per_epoch_ratio`     the largest |score_t - score_{t-1}| /
                              score_{t-1} observed in the history.
    `longest_monotonic_run`   longest run of strictly-upward
                              consecutive score increases.
    `max_cumulative_drift`    MAX_DRIFT_FROM_BASELINE_RATIO.
    `max_per_epoch_drift`     MAX_DRIFT_PER_EPOCH_RATIO.
    `max_monotonic_epochs`    MAX_MONOTONIC_DRIFT_EPOCHS.
    `reasons`                 reason codes; empty when OK.
    """
    status:                  str
    agent_wallet:            str
    baseline_score:          float
    latest_score:            float
    cumulative_drift_ratio:  float
    max_per_epoch_ratio:     float
    longest_monotonic_run:   int
    max_cumulative_drift:    float
    max_per_epoch_drift:     float
    max_monotonic_epochs:    int
    reasons:                 tuple[str, ...]

    @property
    def is_allowed(self) -> bool:
        return self.status == DRIFT_OK


# =============================================================================
# Verifier (pure)
# =============================================================================

def verify_score_drift_ceiling(
    trajectory: AgentScoreTrajectory,
) -> ScoreDriftReport:
    """
    Decide whether an agent's score trajectory respects the
    cumulative-drift, per-epoch-drift, and monotonic-run ceilings.

    The rules:
      * `baseline_score <= 0` -> REFUSED, DRIFT_BASELINE_NON_POSITIVE.
        ILS-3 cannot compute ratios against a zero or negative
        baseline; the agent must be re-baselined to a positive
        score via the on-chain `record_baseline` ceremony.
      * empty `history` -> REFUSED, DRIFT_HISTORY_EMPTY.
      * any history entry's `epoch` <= previous entry's `epoch` ->
        REFUSED, DRIFT_EPOCH_NOT_MONOTONIC (the on-chain ledger
        guarantees monotonic epochs; failure here means the
        trajectory was constructed incorrectly).
      * any history entry's `epoch` > `current_epoch +
        DRIFT_FUTURE_TOLERANCE_EPOCHS` -> REFUSED,
        DRIFT_EPOCH_IN_FUTURE.
      * (latest_score - baseline_score) / baseline_score >
        MAX_DRIFT_FROM_BASELINE_RATIO -> REFUSED,
        DRIFT_OVER_CUMULATIVE_CEILING.
      * For any consecutive pair (prev, curr) in history,
        (curr.score - prev.score) / prev.score >
        MAX_DRIFT_PER_EPOCH_RATIO -> REFUSED,
        DRIFT_OVER_PER_EPOCH_CEILING.
        (Computed only when prev.score > 0; a zero-score prior
        entry skips the per-epoch check for that pair.)
      * Longest run of strictly-upward consecutive transitions
        in history >= MAX_MONOTONIC_DRIFT_EPOCHS -> REFUSED,
        DRIFT_MONOTONIC_TOO_LONG. (>= because a 10-step
        monotonic run is exactly the audit's attack shape and
        should refuse.)

    Pure: no logging, no I/O. Float arithmetic is stable under
    the inequalities used; ratios are computed with division by a
    positive baseline so there is no NaN path.
    """
    reasons: list[str] = []
    baseline = trajectory.baseline_score
    history = trajectory.history
    current = trajectory.current_epoch

    if baseline <= 0:
        return ScoreDriftReport(
            status=DRIFT_REFUSED,
            agent_wallet=trajectory.agent_wallet,
            baseline_score=baseline,
            latest_score=0.0,
            cumulative_drift_ratio=0.0,
            max_per_epoch_ratio=0.0,
            longest_monotonic_run=0,
            max_cumulative_drift=MAX_DRIFT_FROM_BASELINE_RATIO,
            max_per_epoch_drift=MAX_DRIFT_PER_EPOCH_RATIO,
            max_monotonic_epochs=MAX_MONOTONIC_DRIFT_EPOCHS,
            reasons=(REASON_DRIFT_BASELINE_NON_POSITIVE,),
        )

    if not history:
        return ScoreDriftReport(
            status=DRIFT_REFUSED,
            agent_wallet=trajectory.agent_wallet,
            baseline_score=baseline,
            latest_score=0.0,
            cumulative_drift_ratio=0.0,
            max_per_epoch_ratio=0.0,
            longest_monotonic_run=0,
            max_cumulative_drift=MAX_DRIFT_FROM_BASELINE_RATIO,
            max_per_epoch_drift=MAX_DRIFT_PER_EPOCH_RATIO,
            max_monotonic_epochs=MAX_MONOTONIC_DRIFT_EPOCHS,
            reasons=(REASON_DRIFT_HISTORY_EMPTY,),
        )

    # Validate monotonic epochs + future-skew on a single pass.
    for i, entry in enumerate(history):
        if i > 0 and entry.epoch <= history[i - 1].epoch:
            reasons.append(REASON_DRIFT_EPOCH_NOT_MONOTONIC)
            break
    for entry in history:
        if entry.epoch > current + DRIFT_FUTURE_TOLERANCE_EPOCHS:
            reasons.append(REASON_DRIFT_EPOCH_IN_FUTURE)
            break

    latest_score = history[-1].score
    cumulative = (latest_score - baseline) / baseline
    if cumulative > MAX_DRIFT_FROM_BASELINE_RATIO:
        reasons.append(REASON_DRIFT_OVER_CUMULATIVE_CEILING)

    # Per-epoch drift + longest monotonic run, single pass.
    max_per_epoch = 0.0
    longest_run = 0
    current_run = 0
    for i in range(1, len(history)):
        prev = history[i - 1]
        curr = history[i]
        if prev.score > 0:
            step = (curr.score - prev.score) / prev.score
            if step > max_per_epoch:
                max_per_epoch = step
            if step > MAX_DRIFT_PER_EPOCH_RATIO:
                # Add only once per report; further violations are
                # counted into max_per_epoch but don't re-emit.
                if REASON_DRIFT_OVER_PER_EPOCH_CEILING not in reasons:
                    reasons.append(REASON_DRIFT_OVER_PER_EPOCH_CEILING)
        if curr.score > prev.score:
            current_run += 1
            if current_run > longest_run:
                longest_run = current_run
        else:
            current_run = 0

    if longest_run >= MAX_MONOTONIC_DRIFT_EPOCHS:
        if REASON_DRIFT_MONOTONIC_TOO_LONG not in reasons:
            reasons.append(REASON_DRIFT_MONOTONIC_TOO_LONG)

    status = DRIFT_OK if not reasons else DRIFT_REFUSED

    return ScoreDriftReport(
        status=status,
        agent_wallet=trajectory.agent_wallet,
        baseline_score=baseline,
        latest_score=latest_score,
        cumulative_drift_ratio=cumulative,
        max_per_epoch_ratio=max_per_epoch,
        longest_monotonic_run=longest_run,
        max_cumulative_drift=MAX_DRIFT_FROM_BASELINE_RATIO,
        max_per_epoch_drift=MAX_DRIFT_PER_EPOCH_RATIO,
        max_monotonic_epochs=MAX_MONOTONIC_DRIFT_EPOCHS,
        reasons=tuple(reasons),
    )


# =============================================================================
# Enforcement (fail-closed wrapper)
# =============================================================================

def enforce_score_drift_ceiling(
    trajectory: AgentScoreTrajectory,
) -> ScoreDriftReport:
    """
    Run `verify_score_drift_ceiling` and raise on any violation.

    Returns the report when status == DRIFT_OK. Raises
    `ScoreDriftCeilingError` otherwise — the cluster MUST NOT
    issue a cert at the proposed score; the agent must either
    submit a downward-trending epoch or undergo an explicit
    re-baseline ceremony (subject to ILS-1).
    """
    report = verify_score_drift_ceiling(trajectory)
    if report.is_allowed:
        return report
    raise ScoreDriftCeilingError(
        f"ILS-3: score drift refused — "
        f"agent={report.agent_wallet!r}, "
        f"baseline={report.baseline_score:.4f}, "
        f"latest={report.latest_score:.4f}, "
        f"cumulative={report.cumulative_drift_ratio:.3f} (cap "
        f"{report.max_cumulative_drift:.3f}), "
        f"max_per_epoch={report.max_per_epoch_ratio:.3f} (cap "
        f"{report.max_per_epoch_drift:.3f}), "
        f"monotonic_run={report.longest_monotonic_run} (cap "
        f"{report.max_monotonic_epochs}), "
        f"reasons={list(report.reasons)!r}. "
        f"Cumulative drift exceeded the absolute ceiling or the "
        f"cluster's per-epoch detection has missed an active "
        f"slow-drift attack.",
        report,
    )


__all__ = [
    "AgentScoreTrajectory",
    "DRIFT_FUTURE_TOLERANCE_EPOCHS",
    "DRIFT_OK",
    "DRIFT_REFUSED",
    "MAX_DRIFT_FROM_BASELINE_RATIO",
    "MAX_DRIFT_PER_EPOCH_RATIO",
    "MAX_MONOTONIC_DRIFT_EPOCHS",
    "REASON_DRIFT_BASELINE_NON_POSITIVE",
    "REASON_DRIFT_EPOCH_IN_FUTURE",
    "REASON_DRIFT_EPOCH_NOT_MONOTONIC",
    "REASON_DRIFT_HISTORY_EMPTY",
    "REASON_DRIFT_MONOTONIC_TOO_LONG",
    "REASON_DRIFT_OVER_CUMULATIVE_CEILING",
    "REASON_DRIFT_OVER_PER_EPOCH_CEILING",
    "ScoreDriftCeilingError",
    "ScoreDriftReport",
    "ScoreHistoryEntry",
    "enforce_score_drift_ceiling",
    "verify_score_drift_ceiling",
]
