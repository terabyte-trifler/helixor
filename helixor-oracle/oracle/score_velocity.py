"""
oracle/score_velocity.py — PDS-2: SDK-consumer score-velocity contract.

THE GAP THIS CLOSES
-------------------
The on-chain `HealthCertificate` is already keyed per-(agent, epoch):
seed = `["cert", agent_wallet, epoch_le]`. The PREVIOUS epoch's cert
is therefore PERMANENTLY ON CHAIN — a DeFi consumer can read it and
compute the score velocity between two adjacent epochs.

What was missing was a CANONICAL contract that says:
  "two certs (this-epoch, prev-epoch) where the score moved more than
   X points OR more than Y points/hour MUST be treated as a velocity
   anomaly — even if both certs are individually fresh and signed."

Without the canonical contract, every DeFi integrator picks their own
heuristic (or none) and the Protocol Death Spiral attack succeeds: the
attacker inflates scores by 49 points/epoch for 30 epochs, every
individual cert is signed by a valid 3-of-5 quorum, every individual
cert is within the per-epoch `MAX_SCORE_DELTA = 200` guard rail, and
the SDK consumer has no signal to refuse the cert until the damage is
done.

THE MITIGATION (this file)
--------------------------
A pure, deterministic helper that both the cluster's pre-issue gate AND
the SDK's SafeCertReader can call:

  verify_score_velocity(current_score, current_issued_at,
                        previous_score, previous_issued_at,
                        *, max_per_epoch, max_per_hour)

Returns a `ScoreVelocityReport` on safety; raises
`ScoreVelocityError` on a velocity-anomaly that exceeds either floor.

The Python is the CANONICAL form. The TypeScript SDK ports the same
constants and the same arithmetic so two operators reading the same
cert pair reach the same verdict.

DETERMINISM
-----------
Pure stdlib. Integer arithmetic for the per-epoch delta; integer
seconds for the per-hour rate. No clock (the timestamps come in as
arguments), no randomness, no I/O.

INTERACTION WITH SCORING/_GAMING.PY (existing 200-point guard rail)
-------------------------------------------------------------------
`scoring/_gaming.MAX_SCORE_DELTA = 200` clamps the cluster's INTERNAL
movement per epoch. PDS-2 mirrors that ceiling on the SDK side so the
DeFi consumer enforces the SAME contract independently of the cluster
— a cluster that quietly raises its internal cap to 400 still hits the
SDK-side 200-point refusal. Defence-in-depth: the cluster gate AND the
consumer gate must both fail before an inflated score reaches a loan
decision.

INTERACTION WITH TA-6 (cert-freshness ceiling)
----------------------------------------------
TA-6's `MAX_AGE_SECONDS = 48h` rejects STALE certs. PDS-2's
`max_per_hour` rejects FAST-MOVING certs. The two are complementary:
TA-6 catches the consumer who acts on out-of-date data; PDS-2 catches
the consumer who acts on up-to-date data that arrived too fast to be
honest.
"""

from __future__ import annotations

from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

#: Maximum absolute score delta between two adjacent-epoch certs. Mirrors
#: `scoring._gaming.MAX_SCORE_DELTA = 200`. The cluster clamps to this
#: internally; the SDK rejects pairs that exceed it externally.
MAX_SCORE_DELTA_PER_EPOCH = 200

#: Maximum score velocity in points-per-hour. The cluster runs ~12
#: epochs/day (a 2h cadence), so a sustained 100 points/hour is the
#: cluster moving its full 200-point per-epoch cap continuously — at
#: which point the slow-drift detector should already have fired.
#: Anything beyond 100/hour is structurally suspicious.
MAX_SCORE_VELOCITY_PER_HOUR = 100

#: A velocity above this absolute floor is treated as a HARD anomaly even
#: if `max_per_hour` is overridden by the caller. 500 points/hour means
#: the score moved by half the entire 0..1000 scale in one hour — no
#: legitimate operational scenario produces this.
ABSURD_VELOCITY_PER_HOUR = 500

#: Minimum elapsed seconds between two cert issuances before the
#: per-hour velocity is computed. Below this floor the math is dominated
#: by clock jitter; the per-epoch delta check still applies.
MIN_ELAPSED_SECONDS_FOR_VELOCITY = 60


# =============================================================================
# Report / errors
# =============================================================================


@dataclass(frozen=True, slots=True)
class ScoreVelocityReport:
    """
    One run of the score-velocity check between two adjacent-epoch
    certs.

    `score_delta`         signed delta (current - previous).
    `elapsed_seconds`     wall-clock seconds between the two
                          `issued_at` timestamps.
    `velocity_per_hour`   signed points-per-hour (NaN if elapsed is
                          below `MIN_ELAPSED_SECONDS_FOR_VELOCITY`).
    `is_safe`             True iff both floors held.
    `reasons`             reason codes when not safe.
    """
    current_score:     int
    previous_score:    int
    score_delta:       int
    elapsed_seconds:   int
    velocity_per_hour: float
    reasons:           tuple[str, ...]

    @property
    def is_safe(self) -> bool:
        return not self.reasons


REASON_DELTA = "EPOCH_DELTA_EXCEEDS_CAP"
REASON_VELOCITY = "VELOCITY_EXCEEDS_CAP"
REASON_ABSURD = "ABSURD_VELOCITY"
REASON_TIME_TRAVEL = "PREVIOUS_AFTER_CURRENT"


class ScoreVelocityError(RuntimeError):
    """
    Raised when a cert pair fails the velocity contract. The exception's
    `.report` carries the diagnostic so the DeFi consumer (or the
    cluster pre-issue gate) sees which floor failed.
    """

    def __init__(self, message: str, report: ScoreVelocityReport):
        super().__init__(message)
        self.report = report


# =============================================================================
# The verifier
# =============================================================================


def verify_score_velocity(
    *,
    current_score:       int,
    current_issued_at:   int,
    previous_score:      int,
    previous_issued_at:  int,
    max_per_epoch:       int   = MAX_SCORE_DELTA_PER_EPOCH,
    max_per_hour:        float = MAX_SCORE_VELOCITY_PER_HOUR,
    absurd_per_hour:     float = ABSURD_VELOCITY_PER_HOUR,
    min_elapsed_seconds: int   = MIN_ELAPSED_SECONDS_FOR_VELOCITY,
) -> ScoreVelocityReport:
    """
    Compute the velocity report between two adjacent-epoch certs.

    Parameters
    ----------
    current_score / previous_score
        The composite scores from each cert (0..1000).
    current_issued_at / previous_issued_at
        The unix-seconds `issued_at` from each cert.

    The function fails CLOSED on `previous_issued_at > current_issued_at`
    — a future-dated previous cert is a clock-skew or replay signal.

    Returns
    -------
    ScoreVelocityReport
        Caller checks `.is_safe`. To raise on a positive verdict, use
        `enforce_score_velocity`.
    """
    reasons: list[str] = []
    score_delta = current_score - previous_score
    elapsed = current_issued_at - previous_issued_at
    velocity_per_hour = float("nan")

    if elapsed < 0:
        reasons.append(REASON_TIME_TRAVEL)
        elapsed = 0  # for the report; downstream math is short-circuited
    elif elapsed >= min_elapsed_seconds:
        velocity_per_hour = (score_delta * 3600.0) / elapsed
        # The hour cap is on ABSOLUTE velocity — a sharp downward move
        # is just as anomalous as a sharp upward one for credibility
        # purposes.
        if abs(velocity_per_hour) > absurd_per_hour:
            reasons.append(REASON_ABSURD)
        elif abs(velocity_per_hour) > max_per_hour:
            reasons.append(REASON_VELOCITY)

    if abs(score_delta) > max_per_epoch:
        reasons.append(REASON_DELTA)

    return ScoreVelocityReport(
        current_score=int(current_score),
        previous_score=int(previous_score),
        score_delta=int(score_delta),
        elapsed_seconds=int(elapsed),
        velocity_per_hour=velocity_per_hour,
        reasons=tuple(reasons),
    )


def enforce_score_velocity(
    *,
    current_score:      int,
    current_issued_at:  int,
    previous_score:     int,
    previous_issued_at: int,
    **kwargs,
) -> ScoreVelocityReport:
    """
    Run `verify_score_velocity` and raise `ScoreVelocityError` on a
    positive verdict. Intended call sites:

      * cluster pre-issue gate (`oracle/cluster/cert_signing.py`),
        where the cluster compares this-epoch composite against the
        last cert it itself signed for this agent — refusing the
        issuance closes the attack at the source.
      * SDK SafeCertReader (`helixor-sdk/src/safe_reader.ts`,
        ported), where the consumer compares the fetched current
        cert against the fetched previous-epoch cert.
    """
    report = verify_score_velocity(
        current_score=current_score,
        current_issued_at=current_issued_at,
        previous_score=previous_score,
        previous_issued_at=previous_issued_at,
        **kwargs,
    )
    if not report.is_safe:
        bits = []
        if REASON_DELTA in report.reasons:
            bits.append(
                f"per-epoch delta {report.score_delta:+d} exceeds cap "
                f"±{MAX_SCORE_DELTA_PER_EPOCH}"
            )
        if REASON_VELOCITY in report.reasons:
            bits.append(
                f"velocity {report.velocity_per_hour:+.1f} pts/h exceeds "
                f"cap ±{MAX_SCORE_VELOCITY_PER_HOUR}"
            )
        if REASON_ABSURD in report.reasons:
            bits.append(
                f"absurd velocity {report.velocity_per_hour:+.1f} pts/h "
                f"(absolute floor ±{ABSURD_VELOCITY_PER_HOUR})"
            )
        if REASON_TIME_TRAVEL in report.reasons:
            bits.append("previous cert issued_at is AFTER current cert")
        raise ScoreVelocityError(
            "PDS-2: cert pair failed score-velocity contract — "
            + "; ".join(bits)
            + ". Refuse to act on this cert until cluster operators "
            "confirm the move is legitimate.",
            report,
        )
    return report


__all__ = [
    "ABSURD_VELOCITY_PER_HOUR",
    "MAX_SCORE_DELTA_PER_EPOCH",
    "MAX_SCORE_VELOCITY_PER_HOUR",
    "MIN_ELAPSED_SECONDS_FOR_VELOCITY",
    "REASON_ABSURD",
    "REASON_DELTA",
    "REASON_TIME_TRAVEL",
    "REASON_VELOCITY",
    "ScoreVelocityError",
    "ScoreVelocityReport",
    "enforce_score_velocity",
    "verify_score_velocity",
]
