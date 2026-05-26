"""
oracle/cluster/correlated_inflation.py — PDS-3: cross-agent correlated movement detector.

THE LAST MILE OF THE DEATH SPIRAL
---------------------------------
Scenario A from the audit has SEVEN steps:

    1. Attacker compromises 2 oracle nodes.
    2. Runs VULN-03 slow-drift inflation for 30 epochs.
    3. All agent scores reach 900+.
    4. DeFi protocols issue max loans.
    5. Attacker triggers mass agent failures simultaneously.
    6. All DeFi loans default at once.
    7. Helixor's credibility is destroyed.

PDS-1 (saturation_gate.py) closes step 3: the cluster refuses to sign
an epoch where too many agents simultaneously migrated to the HIGH
band. PDS-2 (score_velocity.py) closes step 4 from the DeFi side: the
SDK consumer refuses to act on a cert pair whose per-epoch delta is
above the cap.

What remains is the LONG-RANGE pattern detection — the audit's specific
language of "30 epochs" of slow inflation, then ALL agents failing
together. PDS-1 sees a single epoch; PDS-3 sees the multi-epoch
fingerprint:

  * UNIVERSAL CORRELATION: across the rolling window, the FRACTION of
    agents moving in the same DIRECTION exceeds `MAX_DIRECTIONAL_SHARE`.
    Honest reputation movement is noisy; agents going up while others
    go down. A coordinated push produces unnaturally directional
    moves over consecutive epochs.

  * MASS FAILURE: in a single epoch, the fraction of agents losing
    more than `MASS_FAILURE_DROP` points exceeds
    `MASS_FAILURE_AGENT_FRACTION`. This is the "attacker turns off the
    agents" tail — a credible challenger should see this as a
    chain-wide credibility event, not as new lending capacity.

THE MITIGATION (this file)
--------------------------
Two pure, deterministic checks the cluster runs on its score-history
buffer at epoch boundary:

  verify_correlated_movement(snapshots) -> CorrelatedMovementReport
  verify_mass_failure(snapshot, prior)  -> MassFailureReport

The cluster's reaction differs from PDS-1: PDS-1 refuses to sign;
PDS-3 emits an EVIDENCE PACKAGE that surfaces to the operator alert
channel + (eventually) to the on-chain `challenge_oracle` flow. PDS-3
is the FORENSIC layer — it produces deterministic evidence that
multiple honest cluster members independently compute the same hash
of "what happened over the last K epochs."

DETERMINISM
-----------
Pure stdlib. Inputs are the EpochSnapshot dataclass from
`saturation_gate.py`. No clock, no randomness, no network.

INTERACTION WITH VULN-03 (drift_detector.py)
--------------------------------------------
VULN-03 catches PER-AGENT slow drift. PDS-3 catches WHOLE-POPULATION
slow drift. They share the same threshold philosophy — directional
pressure that adds up — but operate on orthogonal axes:

  VULN-03   agent X is consistently above the cluster median
  PDS-3     the cluster median is consistently moving up

Both fire on the death-spiral attack. Both produce evidence. They are
not redundant — VULN-03 names INDIVIDUAL hostile nodes, PDS-3 names
the MASS EVENT. If VULN-03 fires alone, the cluster knows which node
to challenge; if PDS-3 fires alone, the cluster knows the upstream
substrate is poisoned even when every node is honest-relative-to-its-
inputs.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence

from oracle.cluster.saturation_gate import EpochSnapshot


# =============================================================================
# Thresholds
# =============================================================================

#: Window of recent epochs the correlation check averages over. 5 — long
#: enough that a transient market event (one epoch of broad good news)
#: does not trip; short enough that the slow-drift attack reaches the
#: fingerprint quickly.
CORRELATION_WINDOW = 5

#: An agent's score must move by at least this magnitude in one epoch
#: to count as a "directional move" for correlation purposes. Below this
#: it is treated as noise. 25 — half of the worst-case VULN-03 stealth
#: drift (50 per epoch); the noise floor below which honest variance
#: dominates.
DIRECTIONAL_MIN_DELTA = 25

#: Fraction of the agent universe that may move in the same direction
#: within a window-mean before the correlation flag fires. 0.85 —
#: legitimate market events rarely push 85% of agents the same way
#: across 5 epochs in a row; coordinated manipulation does.
MAX_DIRECTIONAL_SHARE = 0.85

#: In the mass-failure check, an agent counts as "failing" if its score
#: dropped by at least this many points in ONE epoch.
MASS_FAILURE_DROP = 200

#: Fraction of agents that may experience a mass-failure-grade drop in
#: ONE epoch before the mass-failure flag fires. 0.50 — half the
#: population crashing at once is the "all loans default" signature.
MASS_FAILURE_AGENT_FRACTION = 0.50

#: Minimum agent population required before either check is permitted
#: to fire. Below this, individual moves dominate the fractions.
MIN_AGENTS_FOR_CORRELATION = 5


# =============================================================================
# Reports
# =============================================================================


@dataclass(frozen=True, slots=True)
class CorrelatedMovementReport:
    """
    Result of the rolling-window correlation check.

    `window_size`      number of (snapshot, prior) PAIRS over which the
                       direction tally was computed.
    `mean_up_share`    mean fraction of agents moving UP across the
                       window (counting only deltas above the noise
                       floor).
    `mean_down_share`  mean fraction of agents moving DOWN.
    `evidence_hash`    canonical 32-byte SHA-256 over the per-epoch
                       directional tallies — deterministic, so every
                       honest cluster member computes the same hash
                       for the same input window.
    """

    window_size:     int
    mean_up_share:   float
    mean_down_share: float
    is_correlated:   bool
    direction:       str  # "UP" | "DOWN" | "NONE"
    evidence_hash:   str

    @property
    def is_flagged(self) -> bool:
        return self.is_correlated


@dataclass(frozen=True, slots=True)
class MassFailureReport:
    """
    Result of the single-epoch mass-failure check.

    `failed_agents`         count of agents whose score dropped by
                            at least `MASS_FAILURE_DROP` in this epoch.
    `population_size`       total agents this epoch.
    `failure_fraction`      `failed_agents / population_size`.
    `is_mass_failure`       True iff the fraction exceeded the floor.
    `evidence_hash`         canonical hash of the failing wallet set.
    """

    epoch:               int
    failed_agents:       int
    population_size:     int
    failure_fraction:    float
    is_mass_failure:     bool
    evidence_hash:       str


# =============================================================================
# Errors
# =============================================================================


class CorrelatedInflationError(RuntimeError):
    """
    Raised when the cluster wants to fail CLOSED on a detected
    correlated movement OR mass failure (e.g. a pre-issue hook).

    `.report` carries the underlying `CorrelatedMovementReport` or
    `MassFailureReport`.
    """

    def __init__(self, message: str, report):
        super().__init__(message)
        self.report = report


# =============================================================================
# Helpers
# =============================================================================


def _directional_tally(
    snapshot: EpochSnapshot,
    prior:    EpochSnapshot,
    min_delta: int,
) -> tuple[int, int, int]:
    """
    Count (up, down, total_movers) for the snapshot vs prior. An agent
    is counted only if it appears in BOTH snapshots — fresh agents are
    skipped (they have no prior score to compare).
    """
    prior_map = {a.agent_wallet: a.score for a in prior.agents}
    up = down = movers = 0
    for a in snapshot.agents:
        if a.agent_wallet not in prior_map:
            continue
        delta = a.score - prior_map[a.agent_wallet]
        if abs(delta) < min_delta:
            continue
        movers += 1
        if delta > 0:
            up += 1
        else:
            down += 1
    return up, down, movers


def _hash_window(
    pairs: Sequence[tuple[int, int, int, int]],
) -> str:
    """Hash a sequence of (epoch, up, down, movers) tuples."""
    h = hashlib.sha256()
    for epoch, up, down, movers in pairs:
        h.update(epoch.to_bytes(8, "big", signed=True))
        h.update(up.to_bytes(8, "big"))
        h.update(down.to_bytes(8, "big"))
        h.update(movers.to_bytes(8, "big"))
    return h.hexdigest()


# =============================================================================
# Correlated-movement check
# =============================================================================


def verify_correlated_movement(
    snapshots: Sequence[EpochSnapshot],
    *,
    window:                int   = CORRELATION_WINDOW,
    min_delta:             int   = DIRECTIONAL_MIN_DELTA,
    max_directional_share: float = MAX_DIRECTIONAL_SHARE,
    min_agents:            int   = MIN_AGENTS_FOR_CORRELATION,
) -> CorrelatedMovementReport:
    """
    Compute the rolling-window correlation of score movements across
    the agent universe.

    `snapshots` must be in CHRONOLOGICAL order; the function uses the
    last `window + 1` snapshots — the +1 because correlations are
    computed over adjacent PAIRS.

    Returns
    -------
    CorrelatedMovementReport
        With `is_correlated` True iff either the mean UP share OR the
        mean DOWN share across the window exceeded
        `max_directional_share`. The reported `direction` names the
        dominant sign.
    """
    if len(snapshots) < 2:
        return CorrelatedMovementReport(
            window_size=0, mean_up_share=0.0, mean_down_share=0.0,
            is_correlated=False, direction="NONE",
            evidence_hash=hashlib.sha256(b"").hexdigest(),
        )

    pairs: list[tuple[EpochSnapshot, EpochSnapshot]] = []
    # Last `window` adjacent pairs.
    for i in range(max(1, len(snapshots) - window), len(snapshots)):
        pairs.append((snapshots[i], snapshots[i - 1]))

    up_shares: list[float] = []
    down_shares: list[float] = []
    hash_input: list[tuple[int, int, int, int]] = []

    for current, prior in pairs:
        if current.size < min_agents or prior.size < min_agents:
            hash_input.append((current.epoch, 0, 0, 0))
            continue
        up, down, movers = _directional_tally(current, prior, min_delta)
        hash_input.append((current.epoch, up, down, movers))
        if movers == 0:
            continue
        # Denominator is the snapshot's full population — share of the
        # universe that moved in each direction.
        up_shares.append(up / current.size)
        down_shares.append(down / current.size)

    if not up_shares:
        return CorrelatedMovementReport(
            window_size=len(pairs),
            mean_up_share=0.0,
            mean_down_share=0.0,
            is_correlated=False,
            direction="NONE",
            evidence_hash=_hash_window(hash_input),
        )

    mean_up = sum(up_shares) / len(up_shares)
    mean_down = sum(down_shares) / len(down_shares)
    correlated_up = mean_up >= max_directional_share
    correlated_down = mean_down >= max_directional_share
    is_correlated = correlated_up or correlated_down
    direction = (
        "UP" if correlated_up
        else "DOWN" if correlated_down
        else "NONE"
    )

    return CorrelatedMovementReport(
        window_size=len(pairs),
        mean_up_share=mean_up,
        mean_down_share=mean_down,
        is_correlated=is_correlated,
        direction=direction,
        evidence_hash=_hash_window(hash_input),
    )


# =============================================================================
# Mass-failure check
# =============================================================================


def verify_mass_failure(
    snapshot: EpochSnapshot,
    prior:    EpochSnapshot,
    *,
    failure_drop:     int   = MASS_FAILURE_DROP,
    failure_fraction: float = MASS_FAILURE_AGENT_FRACTION,
    min_agents:       int   = MIN_AGENTS_FOR_CORRELATION,
) -> MassFailureReport:
    """
    Detect the death-spiral's terminal phase: a large fraction of
    agents losing significant score in ONE epoch.

    Returns a `MassFailureReport`. The cluster reaction is operator-
    facing (alert + evidence) — the events that produce mass failure
    are typically NOT something the cluster can refuse to sign about
    (the failures are real; the audit's concern is that the DeFi
    consumers needed prior warning that the population was concentrated
    enough to fail together). PDS-3 provides the warning hash.
    """
    if snapshot.size < min_agents or prior.size < min_agents:
        return MassFailureReport(
            epoch=snapshot.epoch,
            failed_agents=0,
            population_size=snapshot.size,
            failure_fraction=0.0,
            is_mass_failure=False,
            evidence_hash=hashlib.sha256(b"").hexdigest(),
        )

    prior_map = {a.agent_wallet: a.score for a in prior.agents}
    failed: list[str] = []
    for a in snapshot.agents:
        prev = prior_map.get(a.agent_wallet)
        if prev is None:
            continue
        if (prev - a.score) >= failure_drop:
            failed.append(a.agent_wallet)

    failed_count = len(failed)
    fraction = failed_count / snapshot.size
    is_mass = fraction >= failure_fraction

    h = hashlib.sha256()
    h.update(snapshot.epoch.to_bytes(8, "big", signed=True))
    for w in sorted(failed):
        h.update(w.encode("utf-8"))
        h.update(b"\x00")

    return MassFailureReport(
        epoch=snapshot.epoch,
        failed_agents=failed_count,
        population_size=snapshot.size,
        failure_fraction=fraction,
        is_mass_failure=is_mass,
        evidence_hash=h.hexdigest(),
    )


# =============================================================================
# Combined fail-closed wrapper
# =============================================================================


def enforce_no_correlated_inflation(
    snapshots: Sequence[EpochSnapshot],
    **kwargs,
) -> CorrelatedMovementReport:
    """
    Run `verify_correlated_movement` and raise
    `CorrelatedInflationError` on a positive verdict.

    Intended call site: the cluster's pre-issue gate, AFTER PDS-1 has
    cleared this epoch's snapshot. PDS-3 is the SECOND-OPINION gate
    that uses MULTI-EPOCH HISTORY where PDS-1 used only the current
    pair. A cluster operator who wants to bypass should bypass both
    explicitly — not by avoiding the multi-epoch hash.
    """
    report = verify_correlated_movement(snapshots, **kwargs)
    if report.is_correlated:
        raise CorrelatedInflationError(
            f"PDS-3: cluster detected correlated {report.direction} "
            f"movement across {report.window_size} epochs — mean "
            f"directional share "
            f"{(report.mean_up_share if report.direction == 'UP' else report.mean_down_share):.1%} "
            f"exceeds floor {MAX_DIRECTIONAL_SHARE:.0%}. "
            f"Evidence hash: {report.evidence_hash[:16]}…. This is the "
            f"long-range fingerprint of the Protocol Death Spiral; the "
            f"per-agent drift detector cannot see it. Investigate the "
            f"upstream RPC fleet (HCR-1) and the cluster input "
            f"commitment (AW-01) before any forced override.",
            report,
        )
    return report


__all__ = [
    "CORRELATION_WINDOW",
    "CorrelatedInflationError",
    "CorrelatedMovementReport",
    "DIRECTIONAL_MIN_DELTA",
    "MASS_FAILURE_AGENT_FRACTION",
    "MASS_FAILURE_DROP",
    "MAX_DIRECTIONAL_SHARE",
    "MIN_AGENTS_FOR_CORRELATION",
    "MassFailureReport",
    "enforce_no_correlated_inflation",
    "verify_correlated_movement",
    "verify_mass_failure",
]
