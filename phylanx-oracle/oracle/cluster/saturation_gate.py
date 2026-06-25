"""
oracle/cluster/saturation_gate.py — PDS-1: cluster-wide score saturation gate.

THE CATASTROPHIC FAILURE SCENARIO (audit Scenario A — Protocol Death Spiral)
---------------------------------------------------------------------------
    "An attacker compromises 2 oracle nodes, runs slow-drift inflation
    (VULN-03) for 30 epochs until every agent's score is in the 900+
    band, DeFi protocols issue maximum loans against those scores, and
    the attacker triggers mass agent failures simultaneously — every
    loan defaults at once, the protocol's credibility is destroyed."

The slow-drift detector (`oracle/cluster/drift_detector.py`) closes the
PER-AGENT case: a node consistently above the cluster median is named.
What it cannot close is the SYSTEM-WIDE case where every agent moves
TOGETHER — if the upstream RPC data is poisoned identically for every
agent, no agent deviates from the cluster median because there IS no
honest median to deviate from. Every honest node sees the same poisoned
inputs and signs the same poisoned scores.

The death spiral therefore has a fingerprint INDEPENDENT of any
single-agent drift: an unprecedented FRACTION of the agent universe
migrates into the HIGH band (≥700 = GREEN tier) within a single epoch,
or the score-distribution VARIANCE collapses (all agents land on
similar inflated values).

THE MITIGATION (this file)
--------------------------
A pure-stdlib, deterministic gate the cluster runs against the full
per-epoch agent score distribution BEFORE signing the cert batch.

  * `verify_band_saturation(snapshot, prior)` — refuses to sign if
    a suspicious fraction of agents migrated into the HIGH band
    (700+) compared to the prior epoch.
  * `verify_variance_collapse(snapshot, prior_snapshots)` — refuses
    to sign if the score-distribution std dev collapsed by more
    than `VARIANCE_COLLAPSE_THRESHOLD` against the rolling mean of
    prior epochs.
  * `verify_saturation(snapshot, prior_snapshots)` — the composite
    gate that runs both checks and aggregates the verdict.

The gate is INTENTIONALLY conservative — it fails CLOSED. A noisy
positive (the cluster refuses to sign one legitimate band-shift event)
is dramatically less expensive than a quiet false negative (mass
inflation slips through and DeFi consumers issue collateralised loans
against inflated scores).

DETERMINISM
-----------
Pure stdlib. The detector takes its inputs as explicit dataclasses; no
clock, no randomness, no network. Two cluster members running this
gate against the same input produce byte-identical verdicts.

INTERACTION WITH VULN-03 (drift_detector.py)
--------------------------------------------
VULN-03 is the PER-AGENT slow-drift detector: catches a coordinated
attacker pushing ONE agent's score up over many epochs.
PDS-1 is the CROSS-AGENT saturation detector: catches a coordinated
attacker (or upstream poisoning) pushing the WHOLE agent universe up
in ONE epoch. The two are orthogonal — VULN-03's tolerance is what
lets the slow drift happen at all; PDS-1 catches the moment that
slow drift produces system-wide saturation.

INTERACTION WITH PDS-3 (correlated_inflation.py)
-----------------------------------------------
PDS-3 detects mass-failure correlation OVER MANY EPOCHS via variance
tracking on a rolling window. PDS-1 is the SINGLE-EPOCH refusal gate
that stops the cluster from SIGNING an obviously saturated batch.
PDS-3 is the alerting / forensic layer that surfaces patterns PDS-1
caught one epoch at a time.
"""

from __future__ import annotations

from dataclasses import dataclass
from statistics import pstdev
from typing import Sequence


# =============================================================================
# Thresholds
# =============================================================================

#: Composite-score boundary above which an agent is in the HIGH band.
#: 700 matches the GREEN-tier floor in `scoring/composite.py` — the score
#: range DeFi protocols treat as collateral-grade. A cross-agent migration
#: into this band is the substrate of the death-spiral attack.
HIGH_BAND_FLOOR = 700

#: Maximum fraction of the agent universe that may migrate INTO the high
#: band within ONE epoch before the gate refuses to sign. 0.40 — chosen
#: to permit a legitimate market-wide good-news event (e.g. a bullish
#: cycle that genuinely lifts 30% of agents) while refusing the
#: catastrophic 60-90% migration that marks coordinated poisoning.
MAX_HIGH_BAND_MIGRATION_FRACTION = 0.40

#: Hard ceiling on the fraction of the agent universe that may be in the
#: HIGH band at all. 0.80 — even a slow climb that does not trip the
#: per-epoch migration cap is refused if the steady-state population
#: density in HIGH exceeds this. A healthy ecosystem has agents in every
#: tier; >80% in GREEN is structurally implausible and is the death
#: spiral's end-state signature.
ABSOLUTE_HIGH_BAND_CEILING = 0.80

#: Minimum number of agents the gate requires before it is allowed to
#: fire. Below this, single-agent moves dominate the fraction math and
#: the gate would false-positive on tiny populations.
MIN_AGENTS_FOR_GATE = 5

#: Minimum number of prior epochs required to compute a meaningful
#: variance baseline. Below this, the variance-collapse check is
#: skipped (the migration check still runs against the most recent
#: prior epoch if present).
MIN_PRIOR_EPOCHS_FOR_VARIANCE = 3

#: A score-distribution std dev that collapses to less than this fraction
#: of the rolling mean prior std dev is flagged. 0.50 — the population
#: variance halved in one epoch is the death-spiral signature where
#: every agent moves together onto the same inflated value.
VARIANCE_COLLAPSE_THRESHOLD = 0.50


# =============================================================================
# Inputs / outputs
# =============================================================================


@dataclass(frozen=True, slots=True)
class AgentScore:
    """One agent's composite score for one epoch."""

    agent_wallet: str
    score: int


@dataclass(frozen=True, slots=True)
class EpochSnapshot:
    """The full agent-score distribution for one epoch."""

    epoch: int
    agents: tuple[AgentScore, ...]

    @property
    def size(self) -> int:
        return len(self.agents)

    def high_band_count(self) -> int:
        return sum(1 for a in self.agents if a.score >= HIGH_BAND_FLOOR)

    def high_band_fraction(self) -> float:
        if not self.agents:
            return 0.0
        return self.high_band_count() / len(self.agents)

    def std_dev(self) -> float:
        if len(self.agents) < 2:
            return 0.0
        return pstdev(a.score for a in self.agents)

    def high_band_wallets(self) -> frozenset[str]:
        return frozenset(
            a.agent_wallet for a in self.agents if a.score >= HIGH_BAND_FLOOR
        )


@dataclass(frozen=True, slots=True)
class SaturationReport:
    """
    The composite saturation verdict.

    `migration_fraction`     fraction of the prior-epoch agent universe
                             that NEWLY entered the high band this epoch
                             (NaN if no prior snapshot was supplied).
    `current_high_fraction`  fraction of THIS epoch's agents in HIGH band.
    `variance_ratio`         current std dev / prior-rolling-mean std dev
                             (NaN if insufficient prior data).
    `reasons`                tuple of fired-reason codes.
    """

    epoch: int
    population_size: int
    migration_fraction: float
    current_high_fraction: float
    variance_ratio: float
    reasons: tuple[str, ...]

    @property
    def is_saturated(self) -> bool:
        return bool(self.reasons)


# Wire codes
REASON_MIGRATION = "HIGH_BAND_MIGRATION_BURST"
REASON_ABSOLUTE = "HIGH_BAND_ABSOLUTE_CEILING"
REASON_VARIANCE = "VARIANCE_COLLAPSE"


# =============================================================================
# Errors
# =============================================================================


class ScoreSaturationError(RuntimeError):
    """
    Raised when the saturation gate refuses to sign an epoch.

    The exception's `.report` attribute carries the per-reason
    diagnostic so the operator can see WHICH check failed.
    """

    def __init__(self, message: str, report: SaturationReport):
        super().__init__(message)
        self.report = report


# =============================================================================
# The gate
# =============================================================================


def verify_saturation(
    snapshot: EpochSnapshot,
    prior_snapshots: Sequence[EpochSnapshot] = (),
    *,
    high_band_floor:                   int   = HIGH_BAND_FLOOR,
    max_migration_fraction:            float = MAX_HIGH_BAND_MIGRATION_FRACTION,
    absolute_high_band_ceiling:        float = ABSOLUTE_HIGH_BAND_CEILING,
    min_agents:                        int   = MIN_AGENTS_FOR_GATE,
    min_prior_epochs_for_variance:     int   = MIN_PRIOR_EPOCHS_FOR_VARIANCE,
    variance_collapse_threshold:       float = VARIANCE_COLLAPSE_THRESHOLD,
) -> SaturationReport:
    """
    Verify that the score distribution for `snapshot` does NOT carry the
    death-spiral fingerprint.

    Three checks (all skipped on too-small inputs — the gate fails OPEN
    on undersized populations to avoid false positives at bootstrap):

      1. MIGRATION BURST — fraction of agents NEWLY entering the HIGH
         band exceeds `max_migration_fraction` between snapshot[-1] and
         snapshot.
      2. ABSOLUTE CEILING — fraction of agents in HIGH band this epoch
         exceeds `absolute_high_band_ceiling`.
      3. VARIANCE COLLAPSE — population std dev this epoch collapsed
         to < `variance_collapse_threshold` × rolling mean of the
         prior epochs' std dev.

    Returns
    -------
    SaturationReport
        The verdict. Caller must check `.is_saturated` and refuse to
        sign the epoch if True; the convenience helper
        `enforce_saturation` raises directly on a positive verdict.
    """
    reasons: list[str] = []
    migration_fraction = float("nan")
    variance_ratio = float("nan")
    current_high_fraction = (
        snapshot.high_band_fraction() if snapshot.size else 0.0
    )

    if snapshot.size < min_agents:
        return SaturationReport(
            epoch=snapshot.epoch,
            population_size=snapshot.size,
            migration_fraction=migration_fraction,
            current_high_fraction=current_high_fraction,
            variance_ratio=variance_ratio,
            reasons=(),
        )

    # ── Absolute ceiling ─────────────────────────────────────────────
    if current_high_fraction > absolute_high_band_ceiling:
        reasons.append(REASON_ABSOLUTE)

    # ── Migration burst ──────────────────────────────────────────────
    if prior_snapshots:
        prev = prior_snapshots[-1]
        if prev.size >= min_agents:
            prior_high = prev.high_band_wallets()
            newly_entered = sum(
                1
                for a in snapshot.agents
                if a.score >= high_band_floor and a.agent_wallet not in prior_high
            )
            # Denominator is the snapshot population — the rate at which
            # the universe migrated INTO the band in one epoch.
            migration_fraction = newly_entered / snapshot.size
            if migration_fraction > max_migration_fraction:
                reasons.append(REASON_MIGRATION)

    # ── Variance collapse ────────────────────────────────────────────
    if len(prior_snapshots) >= min_prior_epochs_for_variance:
        prior_stds = [
            p.std_dev()
            for p in prior_snapshots[-min_prior_epochs_for_variance:]
            if p.size >= min_agents
        ]
        if prior_stds and all(s > 0 for s in prior_stds):
            mean_prior_std = sum(prior_stds) / len(prior_stds)
            cur_std = snapshot.std_dev()
            variance_ratio = cur_std / mean_prior_std if mean_prior_std else float("nan")
            if (
                mean_prior_std > 0.0
                and cur_std / mean_prior_std < variance_collapse_threshold
            ):
                reasons.append(REASON_VARIANCE)

    return SaturationReport(
        epoch=snapshot.epoch,
        population_size=snapshot.size,
        migration_fraction=migration_fraction,
        current_high_fraction=current_high_fraction,
        variance_ratio=variance_ratio,
        reasons=tuple(reasons),
    )


def enforce_saturation(
    snapshot: EpochSnapshot,
    prior_snapshots: Sequence[EpochSnapshot] = (),
    **kwargs,
) -> SaturationReport:
    """
    Run `verify_saturation` and raise `ScoreSaturationError` on a
    positive verdict. Intended call site: the cluster's pre-signing
    hook in `cluster_runner.py` / `epoch_runner.py`. A raise here
    REFUSES TO SIGN THE EPOCH — the death spiral stops at the source.
    """
    report = verify_saturation(snapshot, prior_snapshots, **kwargs)
    if report.is_saturated:
        bits = []
        if REASON_MIGRATION in report.reasons:
            bits.append(
                f"migration burst: {report.migration_fraction:.1%} of agents "
                f"newly entered the HIGH band this epoch (ceiling "
                f"{MAX_HIGH_BAND_MIGRATION_FRACTION:.0%})"
            )
        if REASON_ABSOLUTE in report.reasons:
            bits.append(
                f"absolute ceiling: {report.current_high_fraction:.1%} of "
                f"agents are in the HIGH band (ceiling "
                f"{ABSOLUTE_HIGH_BAND_CEILING:.0%})"
            )
        if REASON_VARIANCE in report.reasons:
            bits.append(
                f"variance collapse: current std dev is "
                f"{report.variance_ratio:.2f}× the rolling prior mean "
                f"(floor {VARIANCE_COLLAPSE_THRESHOLD:.2f}×)"
            )
        raise ScoreSaturationError(
            "PDS-1: cluster refused to sign epoch "
            f"{report.epoch} — score-distribution saturation detected. "
            + "; ".join(bits)
            + ". This is the Protocol Death Spiral fingerprint: a "
            "cross-agent inflation event the per-agent drift detector "
            "cannot see. Investigate the upstream RPC fleet (HCR-1) and "
            "the input commitment (AW-01) before any forced override.",
            report,
        )
    return report


__all__ = [
    "ABSOLUTE_HIGH_BAND_CEILING",
    "AgentScore",
    "EpochSnapshot",
    "HIGH_BAND_FLOOR",
    "MAX_HIGH_BAND_MIGRATION_FRACTION",
    "MIN_AGENTS_FOR_GATE",
    "MIN_PRIOR_EPOCHS_FOR_VARIANCE",
    "REASON_ABSOLUTE",
    "REASON_MIGRATION",
    "REASON_VARIANCE",
    "SaturationReport",
    "ScoreSaturationError",
    "VARIANCE_COLLAPSE_THRESHOLD",
    "enforce_saturation",
    "verify_saturation",
]
