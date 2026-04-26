"""
scoring/engine.py — pure scoring computation. NO I/O.

Takes:
  • WindowStats  (current 7-day behavior)
  • BaselineResult (30-day baseline)
  • optional previous_score (for guard rail)

Returns:
  • ScoreResult with score (0-1000), alert level, full breakdown

Design decisions (where this differs from the spec):

  1. **Absolute success rate, not relative to baseline.**
     The spec computed `sr_score = 500 + sr_delta * 5000`, meaning an agent
     scoring 50% would get 500 points if their baseline was also 50%.
     That's wrong: 50% success is NOT trustworthy regardless of consistency.
     We use absolute brackets: ≥97% → 500, then linear decay to 0 at ≤80%.

  2. **MAD instead of stdev** for SOL volatility — matches Day 5's baseline.
     The spec used stdev; we'd compare stdev vs MAD which is meaningless.

  3. **Versioned weights via ScoringWeights dataclass.**
     Hardcoded weights make A/B testing impossible. With versioned weights,
     we can roll out new schemes by changing config, not code.

  4. **Guard rail uses signed delta.**
     We preserve raw_score and applied_score separately so the breakdown
     shows whether the guard rail was applied AND in which direction.

  5. **Anomaly flag uses absolute success_rate threshold.**
     Spec: "anomaly if success_rate < baseline.success_rate - 0.15"
     This silently drops anomaly detection for low-baseline agents.
     We add an absolute floor: anomaly if success_rate < 75% regardless.

  6. **Returns a frozen dataclass.**
     ScoreResult is immutable. Once computed, it can be stored, hashed,
     written on-chain, without any "did anyone mutate this between" bugs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Optional

from scoring.signals import BaselineResult
from scoring.window import WindowStats


# =============================================================================
# Algorithm + weights versioning
# =============================================================================

# Bump when the scoring formula changes meaningfully.
# Stored alongside every score so we can later say "this score was computed
# under v1 rules; new v2 rules would give X."
SCORING_ALGO_VERSION = 1


@dataclass(frozen=True, slots=True)
class ScoringWeights:
    """
    Versioned weight configuration. Total points must equal 1000.

    Default weights are the MVP scheme:
      - 50% success rate (most direct measure of agent reliability)
      - 30% transaction consistency (deviation from baseline behavioral tempo)
      - 20% SOL flow stability (MAD-based volatility check)
    """
    version:                int = 1
    success_rate_max:       int = 500
    consistency_max:        int = 300
    stability_max:          int = 200

    # Success rate scoring (absolute)
    success_rate_top_pct:    float = 0.97   # ≥97% → full points
    success_rate_floor_pct:  float = 0.80   # ≤80% → zero points

    # Consistency scoring (window vs baseline tempo)
    consistency_full_lo:     float = 0.5    # within ±50% of baseline → full
    consistency_full_hi:     float = 1.5
    consistency_partial_lo:  float = 0.3    # within ±70% → half
    consistency_partial_hi:  float = 2.0

    # Stability scoring (window vs baseline volatility)
    stability_full_ratio:    float = 1.5    # ≤1.5× baseline volatility → full
    stability_partial_ratio: float = 3.0    # ≤3× → half

    # Anomaly thresholds
    anomaly_relative_drop:   float = 0.15   # window < baseline - 0.15
    anomaly_absolute_floor:  float = 0.75   # OR window < 0.75 absolute

    # Guard rail — max change per epoch
    max_score_delta:         int   = 200

    def __post_init__(self):
        # Validate weights sum to 1000
        total = self.success_rate_max + self.consistency_max + self.stability_max
        if total != 1000:
            raise ValueError(
                f"ScoringWeights must sum to 1000, got {total}"
            )


DEFAULT_WEIGHTS = ScoringWeights()


# =============================================================================
# Output type
# =============================================================================

@dataclass(frozen=True, slots=True)
class ScoreBreakdown:
    """Component-by-component score breakdown — stored for transparency."""
    success_rate_score: int          # 0..weights.success_rate_max
    consistency_score:  int          # 0..weights.consistency_max
    stability_score:    int          # 0..weights.stability_max
    raw_score:          int          # sum before guard rail clamp
    guard_rail_applied: bool
    consistency_ratio:  float        # window_daily / baseline_daily
    stability_ratio:    float        # window_volatility / baseline_volatility


@dataclass(frozen=True, slots=True)
class ScoreResult:
    """
    Final scoring output. Frozen — once computed, immutable.

    This is the input to Day 7's update_score on-chain CPI.
    """
    score:               int          # 0-1000, post guard-rail
    alert:               str          # GREEN | YELLOW | RED
    anomaly_flag:        bool

    breakdown:           ScoreBreakdown

    # Inputs used (recorded for forensics + verification)
    window_success_rate: float
    window_tx_count:     int
    window_sol_volatility: int

    baseline_hash:        str
    baseline_algo_version: int

    scoring_algo_version: int = field(default=SCORING_ALGO_VERSION)
    weights_version:      int = field(default=DEFAULT_WEIGHTS.version)


# =============================================================================
# Errors
# =============================================================================

class ScoringError(Exception):
    """Base class for scoring failures."""
    pass


class StaleBaseline(ScoringError):
    """Baseline is older than allowed for scoring (default: 7 days)."""
    pass


class IncompatibleAlgoVersion(ScoringError):
    """Baseline was computed under an algorithm version we don't support."""
    pass


# =============================================================================
# Pure scoring
# =============================================================================

def score_agent(
    window:          WindowStats,
    baseline:        BaselineResult,
    *,
    previous_score:  Optional[int] = None,
    weights:         ScoringWeights = DEFAULT_WEIGHTS,
    supported_baseline_versions: tuple[int, ...] = (1,),
) -> ScoreResult:
    """
    Compute the 0-1000 trust score from window + baseline.

    Args:
        window:                current 7-day stats
        baseline:              30-day baseline reference
        previous_score:        for guard rail (None on first scoring)
        weights:               scoring scheme (defaults to MVP weights)
        supported_baseline_versions: refuse to score against unknown algo versions

    Returns:
        ScoreResult — frozen, complete with breakdown.

    Raises:
        IncompatibleAlgoVersion if baseline.algo_version not supported.
    """
    if baseline.algo_version not in supported_baseline_versions:
        raise IncompatibleAlgoVersion(
            f"Baseline algo_version={baseline.algo_version} not in "
            f"supported set {supported_baseline_versions}",
        )

    # ── Component 1: success rate (absolute, 0-500) ──────────────────────────
    sr_score = _success_rate_score(window.success_rate, weights)

    # ── Component 2: consistency (window daily / baseline daily, 0-300) ──────
    consistency_score, consistency_ratio = _consistency_score(
        window.daily_tx_avg,
        baseline.signals.median_daily_tx,
        weights,
    )

    # ── Component 3: stability (volatility ratio, 0-200) ─────────────────────
    stability_score, stability_ratio = _stability_score(
        window.sol_volatility_mad,
        baseline.signals.sol_volatility_mad,
        weights,
    )

    # ── Composite ─────────────────────────────────────────────────────────────
    raw_score = sr_score + consistency_score + stability_score
    raw_score = max(0, min(1000, raw_score))   # defensive clamp

    # ── Guard rail — limit per-epoch change ──────────────────────────────────
    final_score, guard_applied = _apply_guard_rail(
        raw_score, previous_score, weights.max_score_delta,
    )

    # ── Anomaly: relative OR absolute trigger ────────────────────────────────
    anomaly_flag = _anomaly_check(
        window.success_rate,
        baseline.signals.success_rate,
        weights,
    )

    # ── Alert tier ───────────────────────────────────────────────────────────
    alert = _alert_for(final_score)

    return ScoreResult(
        score                 = final_score,
        alert                 = alert,
        anomaly_flag          = anomaly_flag,
        breakdown             = ScoreBreakdown(
            success_rate_score = sr_score,
            consistency_score  = consistency_score,
            stability_score    = stability_score,
            raw_score          = raw_score,
            guard_rail_applied = guard_applied,
            consistency_ratio  = round(consistency_ratio, 4),
            stability_ratio    = round(stability_ratio, 4),
        ),
        window_success_rate   = window.success_rate,
        window_tx_count       = window.tx_count,
        window_sol_volatility = window.sol_volatility_mad,
        baseline_hash         = baseline.baseline_hash,
        baseline_algo_version = baseline.algo_version,
        weights_version       = weights.version,
    )


# =============================================================================
# Component scorers — each is a pure function of inputs + weights
# =============================================================================

def _success_rate_score(
    window_rate: float,
    w: ScoringWeights,
) -> int:
    """
    ABSOLUTE success-rate scoring.
        rate ≥ 0.97  → full points
        rate ≤ 0.80  → zero points
        between      → linear interpolation
    """
    if window_rate >= w.success_rate_top_pct:
        return w.success_rate_max
    if window_rate <= w.success_rate_floor_pct:
        return 0

    span = w.success_rate_top_pct - w.success_rate_floor_pct
    progress = (window_rate - w.success_rate_floor_pct) / span
    return int(progress * w.success_rate_max)


def _consistency_score(
    window_daily: float,
    baseline_daily: int,
    w: ScoringWeights,
) -> tuple[int, float]:
    """
    Score consistency of behavioral tempo.
    Returns (score, ratio).

    ratio = window_daily / baseline_daily

    full points       if 0.5 ≤ ratio ≤ 1.5
    half points       if 0.3 ≤ ratio < 0.5  OR  1.5 < ratio ≤ 2.0
    zero              otherwise (suspiciously inactive or hyperactive)

    Special case: baseline_daily == 0 means "agent has been mostly inactive
    in baseline period." In that case, treat any window activity as
    full-credit consistency since we have no reliable baseline tempo.
    """
    if baseline_daily <= 0:
        # No reliable baseline tempo. Don't penalize, don't bonus.
        return (w.consistency_max, 1.0)

    ratio = window_daily / baseline_daily

    if w.consistency_full_lo <= ratio <= w.consistency_full_hi:
        return (w.consistency_max, ratio)
    if (w.consistency_partial_lo <= ratio < w.consistency_full_lo
            or w.consistency_full_hi < ratio <= w.consistency_partial_hi):
        return (w.consistency_max // 2, ratio)
    return (0, ratio)


def _stability_score(
    window_volatility: int,
    baseline_volatility: int,
    w: ScoringWeights,
) -> tuple[int, float]:
    """
    Score volatility relative to baseline.
    Returns (score, ratio).

    ratio = window_vol / baseline_vol

    full points if ratio ≤ 1.5
    half points if 1.5 < ratio ≤ 3.0
    zero        if ratio > 3.0

    Special case: baseline_volatility == 0 (agent had perfectly stable flow).
    Any window volatility is "more than 0×" baseline. We compare against an
    absolute threshold instead — small volatility is fine, large is suspect.
    """
    if baseline_volatility == 0:
        # Use an absolute threshold of 1 SOL = 1_000_000_000 lamports.
        # Below that is fine, above is suspicious.
        if window_volatility <= 1_000_000_000:
            return (w.stability_max, 0.0)
        elif window_volatility <= 5_000_000_000:
            return (w.stability_max // 2, 0.0)
        else:
            return (0, 0.0)

    ratio = window_volatility / baseline_volatility

    if ratio <= w.stability_full_ratio:
        return (w.stability_max, ratio)
    if ratio <= w.stability_partial_ratio:
        return (w.stability_max // 2, ratio)
    return (0, ratio)


def _apply_guard_rail(
    raw_score: int,
    previous_score: Optional[int],
    max_delta: int,
) -> tuple[int, bool]:
    """
    Clamp the per-epoch change. Returns (final_score, guard_applied).

    No previous score → no clamp (first scoring after registration).
    """
    if previous_score is None:
        return (raw_score, False)

    delta = raw_score - previous_score
    if abs(delta) <= max_delta:
        return (raw_score, False)

    direction = 1 if delta > 0 else -1
    clamped   = previous_score + direction * max_delta
    return (max(0, min(1000, clamped)), True)


def _anomaly_check(
    window_rate: float,
    baseline_rate: float,
    w: ScoringWeights,
) -> bool:
    """
    Anomaly fires if EITHER:
      • Window dropped >15% relative to baseline, OR
      • Window absolute < 75% (regardless of baseline)
    """
    relative_anomaly = window_rate < (baseline_rate - w.anomaly_relative_drop)
    absolute_anomaly = window_rate < w.anomaly_absolute_floor
    return relative_anomaly or absolute_anomaly


def _alert_for(score: int) -> str:
    """Tri-state alert from score."""
    if score >= 700:
        return "GREEN"
    if score >= 400:
        return "YELLOW"
    return "RED"


# =============================================================================
# Helper: serialize ScoreResult to plain dict
# =============================================================================

def score_to_dict(r: ScoreResult) -> dict:
    """Flatten ScoreResult for logging or JSON output."""
    return {
        "score":                 r.score,
        "alert":                 r.alert,
        "anomaly_flag":          r.anomaly_flag,
        "breakdown": {
            "success_rate_score": r.breakdown.success_rate_score,
            "consistency_score":  r.breakdown.consistency_score,
            "stability_score":    r.breakdown.stability_score,
            "raw_score":          r.breakdown.raw_score,
            "guard_rail_applied": r.breakdown.guard_rail_applied,
            "consistency_ratio":  r.breakdown.consistency_ratio,
            "stability_ratio":    r.breakdown.stability_ratio,
        },
        "window_success_rate":   r.window_success_rate,
        "window_tx_count":       r.window_tx_count,
        "window_sol_volatility": r.window_sol_volatility,
        "baseline_hash":         r.baseline_hash,
        "baseline_algo_version": r.baseline_algo_version,
        "scoring_algo_version":  r.scoring_algo_version,
        "weights_version":       r.weights_version,
    }
