"""
scoring/composite.py — the composite scorer.

CONTRACT
--------
    compute_composite_score(dimension_results, baseline, ...) -> ScoreResult

PURE. Given the same five DimensionResults + baseline metadata, byte-identical
ScoreResult on every machine. The Phase-4 oracle cluster's consensus depends
on this.

THE 0-1000 MAPPING
------------------
Each dimension produces a score in [0, max_score] with its own max (drift 200,
anomaly 200, performance 200, consistency 200, security 150). Naive summing
gives 0..950 — not the 0-1000 user-facing range.

The composite:
  1. Reads each DimensionResult.score_normalised  (each in [0, 1])
  2. Multiplies by WEIGHTS[dimension]              (weights sum to 1)
  3. Sums                                          (in [0, 1])
  4. Scales by 1000 and rounds                     (in [0, 1000])

The IMMEDIATE_RED universal flag short-circuits the score to RED via the
final alert assignment — not by zeroing the score (we want the score to
reflect the underlying detection results so explanations stay coherent).

ALERT TIERS (preserved from Day-3 MVP):
  >= 700  GREEN
  >= 400  YELLOW
  <  400  RED
  IMMEDIATE_RED bit set anywhere → RED regardless of score
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType

from baseline import BASELINE_ALGO_VERSION, BaselineStats
from detection.types import DimensionId, DimensionResult, FlagBit
from scoring._gaming import (
    apply_delta_guard_rail,
    compute_confidence,
    detect_entropy_gaming,
)
from features import FEATURE_SCHEMA_VERSION, FeatureVector
from scoring.weights import SCORING_WEIGHTS_VERSION, WEIGHTS, scoring_schema_fingerprint


# Composite-scorer algorithm version. Bumped on any change to the composite logic.
SCORING_ALGO_VERSION = 2


class AlertTier(str, enum.Enum):
    GREEN  = "GREEN"
    YELLOW = "YELLOW"
    RED    = "RED"


# Thresholds. Tunable in one place; covered by tests so an accidental change is caught.
GREEN_THRESHOLD  = 700
YELLOW_THRESHOLD = 400


# =============================================================================
# ScoreResult — the composite output. Frozen + self-describing.
# =============================================================================

@dataclass(frozen=True, slots=True)
class ScoreResult:
    """
    Final composite score + every piece of evidence behind it.

    What this carries (and why):
      - `score` (0-1000)              — the user-facing number
      - `alert`                       — GREEN | YELLOW | RED
      - `dimension_results`           — every detector's full output
      - `weighted_contributions`      — per-dimension contribution to `score`
                                        (so explainers can render "drift cost 80 pts")
      - `weight_vector`               — exact DimensionId -> weight mapping used
      - `aggregated_flags`            — OR of every dimension's flags
      - `immediate_red`               — did any dimension trip the fast-path?
      - versions + fingerprints       — full provenance for audit
    """
    # ── User-facing ─────────────────────────────────────────────────────────
    score:                       int                      # 0..1000
    alert:                       AlertTier

    # ── Day-13: gaming + confidence ─────────────────────────────────────────
    confidence:                  int       # 0..1000 — how much data backs `score`
    gaming_detected:             bool      # behavioural entropy collapsed >25%
    gaming_drop_fraction:        float     # how far entropy fell, [0, 1]
    delta_clamped:               bool      # the 200-pt guard rail moved `score`

    # ── Evidence ────────────────────────────────────────────────────────────
    dimension_results:           Mapping[DimensionId, DimensionResult]
    weighted_contributions:      Mapping[DimensionId, int]       # sums to `score`
    weight_vector:               Mapping[DimensionId, float]     # exact weights used
    aggregated_flags:            int                              # OR across dimensions
    immediate_red:               bool

    # ── Versioning + provenance ────────────────────────────────────────────
    scoring_algo_version:        int       # SCORING_ALGO_VERSION at compute time
    scoring_weights_version:     int       # SCORING_WEIGHTS_VERSION
    scoring_schema_fingerprint:  str       # sha256 of (algo, weights, dims, maxes)
    feature_schema_fingerprint:  str       # from FeatureVector — provenance chain
    baseline_stats_hash:         str       # links to Day-2 commitment + Day-3 on-chain
    detector_algo_versions:      Mapping[DimensionId, int]

    # ── Provenance ─────────────────────────────────────────────────────────
    computed_at:                 datetime  # tz-aware UTC
    window_success_rate:         float = 0.0
    window_tx_count:             int = 0

    def __post_init__(self) -> None:
        # 1. Score range + type.
        if not isinstance(self.score, int) or isinstance(self.score, bool):
            raise TypeError(f"score must be int, got {type(self.score).__name__}")
        if not (0 <= self.score <= 1000):
            raise ValueError(f"score {self.score} out of range [0, 1000]")

        # 2. Alert tier alignment with score (unless IMMEDIATE_RED).
        expected = _alert_for(self.score)
        if not self.immediate_red and self.alert is not expected:
            raise ValueError(
                f"alert {self.alert.value} inconsistent with score {self.score} "
                f"(expected {expected.value}); did you bypass compute_composite_score?"
            )
        if self.immediate_red and self.alert is not AlertTier.RED:
            raise ValueError(
                f"immediate_red is True but alert is {self.alert.value}, not RED"
            )

        # 3. dimension_results covers every dimension exactly once.
        if set(self.dimension_results.keys()) != set(DimensionId.ordered()):
            raise ValueError(
                f"dimension_results must cover every DimensionId. "
                f"got={set(d.value for d in self.dimension_results)}"
            )

        # 4. weighted_contributions matches dimension_results keyset + sums to score.
        if set(self.weighted_contributions.keys()) != set(DimensionId.ordered()):
            raise ValueError("weighted_contributions must cover every DimensionId")
        if set(self.weight_vector.keys()) != set(DimensionId.ordered()):
            raise ValueError("weight_vector must cover every DimensionId")
        if abs(sum(self.weight_vector.values()) - 1.0) > 1e-9:
            raise ValueError("weight_vector must sum to 1.0")
        for dim, weight in self.weight_vector.items():
            if not isinstance(weight, float) or not (0.0 <= weight <= 1.0):
                raise ValueError(f"weight_vector[{dim.value}] must be a float in [0,1]")
        contrib_sum = sum(self.weighted_contributions.values())
        # Allow ±5 rounding difference: the sum is rounded after weighting.
        # EXCEPTION: when the 200-point delta guard rail clamped the score,
        # `score` is intentionally NOT the weighted sum — the contributions
        # describe the uncapped aggregate, `score` is the rate-limited value.
        if not self.delta_clamped and abs(contrib_sum - self.score) > 5:
            raise ValueError(
                f"weighted_contributions sum {contrib_sum} disagrees with score "
                f"{self.score} by > 5 (this is the Day-13 invariant)"
            )

        # 5. aggregated_flags fits in u32.
        if not (0 <= self.aggregated_flags <= 0xFFFFFFFF):
            raise ValueError(f"aggregated_flags must be u32, got {self.aggregated_flags}")

        # 6. detector_algo_versions covers every dimension.
        if set(self.detector_algo_versions.keys()) != set(DimensionId.ordered()):
            raise ValueError("detector_algo_versions must cover every DimensionId")

        # 7. Timezone contract.
        if self.computed_at.tzinfo is None:
            raise ValueError("computed_at must be timezone-aware UTC")

        if not isinstance(self.window_success_rate, float):
            raise TypeError("window_success_rate must be float")
        if not (0.0 <= self.window_success_rate <= 1.0):
            raise ValueError("window_success_rate must be in [0, 1]")
        if not isinstance(self.window_tx_count, int) or isinstance(self.window_tx_count, bool):
            raise TypeError("window_tx_count must be int")
        if self.window_tx_count < 0:
            raise ValueError("window_tx_count must be non-negative")

        # 7b. Day-13 fields.
        if not isinstance(self.confidence, int) or isinstance(self.confidence, bool):
            raise TypeError(f"confidence must be int, got {type(self.confidence).__name__}")
        if not (0 <= self.confidence <= 1000):
            raise ValueError(f"confidence {self.confidence} out of range [0, 1000]")
        if not isinstance(self.gaming_detected, bool):
            raise TypeError("gaming_detected must be bool")
        if not isinstance(self.delta_clamped, bool):
            raise TypeError("delta_clamped must be bool")
        if not (0.0 <= self.gaming_drop_fraction <= 1.0):
            raise ValueError(
                f"gaming_drop_fraction {self.gaming_drop_fraction} out of [0, 1]"
            )

        # 8. Freeze the mappings.
        if not isinstance(self.dimension_results, MappingProxyType):
            object.__setattr__(
                self, "dimension_results",
                MappingProxyType(dict(self.dimension_results)),
            )
        if not isinstance(self.weighted_contributions, MappingProxyType):
            object.__setattr__(
                self, "weighted_contributions",
                MappingProxyType(dict(self.weighted_contributions)),
            )
        if not isinstance(self.weight_vector, MappingProxyType):
            object.__setattr__(
                self, "weight_vector",
                MappingProxyType(dict(self.weight_vector)),
            )
        if not isinstance(self.detector_algo_versions, MappingProxyType):
            object.__setattr__(
                self, "detector_algo_versions",
                MappingProxyType(dict(self.detector_algo_versions)),
            )

    def has_flag(self, bit: FlagBit | int) -> bool:
        b = int(bit)
        return (self.aggregated_flags & b) == b


# =============================================================================
# Composite scoring
# =============================================================================

def compute_composite_score(
    dimension_results: Mapping[DimensionId, DimensionResult],
    baseline:          BaselineStats,
    *,
    features:          FeatureVector | None = None,
    previous_score:    int | None = None,
    computed_at:       datetime | None = None,
) -> ScoreResult:
    """
    Combine the five DimensionResults into a 0-1000 ScoreResult.

    Day-13 additions over the Day-4 weighted aggregate:
      - GAMING CHECK: if `features` is supplied, the agent's current
        behavioural entropy is compared against its baseline entropy; a
        collapse > 25% sets `gaming_detected`.
      - CONFIDENCE: a 0-1000 data-sufficiency score from the baseline's
        transaction count, active days, and provisional / degraded flags.
      - 200-POINT DELTA GUARD RAIL: if `previous_score` is supplied, the
        new score cannot move more than 200 points from it. Not bypassable.

    Pure. Same inputs -> byte-identical ScoreResult.

    Raises ValueError if dimension_results doesn't cover the five dimensions
    exactly once each (no missing, no duplicates, no extras).
    """
    # Validate the input shape FIRST — fail loud rather than silently produce
    # a partial composite.
    if set(dimension_results.keys()) != set(DimensionId.ordered()):
        missing = set(DimensionId.ordered()) - set(dimension_results.keys())
        extra   = set(dimension_results.keys()) - set(DimensionId.ordered())
        # `extra` may contain non-DimensionId values (defensive against callers
        # passing strings) — render uniformly via str() rather than .value.
        raise ValueError(
            f"compute_composite_score requires exactly the five DimensionIds. "
            f"missing={[d.value for d in missing]}, "
            f"extra={[getattr(d, 'value', str(d)) for d in extra]}"
        )

    # Sanity: each result's reported `dimension` matches its slot.
    for dim, result in dimension_results.items():
        if result.dimension is not dim:
            raise ValueError(
                f"slot {dim.value} contains a DimensionResult reporting "
                f"{result.dimension.value} — mismatched wiring"
            )

    # 1. Per-dimension weighted contribution in [0, 1000 * weight].
    weighted_floats: dict[DimensionId, float] = {}
    aggregated_flags = 0
    for dim in DimensionId.ordered():
        result = dimension_results[dim]
        contribution = result.score_normalised * WEIGHTS[dim] * 1000.0
        weighted_floats[dim] = contribution
        aggregated_flags |= result.flags

    # 2. Round each contribution to int (banker's rounding via int(round(...))).
    weighted_contributions = {
        dim: int(round(value)) for dim, value in weighted_floats.items()
    }

    # 3. Composite score = sum of rounded contributions, clamped to [0, 1000].
    raw_score = sum(weighted_contributions.values())
    score = max(0, min(1000, raw_score))

    # 3b. GAMING CHECK — behavioural-entropy collapse.
    #     An agent gaming the score narrows its own behaviour to chase the
    #     metric; behavioural entropy collapses. We compare the current
    #     action entropy (from the feature vector) against the baseline.
    #     With no feature vector supplied, the check abstains.
    if features is not None:
        gaming = detect_entropy_gaming(
            current_entropy=features.seq_action_entropy,
            baseline_entropy=baseline.action_entropy,
        )
        window_success_rate = features.success_rate_7d
        if features.success_rate_7d > 0.0:
            window_tx_count = int(round(features.success_count_7d / features.success_rate_7d))
        elif features.success_count_7d > 0.0:
            window_tx_count = int(round(features.success_count_7d))
        else:
            window_tx_count = int(round(max(features.failure_streak_current, features.failure_streak_max)))
    else:
        gaming = {"gaming_detected": False, "drop_fraction": 0.0, "abstained": True}
        window_success_rate = 0.0
        window_tx_count = 0
    gaming_detected      = bool(gaming["gaming_detected"])
    gaming_drop_fraction = float(gaming["drop_fraction"])

    # 3c. CONFIDENCE — how much data backs this score.
    degraded = bool(aggregated_flags & int(FlagBit.DEGRADED_BASELINE))
    confidence = compute_confidence(
        transaction_count=baseline.transaction_count,
        days_with_activity=baseline.days_with_activity,
        is_provisional=baseline.is_provisional,
        degraded_baseline=degraded,
    )

    # 3d. 200-POINT DELTA GUARD RAIL — preserved from the MVP, not bypassable.
    #     Every score that leaves this function has passed through here.
    rail = apply_delta_guard_rail(new_score=score, previous_score=previous_score)
    score = rail["score"]
    delta_clamped = bool(rail["clamped"])

    # 4. IMMEDIATE_RED fast-path.
    immediate_red = bool(aggregated_flags & int(FlagBit.IMMEDIATE_RED))
    alert = AlertTier.RED if immediate_red else _alert_for(score)

    # 5. Provenance.
    detector_versions = MappingProxyType({
        dim: result.algo_version
        for dim, result in dimension_results.items()
    })

    return ScoreResult(
        score=score,
        alert=alert,
        confidence=confidence,
        gaming_detected=gaming_detected,
        gaming_drop_fraction=gaming_drop_fraction,
        delta_clamped=delta_clamped,
        dimension_results=MappingProxyType(dict(dimension_results)),
        weighted_contributions=MappingProxyType(weighted_contributions),
        weight_vector=MappingProxyType(dict(WEIGHTS)),
        aggregated_flags=aggregated_flags,
        immediate_red=immediate_red,
        scoring_algo_version=SCORING_ALGO_VERSION,
        scoring_weights_version=SCORING_WEIGHTS_VERSION,
        scoring_schema_fingerprint=scoring_schema_fingerprint(),
        feature_schema_fingerprint=FeatureVector.feature_schema_fingerprint(),
        baseline_stats_hash=baseline.stats_hash,
        detector_algo_versions=detector_versions,
        computed_at=computed_at or datetime.now(timezone.utc),
        window_success_rate=float(max(0.0, min(1.0, window_success_rate))),
        window_tx_count=max(0, window_tx_count),
    )


def _alert_for(score: int) -> AlertTier:
    if score >= GREEN_THRESHOLD:
        return AlertTier.GREEN
    if score >= YELLOW_THRESHOLD:
        return AlertTier.YELLOW
    return AlertTier.RED
