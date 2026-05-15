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
        # Allow ±1 rounding difference: the sum is rounded after weighting, so
        # the integer parts can drift by up to len(DimensionId)-1 = 4 pts.
        if abs(contrib_sum - self.score) > 5:
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
    computed_at:       datetime | None = None,
) -> ScoreResult:
    """
    Combine the five DimensionResults into a 0-1000 ScoreResult.

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
    )


def _alert_for(score: int) -> AlertTier:
    if score >= GREEN_THRESHOLD:
        return AlertTier.GREEN
    if score >= YELLOW_THRESHOLD:
        return AlertTier.YELLOW
    return AlertTier.RED
