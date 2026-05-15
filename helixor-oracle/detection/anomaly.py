"""
detection/anomaly.py — Dimension 2: anomaly ensemble + Isolation Forest.

STATUS: Day 7 — Methods 1-3 landed. Methods 4-5 + Isolation Forest follow Day 8.

ALGORITHMS WIRED TODAY (Day 7)
------------------------------
Method 1 — feature-group disagreement ("prediction uncertainty"):
    Each of the 9 feature groups produces its own anomaly estimate (RMS of
    that group's z-scores). Method 1 is the VARIANCE across the 9 estimates.
    Healthy agents are uniformly normal — groups agree, variance ≈ 0.
    Anomalous agents are off in some groups but not others — groups
    disagree, variance is high. (See _anomaly_math for why this stands in
    for "prediction uncertainty" without needing per-feature sub-models.)

Method 2 — diagonal Mahalanobis distance:
    sqrt(Σ z_i²) — L2 norm of the z-vector. Geometric distance from the
    baseline centroid; dominated by the single worst feature.

Method 3 — joint negative log-likelihood:
    Mean per-feature surprisal under N(μ_i, σ_i²). Dominated by HOW MANY
    features are improbable — the deliberate counterpoint to Method 2.

SCORE LAYOUT (today: partial implementation)
--------------------------------------------
Anomaly dimension MAX_SCORE = 200, split across 6 ensemble components:
   Method 1   0..34   Day 7
   Method 2   0..33   Day 7
   Method 3   0..33   Day 7
   Method 4   0..34   Day 8 (n-gram sequence deviation)
   Method 5   0..33   Day 8 (adversarial / feature-space jumps)
   IsoForest  0..33   Day 8
                ----
                 200
Day 7 awards up to 100 of the 200 points. `FlagBit.PROVISIONAL` is set
until Day 8 completes the ensemble.

FLAGS SET BY THIS DETECTOR
--------------------------
    FLAG_METHOD_1 / 2 / 3   the corresponding method's health sub-score is low
    FlagBit.PROVISIONAL     always set today (ensemble partial)
    FlagBit.DEGRADED_BASELINE  if baseline.is_provisional
    FlagBit.IMMEDIATE_RED   if ANY method is extreme (health ~ 0) — anomaly
                            is the dimension that can short-circuit to RED
"""

from __future__ import annotations

from collections.abc import Mapping

from baseline import BaselineStats
from detection._anomaly_math import (
    feature_z_scores,
    magnitude_to_health,
    method1_group_disagreement,
    method2_mahalanobis,
    method3_mean_surprisal,
)
from detection.base import Detector, assert_baseline_compatible
from detection.types import DimensionId, DimensionResult, FlagBit
from features import FeatureVector
from features.vector import GROUP_SIZES, group_of


# Dimension-specific flag bits (bits 16-21). Order matches the Day-4 stub.
FLAG_METHOD_1  = 1 << 16
FLAG_METHOD_2  = 1 << 17
FLAG_METHOD_3  = 1 << 18
FLAG_METHOD_4  = 1 << 19    # Day 8
FLAG_METHOD_5  = 1 << 20    # Day 8
FLAG_ISOFOREST = 1 << 21    # Day 8


SUB_SCORE_KEYS: tuple[str, ...] = (
    "method_1_uncertainty",   # in [0, 1]; 1.0 = healthy
    "method_2_mahalanobis",   # in [0, 1]; 1.0 = healthy
    "method_3_zscore",        # in [0, 1]; 1.0 = healthy
    "method_4_ngram_deviation",   # Day 8
    "method_5_adversarial",       # Day 8
    "isoforest_score",            # Day 8
)


# -- Tunables -----------------------------------------------------------------
# Day-7 point budget: 34 + 33 + 33 = 100 of the 200-point dimension.
METHOD_1_MAX_POINTS = 34
METHOD_2_MAX_POINTS = 33
METHOD_3_MAX_POINTS = 33

# Per-method saturation magnitudes — the anomaly magnitude at which the
# method's health sub-score hits 0.0. Each method has its own natural scale.
#
#  Method 1 (variance of 9 group-RMS estimates): for a healthy agent every
#  group RMS is near 0-1, so the variance is < ~1. A variance of 9.0 means
#  group estimates are wildly spread (e.g. some groups at RMS 6, others at 0).
METHOD_1_SATURATION = 9.0
#
#  Method 2 (L2 norm of 100 clamped z-scores): a healthy agent sits near
#  sqrt(100 * 1^2) ~ 10 by pure noise. Anomalous starts well above that;
#  saturation at 40 (~ a dozen features at z=10, or broad elevation).
METHOD_2_SATURATION = 40.0
#
#  Method 3 (mean surprisal = mean of 0.5 z_i^2): a healthy agent with
#  z ~ N(0,1) has mean 0.5 z^2 ~ 0.5. Saturation at 8.0 (~ mean |z| ~ 4).
METHOD_3_SATURATION = 8.0

# A method whose health sub-score falls below this is "extreme" and sets
# the universal IMMEDIATE_RED fast-path bit.
IMMEDIATE_RED_HEALTH_FLOOR = 0.05
# A method whose health sub-score falls below this sets its FLAG_METHOD_n.
METHOD_FLAG_HEALTH_FLOOR   = 0.5


# =============================================================================
# AnomalyDetector — Day 7 (Methods 1-3)
# =============================================================================

class AnomalyDetector:
    """
    Day 7: Methods 1-3 of the anomaly ensemble. Methods 4-5 + Isolation
    Forest are stubbed; PROVISIONAL stays set until Day 8.

    Pure, deterministic. Stdlib-only math -> byte-identical across the
    Phase-4 oracle cluster.
    """

    @property
    def dimension(self) -> DimensionId:
        return DimensionId.ANOMALY

    @property
    def algo_version(self) -> int:
        # Day-4 stub = 1. Real Methods 1-3 = 2.
        return 2

    def score(
        self,
        features: FeatureVector,
        baseline: BaselineStats,
    ) -> DimensionResult:
        # 1. Refuse if the baseline isn't comparable.
        assert_baseline_compatible(baseline)

        flags = int(FlagBit.PROVISIONAL)
        if baseline.is_provisional:
            flags |= int(FlagBit.DEGRADED_BASELINE)

        # 2. Per-feature z-scores — the shared substrate for all 3 methods.
        z_scores = feature_z_scores(
            features.to_list(),
            baseline.feature_means,
            baseline.feature_stds,
        )

        # 3. Method 1 — feature-group disagreement.
        group_z = _group_z_scores(z_scores)
        m1_magnitude = method1_group_disagreement(group_z)
        m1_health    = magnitude_to_health(m1_magnitude, saturation=METHOD_1_SATURATION)

        # 4. Method 2 — diagonal Mahalanobis distance.
        m2_magnitude = method2_mahalanobis(z_scores)
        m2_health    = magnitude_to_health(m2_magnitude, saturation=METHOD_2_SATURATION)

        # 5. Method 3 — mean per-feature surprisal.
        m3_magnitude = method3_mean_surprisal(z_scores)
        m3_health    = magnitude_to_health(m3_magnitude, saturation=METHOD_3_SATURATION)

        # 6. Flags — per-method + IMMEDIATE_RED fast-path.
        if m1_health < METHOD_FLAG_HEALTH_FLOOR:
            flags |= FLAG_METHOD_1
        if m2_health < METHOD_FLAG_HEALTH_FLOOR:
            flags |= FLAG_METHOD_2
        if m3_health < METHOD_FLAG_HEALTH_FLOOR:
            flags |= FLAG_METHOD_3
        if min(m1_health, m2_health, m3_health) < IMMEDIATE_RED_HEALTH_FLOOR:
            flags |= int(FlagBit.IMMEDIATE_RED)

        # 7. Combine into a partial 0..200 score. Health sub-scores are
        #    "good" (1.0 = healthy); multiply by each method's point budget.
        score_partial = int(round(
            m1_health * METHOD_1_MAX_POINTS +
            m2_health * METHOD_2_MAX_POINTS +
            m3_health * METHOD_3_MAX_POINTS
        ))
        score_partial = max(0, min(score_partial, 200))

        sub_scores: Mapping[str, float] = {
            "method_1_uncertainty":     m1_health,
            "method_2_mahalanobis":     m2_health,
            "method_3_zscore":          m3_health,
            "method_4_ngram_deviation": 0.0,   # Day 8
            "method_5_adversarial":     0.0,   # Day 8
            "isoforest_score":          0.0,   # Day 8
        }

        return DimensionResult(
            dimension=DimensionId.ANOMALY,
            score=score_partial,
            max_score=200,
            flags=flags,
            sub_scores=sub_scores,
            algo_version=self.algo_version,
        )


# =============================================================================
# Helpers
# =============================================================================

def _group_z_scores(z_scores: list[float]) -> dict[str, list[float]]:
    """
    Partition the 100 per-feature z-scores into the 9 feature groups.

    Uses the canonical feature order: the i-th z-score corresponds to the
    i-th feature in FeatureVector's ordered field list, and `group_of()`
    maps each feature name to its group.
    """
    import dataclasses
    field_names = [f.name for f in dataclasses.fields(FeatureVector)]
    if len(field_names) != len(z_scores):
        raise ValueError(
            f"z-score / field-name length mismatch: "
            f"{len(z_scores)} vs {len(field_names)}"
        )
    groups: dict[str, list[float]] = {g: [] for g in GROUP_SIZES}
    for name, z in zip(field_names, z_scores, strict=True):
        groups[group_of(name)].append(z)
    return groups


# Static check: the real detector still conforms to the Detector Protocol.
_: Detector = AnomalyDetector()
