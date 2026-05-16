"""
detection/anomaly.py — Dimension 2: anomaly ensemble + Isolation Forest.

STATUS: Day 8 — COMPLETE. All 5 methods + Isolation Forest wired.

THE SIX ENSEMBLE COMPONENTS
---------------------------
Method 1 — feature-group disagreement ("prediction uncertainty"):
    Variance across the 9 feature groups' own RMS-z anomaly estimates.
    Catches LOCALISED anomalies (some groups off, others not).

Method 2 — diagonal Mahalanobis distance:
    L2 norm of the z-vector. Dominated by the single worst feature.

Method 3 — joint negative log-likelihood:
    Mean per-feature surprisal. Dominated by HOW MANY features are off.

Method 4 — n-gram sequence deviation:
    RMS of the 14 `sequence`-group z-scores. The sequence group is computed
    FROM the agent's action n-grams (bigram/trigram entropy, repeat runs);
    a tool-invocation pattern that no longer matches the baseline n-gram
    structure shows up here.

Method 5 — adversarial signal (sudden feature-space jumps):
    Excess kurtosis of the z-distribution. Natural drift moves many
    features together (bell-shaped z-distribution, kurtosis ~ 0); an
    adversarial manipulation spikes a FEW features (sparse, high kurtosis).

Isolation Forest — deterministic, over the 100-feature vector:
    Catches BROAD anomalies (a full behaviour-class change). Sparse spikes
    are Method 5's job; the two are complementary. The forest is built on a
    synthetic reference population drawn from the agent's own baseline
    distribution, with the PRNG seeded from baseline.stats_hash so the whole
    computation is a pure function (Phase-4 BFT determinism).

SCORE LAYOUT — full 200-point budget
------------------------------------
   Method 1   0..34
   Method 2   0..33
   Method 3   0..33
   Method 4   0..34
   Method 5   0..33
   IsoForest  0..33
              ----
               200

FLAGS SET BY THIS DETECTOR
--------------------------
    FLAG_METHOD_1..5 / FLAG_ISOFOREST   the component's health sub-score is low
    FlagBit.DEGRADED_BASELINE           if baseline.is_provisional
    FlagBit.IMMEDIATE_RED               if ANY component is extreme — anomaly
                                        can short-circuit the composite to RED
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping

from baseline import BaselineStats
from detection._anomaly_math import (
    feature_z_scores,
    isolation_forest_health,
    isolation_forest_score,
    magnitude_to_health,
    method1_group_disagreement,
    method2_mahalanobis,
    method3_mean_surprisal,
    method4_sequence_deviation,
    method5_adversarial_kurtosis,
)
from detection.base import Detector, assert_baseline_compatible
from detection.types import DimensionId, DimensionResult, FlagBit
from features import FeatureVector
from features.vector import GROUP_SIZES, group_of


# Dimension-specific flag bits (bits 16-21). Order matches the Day-4 stub.
FLAG_METHOD_1  = 1 << 16
FLAG_METHOD_2  = 1 << 17
FLAG_METHOD_3  = 1 << 18
FLAG_METHOD_4  = 1 << 19
FLAG_METHOD_5  = 1 << 20
FLAG_ISOFOREST = 1 << 21


SUB_SCORE_KEYS: tuple[str, ...] = (
    "method_1_uncertainty",     # group disagreement,    1.0 = healthy
    "method_2_mahalanobis",     # diagonal Mahalanobis,  1.0 = healthy
    "method_3_zscore",          # joint log-likelihood,  1.0 = healthy
    "method_4_ngram_deviation", # sequence-group dev,    1.0 = healthy
    "method_5_adversarial",     # kurtosis spikiness,    1.0 = healthy
    "isoforest_score",          # isolation forest,      1.0 = healthy
)


# -- Tunables: point budget — 34+33+33 + 34+33+33 = 200 -----------------------
METHOD_1_MAX_POINTS   = 34
METHOD_2_MAX_POINTS   = 33
METHOD_3_MAX_POINTS   = 33
METHOD_4_MAX_POINTS   = 34
METHOD_5_MAX_POINTS   = 33
ISOFOREST_MAX_POINTS  = 33

# Per-method saturation magnitudes — the anomaly magnitude at which the
# method's health sub-score hits 0.0. Each has its own natural scale.
#
#  Method 1 — variance of 9 group-RMS estimates. Healthy ~ 0; a variance of
#  9.0 means group estimates are wildly spread.
METHOD_1_SATURATION = 9.0
#  Method 2 — L2 norm of 100 clamped z-scores. Healthy ~ sqrt(100) = 10 by
#  noise; saturation at 40.
METHOD_2_SATURATION = 40.0
#  Method 3 — mean surprisal = mean of 0.5 z^2. Healthy ~ 0.5; saturation
#  at 8.0 (mean |z| ~ 4).
METHOD_3_SATURATION = 8.0
#  Method 4 — RMS of the 14 sequence-group z-scores. Healthy ~ 0-1;
#  saturation at 6.0 (sequence features ~ 6σ off).
METHOD_4_SATURATION = 6.0
#  Method 5 — excess kurtosis. NOTE on calibration: an idealised Gaussian
#  z-distribution has excess kurtosis ~ 0, but a REAL healthy agent's
#  single-day feature vector (daily aggregates of bounded fractions and
#  heavy-tailed counts) naturally runs ~ 5-8 even with no manipulation. A
#  genuine sparse adversarial spike runs into the 25-40+ range. Saturation
#  at 40.0 keeps healthy agents near full health while still collapsing on
#  real adversarial spikes.
METHOD_5_SATURATION = 40.0

# A component whose health falls below this sets the universal IMMEDIATE_RED.
IMMEDIATE_RED_HEALTH_FLOOR = 0.05
# A component whose health falls below this sets its FLAG_*.
METHOD_FLAG_HEALTH_FLOOR   = 0.5


# Cached canonical feature field-order (the i-th z-score ↔ the i-th field).
_FIELD_NAMES = [f.name for f in dataclasses.fields(FeatureVector)]


# =============================================================================
# AnomalyDetector — Day 8 (complete ensemble)
# =============================================================================

class AnomalyDetector:
    """
    Day 8: the complete 5-method + Isolation Forest anomaly ensemble.

    Pure, deterministic. The Isolation Forest's PRNG is seeded from the
    baseline's stats_hash, so even the forest is a pure function of
    (features, baseline) — byte-identical across the Phase-4 oracle cluster.
    """

    @property
    def dimension(self) -> DimensionId:
        return DimensionId.ANOMALY

    @property
    def algo_version(self) -> int:
        # Day-4 stub = 1; Day-7 (Methods 1-3, partial) = 2; Day-8 (all 6) = 3.
        return 3

    def score(
        self,
        features: FeatureVector,
        baseline: BaselineStats,
    ) -> DimensionResult:
        # 1. Refuse if the baseline isn't comparable.
        assert_baseline_compatible(baseline)

        flags = 0
        if baseline.is_provisional:
            flags |= int(FlagBit.DEGRADED_BASELINE)

        # 2. Per-feature z-scores — the shared substrate.
        feature_list = features.to_list()
        z_scores = feature_z_scores(
            feature_list,
            baseline.feature_means,
            baseline.feature_stds,
        )

        # 3. Method 1 — feature-group disagreement.
        group_z = _group_z_scores(z_scores)
        m1_health = magnitude_to_health(
            method1_group_disagreement(group_z), saturation=METHOD_1_SATURATION,
        )

        # 4. Method 2 — diagonal Mahalanobis distance.
        m2_health = magnitude_to_health(
            method2_mahalanobis(z_scores), saturation=METHOD_2_SATURATION,
        )

        # 5. Method 3 — mean per-feature surprisal.
        m3_health = magnitude_to_health(
            method3_mean_surprisal(z_scores), saturation=METHOD_3_SATURATION,
        )

        # 6. Method 4 — n-gram sequence deviation (the 14 sequence features).
        sequence_z = [
            z for name, z in zip(_FIELD_NAMES, z_scores, strict=True)
            if group_of(name) == "sequence"
        ]
        m4_health = magnitude_to_health(
            method4_sequence_deviation(sequence_z), saturation=METHOD_4_SATURATION,
        )

        # 7. Method 5 — adversarial spikiness (excess kurtosis of z-distribution).
        m5_health = magnitude_to_health(
            method5_adversarial_kurtosis(z_scores), saturation=METHOD_5_SATURATION,
        )

        # 8. Isolation Forest. The PRNG seed is derived from the baseline's
        #    stats_hash → the forest is a pure function of (features, baseline).
        iso_seed = _seed_from_hash(baseline.stats_hash)
        iso_raw = isolation_forest_score(
            feature_list,
            baseline.feature_means,
            baseline.feature_stds,
            seed=iso_seed,
        )
        iso_health = isolation_forest_health(iso_raw)

        # 9. Flags — per-component + IMMEDIATE_RED fast-path.
        component_healths = {
            FLAG_METHOD_1:  m1_health,
            FLAG_METHOD_2:  m2_health,
            FLAG_METHOD_3:  m3_health,
            FLAG_METHOD_4:  m4_health,
            FLAG_METHOD_5:  m5_health,
            FLAG_ISOFOREST: iso_health,
        }
        for flag_bit, health in component_healths.items():
            if health < METHOD_FLAG_HEALTH_FLOOR:
                flags |= flag_bit
        if min(component_healths.values()) < IMMEDIATE_RED_HEALTH_FLOOR:
            flags |= int(FlagBit.IMMEDIATE_RED)

        # 10. Combine into the full 0..200 score. Health sub-scores are
        #     "good" (1.0 = healthy); multiply by each component's budget.
        score_total = int(round(
            m1_health  * METHOD_1_MAX_POINTS  +
            m2_health  * METHOD_2_MAX_POINTS  +
            m3_health  * METHOD_3_MAX_POINTS  +
            m4_health  * METHOD_4_MAX_POINTS  +
            m5_health  * METHOD_5_MAX_POINTS  +
            iso_health * ISOFOREST_MAX_POINTS
        ))
        score_total = max(0, min(score_total, 200))

        sub_scores: Mapping[str, float] = {
            "method_1_uncertainty":     m1_health,
            "method_2_mahalanobis":     m2_health,
            "method_3_zscore":          m3_health,
            "method_4_ngram_deviation": m4_health,
            "method_5_adversarial":     m5_health,
            "isoforest_score":          iso_health,
        }

        return DimensionResult(
            dimension=DimensionId.ANOMALY,
            score=score_total,
            max_score=200,
            flags=flags,
            sub_scores=sub_scores,
            algo_version=self.algo_version,
        )


# =============================================================================
# Helpers
# =============================================================================

def _group_z_scores(z_scores: list[float]) -> dict[str, list[float]]:
    """Partition the 100 per-feature z-scores into the 9 feature groups."""
    if len(_FIELD_NAMES) != len(z_scores):
        raise ValueError(
            f"z-score / field-name length mismatch: "
            f"{len(z_scores)} vs {len(_FIELD_NAMES)}"
        )
    groups: dict[str, list[float]] = {g: [] for g in GROUP_SIZES}
    for name, z in zip(_FIELD_NAMES, z_scores, strict=True):
        groups[group_of(name)].append(z)
    return groups


def _seed_from_hash(stats_hash: str) -> int:
    """
    Derive a deterministic 64-bit PRNG seed from the baseline's stats_hash.

    stats_hash is already a SHA-256 hex digest of the baseline's statistical
    content. Taking its leading 16 hex chars gives a stable 64-bit integer —
    so the Isolation Forest is identical on every oracle node for a given
    baseline, and changes only when the baseline itself changes.
    """
    if not stats_hash:
        return 0
    return int(stats_hash[:16], 16)


# Static check: the real detector still conforms to the Detector Protocol.
_: Detector = AnomalyDetector()
