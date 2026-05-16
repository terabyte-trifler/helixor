"""
tests/detection/test_anomaly_detector.py — AnomalyDetector, Methods 1-3.

THE DAY-7 DONE-WHEN
-------------------
"Each of the 3 methods produces a 0-1 anomaly signal, tested against
normal + anomalous fixtures."

Each method is exercised against:
  - a NORMAL fixture (current features at the baseline mean) → health ≈ 1.0
  - an ANOMALOUS fixture crafted to target that specific method → health low

The three methods are deliberately different signals, so we also assert
they DISAGREE on shape-specific anomalies:
  - one extreme feature       → Method 2 (distance) reacts hardest
  - many mildly-off features  → Method 3 (count) reacts hardest
  - some groups off, others not → Method 1 (disagreement) reacts hardest
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone

import pytest

from baseline.types import BASELINE_ALGO_VERSION, BaselineStats
from detection import DimensionId, DimensionResult, FlagBit, default_registry
from detection.anomaly import (
    AnomalyDetector,
    FLAG_ISOFOREST,
    FLAG_METHOD_1,
    FLAG_METHOD_2,
    FLAG_METHOD_3,
    FLAG_METHOD_4,
    FLAG_METHOD_5,
)
from features import FEATURE_SCHEMA_VERSION, FeatureVector
from features.vector import TOTAL_FEATURES, group_of
from scoring.weights import scoring_schema_fingerprint


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
_FIELD_NAMES = [f.name for f in dataclasses.fields(FeatureVector)]


# =============================================================================
# Fixtures
# =============================================================================

def _baseline(*, is_provisional: bool = False) -> BaselineStats:
    """A baseline with uniform feature means (0.5) and stds (0.1)."""
    return BaselineStats(
        agent_wallet="agentANOM",
        baseline_algo_version=BASELINE_ALGO_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_schema_fingerprint=FeatureVector.feature_schema_fingerprint(),
        scoring_schema_fingerprint=scoring_schema_fingerprint(),
        window_start=REF_END - timedelta(days=30),
        window_end=REF_END,
        feature_means=tuple(0.5 for _ in range(TOTAL_FEATURES)),
        feature_stds=tuple(0.1 for _ in range(TOTAL_FEATURES)),
        txtype_distribution=(1.0, 0.0, 0.0, 0.0, 0.0),
        action_entropy=0.0,
        success_rate_30d=0.95,
        daily_success_rate_series=tuple(0.95 for _ in range(30)),
        transaction_count=150,
        days_with_activity=30,
        is_provisional=is_provisional,
        computed_at=REF_END,
        stats_hash="b" * 64,
    )


def _features(values: list[float]) -> FeatureVector:
    """Build a FeatureVector from a 100-element value list."""
    assert len(values) == TOTAL_FEATURES
    return FeatureVector(**dict(zip(_FIELD_NAMES, values)))


def _normal() -> FeatureVector:
    """All features at the baseline mean → z = 0 everywhere → healthy."""
    return _features([0.5] * TOTAL_FEATURES)


# =============================================================================
# Done-when: each method produces a 0-1 signal
# =============================================================================

class TestMethodSignalsAreUnitRange:

    def test_normal_fixture_all_methods_near_one(self):
        result = AnomalyDetector().score(_normal(), _baseline())
        assert result.sub_scores["method_1_uncertainty"] == pytest.approx(1.0, abs=1e-9)
        assert result.sub_scores["method_2_mahalanobis"] == pytest.approx(1.0, abs=1e-9)
        assert result.sub_scores["method_3_zscore"]      == pytest.approx(1.0, abs=1e-9)

    def test_all_sub_scores_in_unit_range(self):
        # Even on an extreme fixture, every sub-score stays within [0, 1].
        vals = [3.0] * TOTAL_FEATURES   # z = 25 everywhere → clamps
        result = AnomalyDetector().score(_features(vals), _baseline())
        for key in ("method_1_uncertainty", "method_2_mahalanobis", "method_3_zscore"):
            assert 0.0 <= result.sub_scores[key] <= 1.0


# =============================================================================
# Done-when: anomalous fixtures lower the signal
# =============================================================================

class TestAnomalousFixturesLowerSignal:

    def test_method2_reacts_to_one_extreme_feature(self):
        # One feature pushed to z≈12 (clamped), 99 unchanged.
        vals = [0.5] * TOTAL_FEATURES
        vals[50] = 2.0   # z = (2.0-0.5)/0.1 = 15 → clamps to 12
        result = AnomalyDetector().score(_features(vals), _baseline())
        # Method 2 (distance) reacts: one z=12 → distance 12.
        assert result.sub_scores["method_2_mahalanobis"] < 1.0
        # vs the normal case where it was 1.0.
        normal = AnomalyDetector().score(_normal(), _baseline())
        assert result.sub_scores["method_2_mahalanobis"] < \
               normal.sub_scores["method_2_mahalanobis"]

    def test_method3_reacts_to_broad_mild_shift(self):
        # Every feature mildly off (z=2). Method 3 (count) reacts hard.
        vals = [0.7] * TOTAL_FEATURES   # z = 2 everywhere
        result = AnomalyDetector().score(_features(vals), _baseline())
        assert result.sub_scores["method_3_zscore"] < 0.9
        # Method 1 should NOT react — all groups equally off → no disagreement.
        assert result.sub_scores["method_1_uncertainty"] == pytest.approx(1.0, abs=1e-9)

    def test_method1_reacts_to_group_specific_anomaly(self):
        # Push ONLY the `fees` group features far off; leave others normal.
        # Method 1 (group disagreement) should react; the others less so.
        vals = [0.5] * TOTAL_FEATURES
        for i, name in enumerate(_FIELD_NAMES):
            if group_of(name) == "fees":
                vals[i] = 1.5   # z = 10 for every fees feature
        result = AnomalyDetector().score(_features(vals), _baseline())
        # Groups disagree → Method 1 health drops.
        assert result.sub_scores["method_1_uncertainty"] < 1.0


# =============================================================================
# The three methods disagree — that's the ensemble's value
# =============================================================================

class TestMethodsDisagree:

    def test_one_extreme_hits_method2_hardest(self):
        vals = [0.5] * TOTAL_FEATURES
        vals[10] = 2.0   # single extreme feature
        r = AnomalyDetector().score(_features(vals), _baseline())
        m1, m2, m3 = (r.sub_scores["method_1_uncertainty"],
                      r.sub_scores["method_2_mahalanobis"],
                      r.sub_scores["method_3_zscore"])
        # Method 2 (distance) is the most depressed by a single extreme.
        assert m2 <= m1
        assert m2 <= m3

    def test_broad_shift_hits_method3_harder_than_method1(self):
        # Uniform shift: every group equally off.
        vals = [0.8] * TOTAL_FEATURES   # z = 3 everywhere
        r = AnomalyDetector().score(_features(vals), _baseline())
        # Method 1 sees NO disagreement (uniform) → stays high.
        # Method 3 sees every feature improbable → drops.
        assert r.sub_scores["method_3_zscore"] < r.sub_scores["method_1_uncertainty"]


# =============================================================================
# Flags + IMMEDIATE_RED fast-path
# =============================================================================

class TestFlags:

    def test_normal_fixture_no_method_flags(self):
        r = AnomalyDetector().score(_normal(), _baseline())
        assert not (r.flags & FLAG_METHOD_1)
        assert not (r.flags & FLAG_METHOD_2)
        assert not (r.flags & FLAG_METHOD_3)
        assert not r.has_flag(FlagBit.IMMEDIATE_RED)

    def test_extreme_fixture_sets_immediate_red(self):
        # Every feature maximally extreme → at least one method ≈ 0 health.
        vals = [10.0] * TOTAL_FEATURES   # z huge everywhere → clamps to 12
        r = AnomalyDetector().score(_features(vals), _baseline())
        assert r.has_flag(FlagBit.IMMEDIATE_RED)

    def test_provisional_flag_dropped_day8(self):
        # Day 8 completes the 6-component ensemble → PROVISIONAL no longer set.
        r = AnomalyDetector().score(_normal(), _baseline())
        assert not r.has_flag(FlagBit.PROVISIONAL)

    def test_degraded_baseline_flag_propagates(self):
        r = AnomalyDetector().score(_normal(), _baseline(is_provisional=True))
        assert r.has_flag(FlagBit.DEGRADED_BASELINE)


# =============================================================================
# Contract compliance + determinism
# =============================================================================

class TestContract:

    def test_result_is_valid_dimension_result(self):
        r = AnomalyDetector().score(_normal(), _baseline())
        assert isinstance(r, DimensionResult)
        assert r.dimension is DimensionId.ANOMALY
        assert r.max_score == 200
        assert 0 <= r.score <= 200

    def test_algo_version_is_3(self):
        r = AnomalyDetector().score(_normal(), _baseline())
        assert r.algo_version == 3

    def test_all_six_sub_scores_present(self):
        r = AnomalyDetector().score(_normal(), _baseline())
        for key in ("method_1_uncertainty", "method_2_mahalanobis",
                    "method_3_zscore", "method_4_ngram_deviation",
                    "method_5_adversarial", "isoforest_score"):
            assert key in r.sub_scores
            assert 0.0 <= r.sub_scores[key] <= 1.0

    def test_day8_full_budget_is_200(self):
        # Perfectly healthy → full 200-point budget (all 6 components at 1.0).
        r = AnomalyDetector().score(_normal(), _baseline())
        assert r.score == 200

    def test_deterministic(self):
        vals = [0.5] * TOTAL_FEATURES
        vals[7] = 1.2
        f = _features(vals)
        b = _baseline()
        r1 = AnomalyDetector().score(f, b)
        r2 = AnomalyDetector().score(f, b)
        assert r1 == r2

    def test_50_repeated_runs_stable(self):
        f, b = _normal(), _baseline()
        first = AnomalyDetector().score(f, b)
        for _ in range(50):
            assert AnomalyDetector().score(f, b) == first


# =============================================================================
# Registry wiring
# =============================================================================

class TestRegistry:

    def test_default_registry_anomaly_is_real_v3(self):
        det = default_registry().get(DimensionId.ANOMALY)
        assert det.algo_version == 3
        assert isinstance(det, AnomalyDetector)


# =============================================================================
# DAY-8 DONE-WHEN — Methods 4-5 + Isolation Forest
# =============================================================================
#
# "AnomalyDetector.score() returns dim2 0-200; injecting an adversarial
#  transaction pattern trips Isolation Forest within one scoring run."
# =============================================================================

class TestDay8FullEnsemble:

    def test_full_budget_200_on_healthy(self):
        # All 6 components healthy → the full 200-point budget.
        r = AnomalyDetector().score(_normal(), _baseline())
        assert r.score == 200
        assert r.max_score == 200

    def test_all_six_components_score_in_unit_range(self):
        # An extreme fixture — every sub-score still bounded [0, 1].
        vals = [5.0] * TOTAL_FEATURES
        r = AnomalyDetector().score(_features(vals), _baseline())
        for key in ("method_1_uncertainty", "method_2_mahalanobis",
                    "method_3_zscore", "method_4_ngram_deviation",
                    "method_5_adversarial", "isoforest_score"):
            assert 0.0 <= r.sub_scores[key] <= 1.0

    def test_method4_reacts_to_sequence_group_manipulation(self):
        # Push ONLY the `sequence`-group features off (an n-gram pattern change).
        vals = [0.5] * TOTAL_FEATURES
        for i, name in enumerate(_FIELD_NAMES):
            if group_of(name) == "sequence":
                vals[i] = 1.2   # z = 7 on every sequence feature
        r = AnomalyDetector().score(_features(vals), _baseline())
        # Method 4 (n-gram sequence deviation) reacts.
        assert r.sub_scores["method_4_ngram_deviation"] < 0.5
        assert r.flags & FLAG_METHOD_4

    def test_method5_reacts_to_sparse_adversarial_spike(self):
        # A sparse spike — a few features extreme, the rest pristine.
        vals = [0.5] * TOTAL_FEATURES
        vals[10] = 3.0
        vals[40] = 3.0
        vals[70] = 3.0
        r = AnomalyDetector().score(_features(vals), _baseline())
        # Method 5 (kurtosis / spikiness) reacts to the sparse spike.
        assert r.sub_scores["method_5_adversarial"] < 0.9

    def test_isolation_forest_trips_on_adversarial_pattern(self):
        # THE DAY-8 DONE-WHEN: an adversarial transaction pattern — a broad
        # behaviour-class change shifting MANY features at once — trips the
        # Isolation Forest within ONE scoring run.
        vals = [2.5] * TOTAL_FEATURES   # every feature ~20σ off
        r = AnomalyDetector().score(_features(vals), _baseline())
        # IsoForest health collapses → FLAG_ISOFOREST fires.
        assert r.sub_scores["isoforest_score"] < 0.5, \
            f"isoforest health was {r.sub_scores['isoforest_score']}"
        assert r.flags & FLAG_ISOFOREST

    def test_isolation_forest_does_not_trip_on_healthy(self):
        # The complement: a healthy agent must NOT trip the forest.
        r = AnomalyDetector().score(_normal(), _baseline())
        assert r.sub_scores["isoforest_score"] == pytest.approx(1.0, abs=1e-9)
        assert not (r.flags & FLAG_ISOFOREST)

    def test_isoforest_is_deterministic_across_runs(self):
        # The forest's PRNG is seeded from baseline.stats_hash → the whole
        # IsoForest is a pure function. Critical for Phase-4 BFT consensus.
        vals = [2.5] * TOTAL_FEATURES
        f, b = _features(vals), _baseline()
        scores = [
            AnomalyDetector().score(f, b).sub_scores["isoforest_score"]
            for _ in range(10)
        ]
        assert len(set(scores)) == 1, f"non-deterministic isoforest: {set(scores)}"

    def test_isoforest_and_method5_are_complementary(self):
        # IsoForest catches BROAD anomalies; Method 5 catches SPARSE spikes.
        # A broad shift → IsoForest reacts harder than Method 5.
        broad = _features([2.5] * TOTAL_FEATURES)
        rb = AnomalyDetector().score(broad, _baseline())
        assert rb.sub_scores["isoforest_score"] < rb.sub_scores["method_5_adversarial"]
        # A sparse spike → Method 5 reacts harder than IsoForest.
        sparse_vals = [0.5] * TOTAL_FEATURES
        for idx in (5, 25, 55):
            sparse_vals[idx] = 3.0
        rs = AnomalyDetector().score(_features(sparse_vals), _baseline())
        assert rs.sub_scores["method_5_adversarial"] < rs.sub_scores["isoforest_score"]


class TestDay8Flags:

    def test_severe_broad_anomaly_sets_immediate_red(self):
        vals = [9.0] * TOTAL_FEATURES   # maximally extreme everywhere
        r = AnomalyDetector().score(_features(vals), _baseline())
        assert r.has_flag(FlagBit.IMMEDIATE_RED)

    def test_score_drops_monotonically_with_severity(self):
        b = _baseline()
        s_clean  = AnomalyDetector().score(_normal(), b).score
        s_mild   = AnomalyDetector().score(_features([0.7] * TOTAL_FEATURES), b).score
        s_severe = AnomalyDetector().score(_features([3.0] * TOTAL_FEATURES), b).score
        assert s_clean > s_mild > s_severe
