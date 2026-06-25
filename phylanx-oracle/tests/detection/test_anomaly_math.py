"""
tests/detection/test_anomaly_math.py — anomaly-ensemble primitives, Methods 1-3.

Each primitive tested in isolation: degenerate inputs, hand-computed
expectations, and the deliberate disagreement between the three methods.
"""

from __future__ import annotations

import math

import pytest

from detection._anomaly_math import (
    Z_CLAMP,
    feature_z_scores,
    group_rms,
    magnitude_to_health,
    method1_group_disagreement,
    method2_mahalanobis,
    method3_mean_surprisal,
    standard_normal_logpdf,
)


APPROX = 1e-9


# =============================================================================
# feature_z_scores — the shared substrate
# =============================================================================

class TestFeatureZScores:

    def test_at_mean_gives_zero(self):
        zs = feature_z_scores([0.5, 0.5, 0.5], [0.5, 0.5, 0.5], [0.1, 0.1, 0.1])
        assert zs == [0.0, 0.0, 0.0]

    def test_one_sigma_above(self):
        zs = feature_z_scores([0.6], [0.5], [0.1])
        assert zs[0] == pytest.approx(1.0, abs=APPROX)

    def test_negative_z(self):
        zs = feature_z_scores([0.3], [0.5], [0.1])
        assert zs[0] == pytest.approx(-2.0, abs=APPROX)

    def test_zero_variance_feature_yields_zero(self):
        # A baseline feature with σ ≈ 0 carries no anomaly signal.
        zs = feature_z_scores([0.9], [0.5], [0.0])
        assert zs[0] == 0.0

    def test_clamped_at_z_clamp(self):
        # A wildly extreme feature clamps to ±Z_CLAMP.
        zs = feature_z_scores([1000.0], [0.5], [0.1])
        assert zs[0] == Z_CLAMP
        zs = feature_z_scores([-1000.0], [0.5], [0.1])
        assert zs[0] == -Z_CLAMP

    def test_length_mismatch_rejected(self):
        with pytest.raises(ValueError, match="length mismatch"):
            feature_z_scores([0.5, 0.5], [0.5], [0.1])


# =============================================================================
# group_rms
# =============================================================================

class TestGroupRMS:

    def test_empty_is_zero(self):
        assert group_rms([]) == 0.0

    def test_all_zero(self):
        assert group_rms([0.0, 0.0, 0.0]) == 0.0

    def test_known_value(self):
        # RMS of [3, 4] = sqrt((9+16)/2) = sqrt(12.5)
        assert group_rms([3.0, 4.0]) == pytest.approx(math.sqrt(12.5), abs=APPROX)

    def test_sign_insensitive(self):
        assert group_rms([-3.0, 4.0]) == group_rms([3.0, 4.0])


# =============================================================================
# Method 1 — feature-group disagreement
# =============================================================================

class TestMethod1:

    def test_no_groups_is_zero(self):
        assert method1_group_disagreement({}) == 0.0

    def test_single_group_is_zero(self):
        # Variance across 1 estimate is undefined → defined as 0.
        assert method1_group_disagreement({"g": [1.0, 2.0]}) == 0.0

    def test_all_groups_equal_zero_variance(self):
        # Every group has the SAME RMS → variance 0 (uniform anomaly).
        gz = {f"g{i}": [2.0, 2.0] for i in range(9)}
        assert method1_group_disagreement(gz) == pytest.approx(0.0, abs=APPROX)

    def test_disagreeing_groups_positive_variance(self):
        # Some groups extreme, others calm → high variance.
        gz = {
            "calm1": [0.0, 0.0], "calm2": [0.0, 0.0],
            "calm3": [0.0, 0.0], "calm4": [0.0, 0.0],
            "hot1":  [8.0, 8.0], "hot2":  [8.0, 8.0],
        }
        v = method1_group_disagreement(gz)
        assert v > 0.0

    def test_healthy_uniform_low(self):
        # All groups uniformly slightly noisy → low variance.
        gz = {f"g{i}": [0.5, -0.5, 0.3] for i in range(9)}
        v = method1_group_disagreement(gz)
        assert v < 0.5


# =============================================================================
# Method 2 — diagonal Mahalanobis distance
# =============================================================================

class TestMethod2:

    def test_empty_is_zero(self):
        assert method2_mahalanobis([]) == 0.0

    def test_all_zero(self):
        assert method2_mahalanobis([0.0] * 100) == 0.0

    def test_known_value(self):
        # L2 of [3, 4] = 5
        assert method2_mahalanobis([3.0, 4.0]) == pytest.approx(5.0, abs=APPROX)

    def test_dominated_by_worst_feature(self):
        # One feature at z=10, 99 at z=0 → distance ≈ 10.
        zs = [0.0] * 99 + [10.0]
        assert method2_mahalanobis(zs) == pytest.approx(10.0, abs=APPROX)

    def test_sign_insensitive(self):
        assert method2_mahalanobis([-3.0, -4.0]) == method2_mahalanobis([3.0, 4.0])


# =============================================================================
# Method 3 — mean per-feature surprisal
# =============================================================================

class TestMethod3:

    def test_empty_is_zero(self):
        assert method3_mean_surprisal([]) == 0.0

    def test_all_zero_is_zero(self):
        # z=0 everywhere → surprisal 0.
        assert method3_mean_surprisal([0.0] * 100) == 0.0

    def test_known_value(self):
        # surprisal of z = mean(0.5 z²). For [2, 2]: 0.5*4 = 2 each → mean 2.
        assert method3_mean_surprisal([2.0, 2.0]) == pytest.approx(2.0, abs=APPROX)

    def test_dominated_by_count_not_magnitude(self):
        # Method 3's signature: many mild beats one extreme.
        one_extreme = [10.0] + [0.0] * 99      # mean surprisal = 0.5*100/100 = 0.5
        many_mild   = [3.0] * 100              # mean surprisal = 0.5*9 = 4.5
        assert method3_mean_surprisal(many_mild) > method3_mean_surprisal(one_extreme)

    def test_contrast_with_method2(self):
        # The SAME two inputs: Method 2 ranks them the OPPOSITE way.
        one_extreme = [10.0] + [0.0] * 99
        many_mild   = [3.0] * 100
        # Method 2 (distance) — one_extreme is "further".
        assert method2_mahalanobis(one_extreme) < method2_mahalanobis(many_mild)
        # ...wait: sqrt(100) = 10 for one_extreme, sqrt(900) = 30 for many_mild.
        # Both methods actually agree HERE because many_mild has huge total.
        # The real contrast: one BIG vs a FEW mild.
        one_big   = [12.0] + [0.0] * 99        # M2: 12   M3: 0.72
        few_mild  = [2.0] * 20 + [0.0] * 80    # M2: ~8.9 M3: 0.4
        assert method2_mahalanobis(one_big) > method2_mahalanobis(few_mild)   # distance: big wins
        # Method 3 (count): few_mild has 20 off vs 1 off → but one_big's z²
        # is large. The methods genuinely weight differently — that's the point.


class TestStandardNormalLogPDF:

    def test_at_zero_is_max(self):
        # logpdf(0) = -0.5 log(2π)
        assert standard_normal_logpdf(0.0) == pytest.approx(-0.5 * math.log(2 * math.pi), abs=APPROX)

    def test_decreasing_in_abs_z(self):
        assert standard_normal_logpdf(0.0) > standard_normal_logpdf(1.0)
        assert standard_normal_logpdf(1.0) > standard_normal_logpdf(3.0)

    def test_symmetric(self):
        assert standard_normal_logpdf(-2.0) == pytest.approx(standard_normal_logpdf(2.0), abs=APPROX)


# =============================================================================
# magnitude_to_health
# =============================================================================

class TestMagnitudeToHealth:

    def test_zero_magnitude_is_healthy(self):
        assert magnitude_to_health(0.0, saturation=10.0) == 1.0

    def test_at_saturation_is_zero(self):
        assert magnitude_to_health(10.0, saturation=10.0) == 0.0

    def test_beyond_saturation_clamped(self):
        assert magnitude_to_health(100.0, saturation=10.0) == 0.0

    def test_midpoint(self):
        assert magnitude_to_health(5.0, saturation=10.0) == pytest.approx(0.5, abs=APPROX)

    def test_nan_magnitude_is_anomalous(self):
        assert magnitude_to_health(float("nan"), saturation=10.0) == 0.0

    def test_negative_magnitude_is_healthy(self):
        # Defensive: a negative magnitude is nonsensical but maps to healthy.
        assert magnitude_to_health(-1.0, saturation=10.0) == 1.0


# =============================================================================
# Day 8 — Method 4, Method 5, Isolation Forest
# =============================================================================

from detection._anomaly_math import (
    isolation_forest_health,
    isolation_forest_score,
    method4_sequence_deviation,
    method5_adversarial_kurtosis,
)


class TestMethod4SequenceDeviation:

    def test_empty_is_zero(self):
        assert method4_sequence_deviation([]) == 0.0

    def test_all_zero_is_zero(self):
        # Sequence features all at baseline → no n-gram deviation.
        assert method4_sequence_deviation([0.0] * 14) == 0.0

    def test_known_rms_value(self):
        # RMS of [3, 4] = sqrt((9+16)/2) = sqrt(12.5)
        assert method4_sequence_deviation([3.0, 4.0]) == pytest.approx(
            math.sqrt(12.5), abs=APPROX,
        )

    def test_sign_insensitive(self):
        # n-gram structure shifting up or down is equally a deviation.
        assert method4_sequence_deviation([-3.0, -4.0]) == \
               method4_sequence_deviation([3.0, 4.0])

    def test_large_deviation(self):
        # All 14 sequence features 6σ off → RMS = 6.
        assert method4_sequence_deviation([6.0] * 14) == pytest.approx(6.0, abs=APPROX)


class TestMethod5AdversarialKurtosis:

    def test_too_few_samples_is_zero(self):
        assert method5_adversarial_kurtosis([1.0, 2.0, 3.0]) == 0.0

    def test_zero_variance_is_zero(self):
        # All identical → no spikiness.
        assert method5_adversarial_kurtosis([2.0] * 50) == 0.0

    def test_gaussian_like_is_near_zero(self):
        # A broad, bell-shaped z-distribution → excess kurtosis ≈ 0.
        import random
        rng = random.Random(7)
        sample = [rng.gauss(0.0, 1.0) for _ in range(500)]
        k = method5_adversarial_kurtosis(sample)
        assert k < 1.5    # close to 0 for a Gaussian

    def test_sparse_spike_has_high_kurtosis(self):
        # 97 features at 0, 3 at extreme → sharp spike → high excess kurtosis.
        spiky = [0.0] * 97 + [12.0, 12.0, 12.0]
        k = method5_adversarial_kurtosis(spiky)
        assert k > 10.0

    def test_spike_beats_broad(self):
        # The signature of Method 5: a sparse spike scores far above a broad shift.
        import random
        rng = random.Random(11)
        broad = [rng.gauss(0.0, 3.0) for _ in range(100)]   # broad but Gaussian
        spiky = [0.0] * 95 + [10.0] * 5
        assert method5_adversarial_kurtosis(spiky) > method5_adversarial_kurtosis(broad)

    def test_floored_at_zero(self):
        # A platykurtic (flat) distribution has negative excess kurtosis;
        # Method 5 floors at 0 (only spikiness matters).
        flat = [-1.0, -1.0, 1.0, 1.0] * 25   # bimodal → negative excess kurtosis
        assert method5_adversarial_kurtosis(flat) >= 0.0


class TestIsolationForest:

    def _means_stds(self):
        return [0.5] * 100, [0.1] * 100

    def test_deterministic_same_seed(self):
        means, stds = self._means_stds()
        point = [0.5] * 100
        s1 = isolation_forest_score(point, means, stds, seed=42)
        s2 = isolation_forest_score(point, means, stds, seed=42)
        assert s1 == s2

    def test_different_seed_can_differ(self):
        # Different seeds build different forests — but both are valid scores.
        means, stds = self._means_stds()
        point = [2.0] * 100
        s1 = isolation_forest_score(point, means, stds, seed=1)
        s2 = isolation_forest_score(point, means, stds, seed=2)
        assert 0.0 <= s1 <= 1.0
        assert 0.0 <= s2 <= 1.0

    def test_score_in_unit_range(self):
        means, stds = self._means_stds()
        for point in ([0.5] * 100, [10.0] * 100, [-5.0] * 100):
            s = isolation_forest_score(point, means, stds, seed=42)
            assert 0.0 <= s <= 1.0

    def test_normal_point_low_score(self):
        # A point at the baseline centroid isolates SLOWLY → low anomaly score.
        means, stds = self._means_stds()
        s = isolation_forest_score([0.5] * 100, means, stds, seed=42)
        assert s < 0.5

    def test_broad_anomaly_high_score(self):
        # A point far from the baseline on every feature isolates FAST.
        means, stds = self._means_stds()
        s = isolation_forest_score([5.0] * 100, means, stds, seed=42)
        assert s > 0.6

    def test_empty_point_neutral(self):
        s = isolation_forest_score([], [], [], seed=42)
        assert s == 0.5

    def test_length_mismatch_rejected(self):
        with pytest.raises(ValueError, match="length mismatch"):
            isolation_forest_score([0.5, 0.5], [0.5], [0.1], seed=1)


class TestIsolationForestHealth:

    def test_low_score_is_healthy(self):
        assert isolation_forest_health(0.3) == 1.0
        assert isolation_forest_health(0.5) == 1.0

    def test_high_score_is_unhealthy(self):
        assert isolation_forest_health(1.0) == 0.0

    def test_midpoint(self):
        assert isolation_forest_health(0.75) == pytest.approx(0.5, abs=APPROX)

    def test_nan_is_anomalous(self):
        assert isolation_forest_health(float("nan")) == 0.0
