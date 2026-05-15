"""
tests/detection/test_drift_math.py — pure-stdlib PSI + KS primitives.

These primitives feed every downstream drift test. Each is tested in
isolation against hand-computed expectations and known statistical tables.
"""

from __future__ import annotations

import math

import pytest

from detection._drift_math import (
    PSI_EPSILON,
    bonferroni_alpha,
    ks_one_sample_normal,
    population_stability_index,
    psi_normalised_score,
    standard_normal_cdf,
)


APPROX = 1e-9


# =============================================================================
# PSI
# =============================================================================

class TestPSI:

    def test_identical_distributions_gives_zero(self):
        d = (0.2, 0.2, 0.2, 0.2, 0.2)
        psi = population_stability_index(d, d)
        assert psi == pytest.approx(0.0, abs=1e-12)

    def test_psi_is_symmetric(self):
        # PSI is mathematically symmetric: PSI(a, b) == PSI(b, a).
        a = (0.5, 0.3, 0.2)
        b = (0.2, 0.5, 0.3)
        assert population_stability_index(a, b) == pytest.approx(
            population_stability_index(b, a), abs=1e-12,
        )

    def test_known_value_two_buckets(self):
        # Hand-computed: cur=(0.6,0.4), base=(0.5,0.5), no smoothing matters
        # since no bucket is zero.
        # PSI = (0.6-0.5)*ln(0.6/0.5) + (0.4-0.5)*ln(0.4/0.5)
        #     = 0.1*ln(1.2) + (-0.1)*ln(0.8)
        #     = 0.1*0.18232... + (-0.1)*(-0.22314...)
        #     = 0.018232 + 0.022314 = 0.040546
        cur  = (0.6, 0.4)
        base = (0.5, 0.5)
        psi = population_stability_index(cur, base, epsilon=1e-9)  # ε tiny to match raw math
        expected = 0.1 * math.log(1.2) + (-0.1) * math.log(0.8)
        assert psi == pytest.approx(expected, abs=1e-6)

    def test_major_shift_exceeds_threshold(self):
        # 5-category tx-type: from "all swap" to "all lend" — a complete shift.
        cur  = (0.0, 1.0, 0.0, 0.0, 0.0)
        base = (1.0, 0.0, 0.0, 0.0, 0.0)
        psi = population_stability_index(cur, base)
        assert psi > 0.25   # major shift

    def test_zero_baseline_bucket_no_log_zero(self):
        # cur has mass in a bucket where baseline has zero — ε must save us.
        cur  = (0.0, 0.5, 0.5)
        base = (0.0, 1.0, 0.0)
        psi = population_stability_index(cur, base)
        assert math.isfinite(psi)
        assert psi > 0.0     # there IS drift

    def test_psi_non_negative(self):
        # PSI is a divergence — always >= 0.
        import random
        rng = random.Random(7)
        for _ in range(20):
            cur  = [rng.random() for _ in range(5)]
            base = [rng.random() for _ in range(5)]
            psi = population_stability_index(
                [c / sum(cur) for c in cur],
                [b / sum(base) for b in base],
            )
            assert psi >= 0.0

    def test_length_mismatch_rejected(self):
        with pytest.raises(ValueError, match="bucket count"):
            population_stability_index((0.5, 0.5), (0.33, 0.33, 0.34))

    def test_empty_inputs_rejected(self):
        with pytest.raises(ValueError, match="non-empty"):
            population_stability_index([], [])


class TestPsiNormalisedScore:

    def test_zero_psi_is_perfect(self):
        assert psi_normalised_score(0.0) == 1.0

    def test_at_threshold_is_zero(self):
        assert psi_normalised_score(0.25) == 0.0

    def test_beyond_threshold_clamped_zero(self):
        assert psi_normalised_score(1.0) == 0.0

    def test_midpoint_is_half(self):
        # PSI = 0.125 → halfway between 0 and 0.25 → score 0.5
        assert psi_normalised_score(0.125) == pytest.approx(0.5, abs=APPROX)

    def test_nan_psi_returns_neutral(self):
        assert psi_normalised_score(float("nan")) == 0.5


# =============================================================================
# Standard normal CDF
# =============================================================================

class TestStandardNormalCDF:

    def test_at_zero_is_half(self):
        assert standard_normal_cdf(0.0) == pytest.approx(0.5, abs=1e-12)

    def test_one_sigma_known_value(self):
        # Φ(1) ≈ 0.8413447
        assert standard_normal_cdf(1.0) == pytest.approx(0.8413447, abs=1e-6)

    def test_negative_symmetry(self):
        assert standard_normal_cdf(-1.0) == pytest.approx(
            1.0 - standard_normal_cdf(1.0), abs=1e-12,
        )

    def test_extreme_values(self):
        assert standard_normal_cdf(-10.0) == pytest.approx(0.0, abs=1e-15)
        assert standard_normal_cdf(10.0) == pytest.approx(1.0, abs=1e-15)


# =============================================================================
# KS one-sample against N(0, 1)
# =============================================================================

class TestKSOneSampleNormal:

    def test_empty_returns_max_p_value(self):
        d, p = ks_one_sample_normal([])
        assert d == 0.0
        assert p == 1.0

    def test_perfect_normal_sample_has_low_d(self):
        # Symmetric draw from N(0, 1) at integer percentiles → small D.
        # Pre-computed: 11 values at z = -2, -1.5, -1, -0.5, 0, 0.5, 1, 1.5, 2
        # produces a small D for the empirical CDF vs Φ.
        sample = [-2.0, -1.5, -1.0, -0.5, 0.0, 0.5, 1.0, 1.5, 2.0]
        d, p = ks_one_sample_normal(sample)
        assert d < 0.20       # small D
        assert p > 0.5        # cannot reject H0

    def test_clearly_non_normal_sample_rejects(self):
        # All values clustered at +3 — definitely not N(0, 1).
        sample = [3.0] * 20
        d, p = ks_one_sample_normal(sample)
        assert d > 0.5
        assert p < 0.001      # reject at almost any α

    def test_d_is_in_unit_range(self):
        # KS D statistic is bounded in [0, 1].
        for sample in (
            [0.0],
            [-5.0, 0.0, 5.0],
            [100.0, -100.0],
            [0.1, -0.1, 0.0, 0.05],
        ):
            d, p = ks_one_sample_normal(sample)
            assert 0.0 <= d <= 1.0
            assert 0.0 <= p <= 1.0

    def test_deterministic(self):
        # Same input → same output. Phase-4 BFT contract.
        sample = [0.1, -0.2, 1.5, -1.4, 0.05, 0.3]
        a = ks_one_sample_normal(sample)
        b = ks_one_sample_normal(sample)
        assert a == b

    def test_input_order_irrelevant(self):
        # KS sorts internally; passing the same multiset shuffled must give
        # the SAME (D, p).
        import random
        sample = [0.1, -0.2, 1.5, -1.4, 0.05, 0.3, -0.7, 0.8]
        rng = random.Random(11)
        canonical = ks_one_sample_normal(sample)
        for _ in range(5):
            s2 = sample[:]
            rng.shuffle(s2)
            assert ks_one_sample_normal(s2) == canonical


# =============================================================================
# Bonferroni
# =============================================================================

class TestBonferroni:

    def test_divides_alpha(self):
        assert bonferroni_alpha(0.05, 10) == pytest.approx(0.005, abs=APPROX)

    def test_100_tests(self):
        assert bonferroni_alpha(0.05, 100) == pytest.approx(5e-4, abs=1e-12)

    def test_n_one_unchanged(self):
        assert bonferroni_alpha(0.05, 1) == pytest.approx(0.05, abs=APPROX)

    def test_invalid_n_rejected(self):
        with pytest.raises(ValueError, match="n_tests"):
            bonferroni_alpha(0.05, 0)

    def test_invalid_alpha_rejected(self):
        with pytest.raises(ValueError, match="alpha"):
            bonferroni_alpha(0.0, 10)
        with pytest.raises(ValueError, match="alpha"):
            bonferroni_alpha(1.0, 10)


# =============================================================================
# CUSUM — Page's two-sided cumulative-sum change-point
# =============================================================================

from detection._drift_math import (
    CUSUM_MIN_SIGMA,
    adwin_detect,
    adwin_normalised_score,
    cusum_normalised_score,
    cusum_two_sided,
    ddm_detect,
    ddm_normalised_score,
)


class TestCUSUM:

    def test_empty_stream_no_trigger(self):
        r = cusum_two_sided([], reference_mean=0.5, sigma=0.1)
        assert r["triggered"] is False
        assert r["trigger_idx"] == -1
        assert r["pos_max"] == 0.0
        assert r["neg_max"] == 0.0

    def test_constant_stream_at_reference_no_trigger(self):
        r = cusum_two_sided([0.95]*30, reference_mean=0.95, sigma=0.05)
        assert not r["triggered"]
        assert r["pos_max"] == 0.0
        assert r["neg_max"] == 0.0
        assert cusum_normalised_score(r) == 1.0

    def test_abrupt_drop_below_reference_triggers_negative(self):
        # First 20 obs at the reference, then 20 at a lower level.
        stream = [0.95]*20 + [0.50]*20
        r = cusum_two_sided(stream, reference_mean=0.95, sigma=0.05)
        assert r["triggered"]
        assert r["neg_max"] > r["pos_max"]      # downward shift dominates
        assert r["trigger_idx"] >= 20           # trigger only AFTER the shift
        assert cusum_normalised_score(r) < 0.2

    def test_abrupt_rise_above_reference_triggers_positive(self):
        # Start below reference, then jump above.
        stream = [0.50]*20 + [0.95]*20
        r = cusum_two_sided(stream, reference_mean=0.50, sigma=0.05)
        assert r["triggered"]
        assert r["pos_max"] > r["neg_max"]
        assert r["trigger_idx"] >= 20

    def test_min_sigma_floor_protects_zero_variance_baseline(self):
        # σ = 0 in input → engine uses CUSUM_MIN_SIGMA floor.
        r = cusum_two_sided([0.95]*30, reference_mean=0.95, sigma=0.0)
        assert r["h"] == pytest.approx(5.0 * CUSUM_MIN_SIGMA)
        # Still no trigger on constant stream.
        assert not r["triggered"]

    def test_deterministic(self):
        a = cusum_two_sided([0.95, 0.50, 0.95, 0.60], reference_mean=0.8, sigma=0.1)
        b = cusum_two_sided([0.95, 0.50, 0.95, 0.60], reference_mean=0.8, sigma=0.1)
        assert a == b

    def test_normalised_score_bounds(self):
        # Triggered → score 0; clean → score 1.
        triggered = cusum_two_sided([0.0]*30, reference_mean=1.0, sigma=0.05)
        clean     = cusum_two_sided([0.95]*30, reference_mean=0.95, sigma=0.05)
        assert cusum_normalised_score(triggered) == 0.0
        assert cusum_normalised_score(clean) == 1.0


# =============================================================================
# ADWIN — adaptive windowing
# =============================================================================

class TestADWIN:

    def test_empty_stream(self):
        r = adwin_detect([])
        assert r["cuts"] == 0
        assert not r["drifted"]
        assert r["width_loss_ratio"] == 0.0

    def test_single_observation_no_cut(self):
        r = adwin_detect([0.5])
        assert r["cuts"] == 0
        assert not r["drifted"]

    def test_constant_stream_no_cut(self):
        r = adwin_detect([0.95]*40)
        assert r["cuts"] == 0
        assert not r["drifted"]
        assert r["width_loss_ratio"] == 0.0
        assert adwin_normalised_score(r) == 1.0

    def test_abrupt_change_triggers_cut(self):
        # Long stable run then sudden drop — ADWIN should drop the old window.
        stream = [0.95]*30 + [0.30]*30
        r = adwin_detect(stream)
        assert r["drifted"]
        assert r["cuts"] >= 1
        # The window should shrink — width loss > 0.
        assert r["width_loss_ratio"] > 0.0
        assert adwin_normalised_score(r) < 1.0

    def test_deterministic(self):
        stream = [0.95]*20 + [0.30]*20
        assert adwin_detect(stream) == adwin_detect(stream)

    def test_normalised_score_bounds(self):
        # All-zero width loss → 1.0; full loss → 0.0.
        zero   = {"window_size_final": 10, "window_size_initial": 10,
                  "cuts": 0, "drifted": False, "last_cut_idx": -1,
                  "width_loss_ratio": 0.0}
        full   = {"window_size_final": 0, "window_size_initial": 10,
                  "cuts": 1, "drifted": True, "last_cut_idx": 5,
                  "width_loss_ratio": 1.0}
        assert adwin_normalised_score(zero) == 1.0
        assert adwin_normalised_score(full) == 0.0


# =============================================================================
# DDM — drift detection method (Gama 2004)
# =============================================================================

class TestDDM:

    def test_too_few_samples_no_drift(self):
        # min_n default is 30; 10 samples → not enough to trip
        r = ddm_detect([0.5]*10)
        assert not r["drift"]
        assert not r["warning"]
        assert r["warning_ratio"] == 0.0

    def test_stable_low_error_rate(self):
        # 30 samples at 5% error rate, the rate stays put → no drift.
        r = ddm_detect([0.05]*30)
        assert not r["drift"]
        assert r["warning_ratio"] == 0.0
        assert ddm_normalised_score(r) == 1.0

    def test_abrupt_error_rate_climb_triggers_drift(self):
        # First 30 samples at 5%, then 30 at 80% — DDM must catch this.
        r = ddm_detect([0.05]*30 + [0.80]*30)
        assert r["drift"]
        assert r["warning"]
        assert r["warning_ratio"] > 1.0      # well past drift threshold
        assert ddm_normalised_score(r) == 0.0

    def test_gradual_climb_caught(self):
        # Gradual climb from 5% to 60% — DDM's bread-and-butter case.
        stream = [0.05 + i * 0.018 for i in range(40)]
        r = ddm_detect(stream)
        assert r["drift"] or r["warning"]
        assert ddm_normalised_score(r) < 1.0

    def test_deterministic(self):
        s = [0.05]*30 + [0.50]*20
        assert ddm_detect(s) == ddm_detect(s)

    def test_normalised_score_bounds(self):
        clean   = {"warning": False, "drift": False, "warning_idx": -1,
                   "drift_idx": -1, "warning_ratio": 0.0}
        drifted = {"warning": True, "drift": True, "warning_idx": 10,
                   "drift_idx": 12, "warning_ratio": 5.0}
        assert ddm_normalised_score(clean) == 1.0
        assert ddm_normalised_score(drifted) == 0.0
