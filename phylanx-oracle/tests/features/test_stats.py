"""
tests/features/test_stats.py — the _stats primitives.

These functions are the foundation of the "no NaN" guarantee. Every one is
tested against its degenerate inputs (empty, single, zero-variance) plus a
known-value case.
"""

from __future__ import annotations

import math

import pytest

from features import _stats as st

APPROX = 1e-9


class TestSafeDiv:
    def test_normal(self):
        assert st.safe_div(10.0, 2.0) == pytest.approx(5.0, abs=APPROX)
    def test_zero_denominator_returns_default(self):
        assert st.safe_div(10.0, 0.0) == 0.0
        assert st.safe_div(10.0, 0.0, default=-1.0) == -1.0
    def test_result_always_finite(self):
        assert math.isfinite(st.safe_div(1e308, 1e-308))


class TestMean:
    def test_known(self):
        assert st.mean([1.0, 2.0, 3.0]) == pytest.approx(2.0, abs=APPROX)
    def test_empty_is_zero(self):
        assert st.mean([]) == 0.0
    def test_single(self):
        assert st.mean([7.0]) == 7.0


class TestStddev:
    def test_known_population(self):
        # values 2,4,4,4,5,5,7,9 → population stddev = 2.0
        assert st.stddev([2,4,4,4,5,5,7,9]) == pytest.approx(2.0, abs=1e-9)
    def test_empty_is_zero(self):
        assert st.stddev([]) == 0.0
    def test_single_is_zero(self):
        assert st.stddev([5.0]) == 0.0
    def test_identical_is_zero(self):
        assert st.stddev([3.0, 3.0, 3.0, 3.0]) == 0.0
    def test_sample_needs_two(self):
        assert st.stddev([5.0], population=False) == 0.0


class TestCoefficientOfVariation:
    def test_known(self):
        # mean 10, stddev 2 → cv 0.2  (values: 8,10,12 → pop stddev = 1.632...)
        # use a cleaner set: 10,10,10 → cv 0
        assert st.coefficient_of_variation([10.0, 10.0, 10.0]) == 0.0
    def test_zero_mean_is_zero(self):
        assert st.coefficient_of_variation([-1.0, 0.0, 1.0]) == 0.0
    def test_empty_is_zero(self):
        assert st.coefficient_of_variation([]) == 0.0


class TestMedian:
    def test_odd(self):
        assert st.median([3.0, 1.0, 2.0]) == 2.0
    def test_even(self):
        assert st.median([1.0, 2.0, 3.0, 4.0]) == 2.5
    def test_empty_is_zero(self):
        assert st.median([]) == 0.0
    def test_single(self):
        assert st.median([9.0]) == 9.0


class TestPercentile:
    def test_p50_is_median_ish(self):
        assert st.percentile([1.0, 2.0, 3.0, 4.0, 5.0], 50) == pytest.approx(3.0, abs=APPROX)
    def test_p0_is_min(self):
        assert st.percentile([5.0, 1.0, 3.0], 0) == 1.0
    def test_p100_is_max(self):
        assert st.percentile([5.0, 1.0, 3.0], 100) == 5.0
    def test_empty_is_zero(self):
        assert st.percentile([], 90) == 0.0
    def test_single(self):
        assert st.percentile([7.0], 90) == 7.0
    def test_interpolation(self):
        # p25 of [1,2,3,4] → rank = 0.25*3 = 0.75 → 1*0.25 + 2*0.75 = 1.75
        assert st.percentile([1.0, 2.0, 3.0, 4.0], 25) == pytest.approx(1.75, abs=APPROX)


class TestMAD:
    def test_known(self):
        # values 1,2,3,4,5 → median 3 → deviations 2,1,0,1,2 → MAD = median = 1
        assert st.median_absolute_deviation([1.0, 2.0, 3.0, 4.0, 5.0]) == pytest.approx(1.0, abs=APPROX)
    def test_empty_is_zero(self):
        assert st.median_absolute_deviation([]) == 0.0
    def test_single_is_zero(self):
        assert st.median_absolute_deviation([4.0]) == 0.0
    def test_identical_is_zero(self):
        assert st.median_absolute_deviation([2.0, 2.0, 2.0]) == 0.0


class TestShannonEntropy:
    def test_uniform_normalised_is_one(self):
        # 4 equal categories → max entropy → normalised 1.0
        assert st.shannon_entropy([1.0, 1.0, 1.0, 1.0], normalised=True) == pytest.approx(1.0, abs=1e-9)
    def test_single_category_is_zero(self):
        assert st.shannon_entropy([5.0], normalised=True) == 0.0
        assert st.shannon_entropy([5.0, 0.0, 0.0], normalised=True) == 0.0
    def test_empty_is_zero(self):
        assert st.shannon_entropy([], normalised=True) == 0.0
    def test_all_zero_is_zero(self):
        assert st.shannon_entropy([0.0, 0.0, 0.0]) == 0.0
    def test_unnormalised_two_equal_is_one_bit(self):
        # 2 equal categories → 1 bit of entropy
        assert st.shannon_entropy([1.0, 1.0], normalised=False) == pytest.approx(1.0, abs=1e-9)
    def test_result_in_unit_range_when_normalised(self):
        h = st.shannon_entropy([3.0, 1.0, 1.0, 5.0, 2.0], normalised=True)
        assert 0.0 <= h <= 1.0


class TestHerfindahl:
    def test_full_concentration(self):
        assert st.herfindahl_index([10.0]) == pytest.approx(1.0, abs=APPROX)
        assert st.herfindahl_index([10.0, 0.0, 0.0]) == pytest.approx(1.0, abs=APPROX)
    def test_even_split(self):
        # 4 equal → HHI = 4 * (0.25^2) = 0.25
        assert st.herfindahl_index([1.0, 1.0, 1.0, 1.0]) == pytest.approx(0.25, abs=APPROX)
    def test_empty_is_zero(self):
        assert st.herfindahl_index([]) == 0.0


class TestTopKConcentration:
    def test_top1(self):
        # counts 5,3,2 total 10 → top1 = 0.5
        assert st.top_k_concentration([5.0, 3.0, 2.0], 1) == pytest.approx(0.5, abs=APPROX)
    def test_top2(self):
        assert st.top_k_concentration([5.0, 3.0, 2.0], 2) == pytest.approx(0.8, abs=APPROX)
    def test_k_exceeds_categories(self):
        assert st.top_k_concentration([5.0, 3.0], 10) == pytest.approx(1.0, abs=APPROX)
    def test_empty_is_zero(self):
        assert st.top_k_concentration([], 3) == 0.0


class TestLinearSlope:
    def test_increasing(self):
        # 0,1,2,3,4 → slope 1.0
        assert st.linear_slope([0.0, 1.0, 2.0, 3.0, 4.0]) == pytest.approx(1.0, abs=APPROX)
    def test_decreasing(self):
        assert st.linear_slope([4.0, 3.0, 2.0, 1.0, 0.0]) == pytest.approx(-1.0, abs=APPROX)
    def test_flat(self):
        assert st.linear_slope([2.0, 2.0, 2.0]) == pytest.approx(0.0, abs=APPROX)
    def test_empty_is_zero(self):
        assert st.linear_slope([]) == 0.0
    def test_single_is_zero(self):
        assert st.linear_slope([5.0]) == 0.0


class TestBurstiness:
    def test_periodic_is_negative_one(self):
        # perfectly even gaps → stddev 0 → (0-mu)/(0+mu) = -1
        assert st.burstiness([10.0, 10.0, 10.0]) == pytest.approx(-1.0, abs=APPROX)
    def test_empty_is_zero(self):
        assert st.burstiness([]) == 0.0
    def test_single_is_zero(self):
        assert st.burstiness([5.0]) == 0.0
    def test_in_range(self):
        b = st.burstiness([1.0, 100.0, 2.0, 50.0, 1.0])
        assert -1.0 <= b <= 1.0


class TestClampAndFraction:
    def test_clamp(self):
        assert st.clamp(5.0, 0.0, 10.0) == 5.0
        assert st.clamp(-3.0, 0.0, 10.0) == 0.0
        assert st.clamp(99.0, 0.0, 10.0) == 10.0
    def test_clamp_nonfinite_returns_lo(self):
        assert st.clamp(float("nan"), 0.0, 10.0) == 0.0
        assert st.clamp(float("inf"), 1.0, 10.0) == 1.0
    def test_fraction_in_unit_range(self):
        assert st.fraction(3.0, 4.0) == pytest.approx(0.75, abs=APPROX)
        assert st.fraction(10.0, 4.0) == 1.0     # clamped
        assert st.fraction(5.0, 0.0) == 0.0      # zero denom
