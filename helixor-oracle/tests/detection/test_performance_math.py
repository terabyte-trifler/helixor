"""
tests/detection/test_performance_math.py — performance-scoring primitives.
"""

from __future__ import annotations

import pytest

from detection._performance_math import (
    FADING_ALPHA_FAST,
    FADING_ALPHA_SLOW,
    exponential_moving_average,
    fading_divergence,
    fading_health,
    profit_quality,
    zscore,
    zscore_health,
)


APPROX = 1e-9


# =============================================================================
# exponential_moving_average
# =============================================================================

class TestEMA:

    def test_empty_series_zero(self):
        assert exponential_moving_average([], 0.1) == 0.0

    def test_single_value(self):
        assert exponential_moving_average([0.7], 0.1) == 0.7

    def test_constant_series_converges_to_constant(self):
        assert exponential_moving_average([0.5] * 50, 0.1) == pytest.approx(0.5, abs=APPROX)

    def test_alpha_one_is_last_value(self):
        # α=1 → EMA tracks the latest value exactly.
        assert exponential_moving_average([0.1, 0.2, 0.9], 1.0) == pytest.approx(0.9)

    def test_known_value(self):
        # series [0, 1], α=0.5: ema0=0, ema1 = 0.5*1 + 0.5*0 = 0.5
        assert exponential_moving_average([0.0, 1.0], 0.5) == pytest.approx(0.5)

    def test_rejects_bad_alpha(self):
        with pytest.raises(ValueError, match="alpha"):
            exponential_moving_average([0.5], 0.0)
        with pytest.raises(ValueError, match="alpha"):
            exponential_moving_average([0.5], 1.5)


# =============================================================================
# fading_divergence
# =============================================================================

class TestFadingDivergence:

    def test_empty_series(self):
        d = fading_divergence([])
        assert d["abs_divergence"] == 0.0

    def test_stable_series_low_divergence(self):
        d = fading_divergence([0.95] * 30)
        assert d["abs_divergence"] < 0.01

    def test_recent_collapse_high_divergence(self):
        # 20 good days then 10 bad — the fast EMA pulls away from the slow.
        d = fading_divergence([0.95] * 20 + [0.30] * 10)
        assert d["abs_divergence"] > 0.1
        # Fast EMA is below the slow EMA after a collapse.
        assert d["fast"] < d["slow"]

    def test_recent_spike_positive_divergence(self):
        d = fading_divergence([0.30] * 20 + [0.95] * 10)
        assert d["divergence"] > 0.0      # recent improvement

    def test_fast_slower_than_slow_label(self):
        # The fast EMA reacts MORE than the slow one to a recent change.
        series = [0.5] * 25 + [1.0] * 5
        d = fading_divergence(series)
        # fast moved further toward 1.0 than slow.
        assert d["fast"] > d["slow"]

    def test_alphas_are_distinct(self):
        assert FADING_ALPHA_FAST > FADING_ALPHA_SLOW


class TestFadingHealth:

    def test_zero_divergence_is_healthy(self):
        assert fading_health(0.0, saturation=0.3) == 1.0

    def test_saturation_is_zero_health(self):
        assert fading_health(0.3, saturation=0.3) == 0.0

    def test_midpoint(self):
        assert fading_health(0.15, saturation=0.3) == pytest.approx(0.5)

    def test_beyond_saturation_clamped(self):
        assert fading_health(99.0, saturation=0.3) == 0.0


# =============================================================================
# profit_quality — the fraud-resistant core
# =============================================================================

class TestProfitQuality:

    def test_profit_in_up_market_high_quality(self):
        # Long agent, profit, rising market → consistent → high.
        q = profit_quality(claimed_return=1.0, market_return=0.10)
        assert q > 0.9

    def test_profit_in_crash_market_low_quality(self):
        # Long agent claiming profit while the market CRASHED → suspicious.
        q = profit_quality(claimed_return=1.0, market_return=-0.10)
        assert q < 0.1

    def test_loss_in_crash_market_high_quality(self):
        # Honest loss reporting in a down market → consistent → high.
        q = profit_quality(claimed_return=-1.0, market_return=-0.10)
        assert q > 0.9

    def test_flat_market_is_neutral(self):
        # No market move → no evidence → neutral 0.5.
        q = profit_quality(claimed_return=1.0, market_return=0.0)
        assert q == 0.5

    def test_short_agent_profit_in_crash_high_quality(self):
        # A SHORT agent (exposure -1) making money in a crash IS consistent.
        q = profit_quality(claimed_return=1.0, market_return=-0.10,
                            market_exposure=-1.0)
        assert q > 0.9

    def test_stronger_adverse_move_lower_quality(self):
        # A bigger adverse market move makes a claimed profit MORE suspicious.
        mild   = profit_quality(claimed_return=1.0, market_return=-0.02)
        severe = profit_quality(claimed_return=1.0, market_return=-0.20)
        assert severe < mild

    def test_zero_claimed_return_is_neutral(self):
        q = profit_quality(claimed_return=0.0, market_return=0.10)
        assert q == 0.5

    def test_nan_handled(self):
        assert profit_quality(claimed_return=float("nan"), market_return=0.1) == 0.0


# =============================================================================
# zscore + zscore_health
# =============================================================================

class TestZScore:

    def test_at_mean_is_zero(self):
        assert zscore(0.5, 0.5, 0.1) == 0.0

    def test_one_sigma(self):
        assert zscore(0.6, 0.5, 0.1) == pytest.approx(1.0)

    def test_zero_std_guard(self):
        assert zscore(0.9, 0.5, 0.0) == 0.0

    def test_clamped(self):
        assert zscore(1000.0, 0.5, 0.1) == 12.0
        assert zscore(-1000.0, 0.5, 0.1) == -12.0


class TestZScoreHealth:

    def test_positive_z_is_healthy(self):
        # Outperforming own history → full health.
        assert zscore_health(2.0) == 1.0
        assert zscore_health(0.0) == 1.0

    def test_negative_z_lowers_health(self):
        assert zscore_health(-3.0) < 1.0

    def test_saturation(self):
        assert zscore_health(-6.0, saturation=6.0) == 0.0

    def test_midpoint(self):
        assert zscore_health(-3.0, saturation=6.0) == pytest.approx(0.5)
