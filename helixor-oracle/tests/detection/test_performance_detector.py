"""
tests/detection/test_performance_detector.py — PerformanceDetector, Day 11.

THE DAY-11 DONE-WHEN
--------------------
"PerformanceDetector.score() returns dim3 0-200; an agent that fakes
 profits without matching Pyth-priced moves scores low."
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone

import pytest

from baseline.types import BASELINE_ALGO_VERSION, BaselineStats
from detection import DimensionId, DimensionResult, FlagBit, default_registry
from detection.performance import (
    FLAG_FADING_DIVERGENCE,
    FLAG_PROFIT_QUALITY_LOW,
    FLAG_ZSCORE_OUTLIER,
    PerformanceDetector,
)
from detection.performance_context import MarketContext, NEUTRAL_MARKET
from features import FEATURE_SCHEMA_VERSION, FeatureVector
from features.vector import TOTAL_FEATURES
from scoring.weights import scoring_schema_fingerprint


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
_FIELD_NAMES = [f.name for f in dataclasses.fields(FeatureVector)]
_IDX = {n: i for i, n in enumerate(_FIELD_NAMES)}


# =============================================================================
# Fixtures
# =============================================================================

def _baseline(*, daily=None, net_mean: float = 0.5,
              net_std: float = 0.1) -> BaselineStats:
    means = [0.5] * TOTAL_FEATURES
    stds = [0.1] * TOTAL_FEATURES
    means[_IDX["solflow_net"]] = net_mean
    stds[_IDX["solflow_net"]] = net_std
    series = tuple(daily if daily is not None else [0.95] * 30)
    return BaselineStats(
        agent_wallet="agentPERF",
        baseline_algo_version=BASELINE_ALGO_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_schema_fingerprint=FeatureVector.feature_schema_fingerprint(),
        scoring_schema_fingerprint=scoring_schema_fingerprint(),
        window_start=REF_END - timedelta(days=30),
        window_end=REF_END,
        feature_means=tuple(means),
        feature_stds=tuple(stds),
        txtype_distribution=(1.0, 0.0, 0.0, 0.0, 0.0),
        action_entropy=0.0,
        success_rate_30d=0.95,
        daily_success_rate_series=series,
        transaction_count=150,
        days_with_activity=len(series),
        is_provisional=False,
        computed_at=REF_END,
        stats_hash="abc" * 21 + "a",
    )


def _features(net: float = 0.5) -> FeatureVector:
    vals = [0.5] * TOTAL_FEATURES
    vals[_IDX["solflow_net"]] = net
    return FeatureVector(**dict(zip(_FIELD_NAMES, vals)))


# =============================================================================
# DONE-WHEN, part 1 — score() returns dim3 in [0, 200]
# =============================================================================

class TestScoreContract:

    def test_returns_dimension_result(self):
        r = PerformanceDetector().score(_features(), _baseline())
        assert isinstance(r, DimensionResult)
        assert r.dimension is DimensionId.PERFORMANCE

    def test_score_in_0_200(self):
        r = PerformanceDetector().score(_features(), _baseline())
        assert r.max_score == 200
        assert 0 <= r.score <= 200

    def test_algo_version_is_2(self):
        r = PerformanceDetector().score(_features(), _baseline())
        assert r.algo_version == 2

    def test_all_three_sub_scores_present(self):
        r = PerformanceDetector().score(_features(), _baseline())
        for key in ("fading_factor_divergence", "profit_quality_score",
                    "zscore_normalised"):
            assert key in r.sub_scores
            assert 0.0 <= r.sub_scores[key] <= 1.0


# =============================================================================
# DONE-WHEN, part 2 — faked profit without matching Pyth moves scores low
# =============================================================================

class TestProfitFraudDetection:

    def test_faked_profit_in_crash_scores_low(self):
        """
        THE DONE-WHEN: an agent claiming profit while the committed Pyth
        market context shows a CRASH scores low on profit quality.
        """
        crash = MarketContext(market_return=-0.15)   # market fell 15%
        detector = PerformanceDetector(crash)
        # The agent claims a strong positive net return.
        result = detector.score(_features(net=0.9), _baseline())
        # Profit-quality collapses — the profit is inconsistent with the market.
        assert result.sub_scores["profit_quality_score"] < 0.35
        assert result.flags & FLAG_PROFIT_QUALITY_LOW

    def test_real_profit_in_up_market_scores_high(self):
        # The honest converse — profit consistent with a rising market.
        up = MarketContext(market_return=0.15)
        detector = PerformanceDetector(up)
        result = detector.score(_features(net=0.9), _baseline())
        assert result.sub_scores["profit_quality_score"] > 0.9
        assert not (result.flags & FLAG_PROFIT_QUALITY_LOW)

    def test_faked_profit_scores_lower_than_real_profit(self):
        # Same claimed return; only the market context differs.
        feats = _features(net=0.9)
        base = _baseline()
        faked = PerformanceDetector(MarketContext(market_return=-0.15)).score(feats, base)
        real  = PerformanceDetector(MarketContext(market_return=0.15)).score(feats, base)
        assert faked.score < real.score

    def test_honest_loss_in_crash_not_penalised_on_quality(self):
        # An agent reporting a LOSS in a crash is honest → quality stays high.
        crash = MarketContext(market_return=-0.15)
        result = PerformanceDetector(crash).score(_features(net=-0.5), _baseline())
        assert result.sub_scores["profit_quality_score"] > 0.9

    def test_neutral_market_no_profit_penalty(self):
        # With no committed market move, profit quality abstains (neutral).
        result = PerformanceDetector(NEUTRAL_MARKET).score(_features(net=0.9), _baseline())
        assert result.sub_scores["profit_quality_score"] == 0.5
        assert not (result.flags & FLAG_PROFIT_QUALITY_LOW)

    def test_short_agent_profit_in_crash_is_legitimate(self):
        # A SHORT agent making money in a crash is consistent — not flagged.
        crash_short = MarketContext(market_return=-0.15, market_exposure=-1.0)
        result = PerformanceDetector(crash_short).score(_features(net=0.9), _baseline())
        assert result.sub_scores["profit_quality_score"] > 0.9

    def test_asset_level_returns_override_broad_market_return(self):
        # Broad market was up, but this agent was exposed to an asset that fell.
        # Claimed profit is therefore low-quality once per-asset attribution is used.
        ctx = MarketContext(
            market_return=0.20,
            asset_returns={"SOL": 0.20, "RUG": -0.15},
            asset_exposures={"RUG": 1.0},
        )
        result = PerformanceDetector(ctx).score(_features(net=0.9), _baseline())
        assert ctx.effective_market_return == pytest.approx(-0.15)
        assert result.sub_scores["profit_quality_score"] < 0.35
        assert result.flags & FLAG_PROFIT_QUALITY_LOW

    def test_asset_level_short_exposure_is_supported(self):
        # Short exposure to a falling asset means profit is market-consistent.
        ctx = MarketContext(
            market_return=0.20,
            asset_returns={"RUG": -0.15},
            asset_exposures={"RUG": -1.0},
        )
        result = PerformanceDetector(ctx).score(_features(net=0.9), _baseline())
        assert ctx.effective_market_return == pytest.approx(0.15)
        assert result.sub_scores["profit_quality_score"] > 0.9


# =============================================================================
# Fading factors
# =============================================================================

class TestFadingFactors:

    def test_stable_agent_high_fading_health(self):
        r = PerformanceDetector().score(_features(), _baseline(daily=[0.95] * 30))
        assert r.sub_scores["fading_factor_divergence"] > 0.8

    def test_recent_collapse_lowers_fading_health(self):
        # 20 good days then 10 bad → fast/slow EMAs diverge.
        r = PerformanceDetector().score(
            _features(), _baseline(daily=[0.95] * 20 + [0.30] * 10),
        )
        assert r.sub_scores["fading_factor_divergence"] < 0.6

    def test_severe_collapse_sets_flag(self):
        r = PerformanceDetector().score(
            _features(), _baseline(daily=[0.98] * 20 + [0.10] * 10),
        )
        assert r.flags & FLAG_FADING_DIVERGENCE


# =============================================================================
# Z-scored returns
# =============================================================================

class TestZScoredReturns:

    def test_return_at_history_mean_full_health(self):
        # Current net return == baseline mean → z=0 → full z-health.
        r = PerformanceDetector().score(_features(net=0.5), _baseline(net_mean=0.5))
        assert r.sub_scores["zscore_normalised"] == 1.0

    def test_return_far_below_history_low_health(self):
        # Net return far below the agent's own historical mean.
        r = PerformanceDetector().score(
            _features(net=-0.5), _baseline(net_mean=0.5, net_std=0.1),
        )
        assert r.sub_scores["zscore_normalised"] < 0.5
        assert r.flags & FLAG_ZSCORE_OUTLIER

    def test_outperforming_own_history_full_health(self):
        # Return ABOVE own mean → z positive → full health (good, not bad).
        r = PerformanceDetector().score(
            _features(net=2.0), _baseline(net_mean=0.5, net_std=0.1),
        )
        assert r.sub_scores["zscore_normalised"] == 1.0


# =============================================================================
# Determinism + registry
# =============================================================================

class TestDeterminismAndRegistry:

    def test_deterministic(self):
        det = PerformanceDetector(MarketContext(market_return=-0.1))
        f, b = _features(net=0.8), _baseline()
        assert det.score(f, b) == det.score(f, b)

    def test_default_registry_performance_is_real_v2(self):
        det = default_registry().get(DimensionId.PERFORMANCE)
        assert det.algo_version == 2
        assert isinstance(det, PerformanceDetector)

    def test_clean_high_performer_scores_well(self):
        # Stable, real profit in an up market, returns above own history.
        up = MarketContext(market_return=0.12)
        r = PerformanceDetector(up).score(
            _features(net=0.9), _baseline(daily=[0.95] * 30),
        )
        assert r.score >= 180
