"""
detection/performance.py — Dimension 3: performance scoring.

STATUS: Day 11 — COMPLETE.

THREE COMPONENTS
----------------
1. Dual fading factors — a fast EMA (α=0.10) and a slow EMA (α=0.01) over
   the agent's daily success-rate series. Their divergence measures how far
   recent performance has shifted from the long-run baseline.

2. Profit Quality — the agent's claimed net return cross-referenced against
   the committed market move (Pyth snapshot). Profit consistent with price
   action scores high; profit booked while the market moved against the
   agent scores low. This is the fraud-resistant core: hard to game without
   genuinely performing.

3. Z-scored returns — the agent's current return normalised against the
   mean / std of its own historical returns. Directional: returns far
   BELOW the agent's norm are a performance problem; above is not.

SCORE LAYOUT — 200-point dimension
----------------------------------
   Profit Quality      0..90    (the fraud-resistant core — largest share)
   Z-scored returns    0..60
   Fading divergence   0..50
                       -----
                        200

A STATEFUL DETECTOR
-------------------
Like the Day-10 SecurityDetector, this detector needs context beyond
(features, baseline): the committed Pyth `MarketContext`. It is
constructed with one; `default_registry()` builds it with NEUTRAL_MARKET.
Keeps the Day-4 Detector Protocol intact.
"""

from __future__ import annotations

import dataclasses as _dc
from collections.abc import Mapping

from baseline import BaselineStats
from detection._performance_math import (
    fading_divergence,
    fading_health,
    profit_quality,
    zscore,
    zscore_health,
)
from detection.base import Detector, assert_baseline_compatible
from detection.performance_context import NEUTRAL_MARKET, MarketContext
from detection.types import DimensionId, DimensionResult, FlagBit
from features import FeatureVector


# ── Dimension-specific flag bits — Performance owns bits 13-15 ───────────────
# (Drift: 8-12, Anomaly: 16-21, Security: 24-29 — see detection/types.py.)
FLAG_FADING_DIVERGENCE  = 1 << 13    # fast/slow EMA diverged sharply
FLAG_PROFIT_QUALITY_LOW = 1 << 14    # claimed profit inconsistent with the market
FLAG_ZSCORE_OUTLIER     = 1 << 15    # returns far below the agent's own history


SUB_SCORE_KEYS: tuple[str, ...] = (
    "fading_factor_divergence",   # [0,1]; 1.0 = recent == long-run
    "profit_quality_score",       # [0,1]; 1.0 = profit consistent with market
    "zscore_normalised",          # [0,1]; 1.0 = returns at/above own norm
)


# ── Point budget — 90 + 60 + 50 = 200 ────────────────────────────────────────
PROFIT_QUALITY_MAX_POINTS = 90
ZSCORE_MAX_POINTS         = 60
FADING_MAX_POINTS         = 50

# Fading-divergence saturation: a fast/slow EMA gap this large on the
# success-rate series (a [0,1] quantity) is a maximal recent shift.
FADING_SATURATION = 0.30

# A component health below this sets its FLAG_*.
COMPONENT_FLAG_FLOOR = 0.5
# Profit quality this low is an explicit "claimed profit contradicts the market".
PROFIT_QUALITY_FLAG_FLOOR = 0.35
# A return z-score below this (negative) sets FLAG_ZSCORE_OUTLIER.
ZSCORE_OUTLIER_FLOOR = -3.0

# Feature indices, resolved once from the canonical field order.
_FIELD_NAMES = [f.name for f in _dc.fields(FeatureVector)]
_IDX = {name: i for i, name in enumerate(_FIELD_NAMES)}
_NET_RETURN_FEATURE = "solflow_net"


# =============================================================================
# PerformanceDetector — Day 11
# =============================================================================

class PerformanceDetector:
    """
    Dimension 3. A stateful detector: constructed with a committed
    `MarketContext` (Pyth snapshot), then scoring agents against it.

    Pure + deterministic given (features, baseline, market context).
    """

    def __init__(self, market: MarketContext = NEUTRAL_MARKET) -> None:
        self._market = market

    @property
    def dimension(self) -> DimensionId:
        return DimensionId.PERFORMANCE

    @property
    def algo_version(self) -> int:
        # Day-4 stub = 1. Day-11 real implementation = 2.
        return 2

    @property
    def market(self) -> MarketContext:
        return self._market

    def score(
        self,
        features: FeatureVector,
        baseline: BaselineStats,
    ) -> DimensionResult:
        assert_baseline_compatible(baseline)

        flags = 0
        if baseline.is_provisional:
            flags |= int(FlagBit.DEGRADED_BASELINE)

        feature_values = features.to_list()

        # ── 1. Dual fading factors over the daily success-rate series ───────
        series = baseline.daily_success_rate_series
        if len(series) >= 2:
            fdiv = fading_divergence(series)
            fading_h = fading_health(fdiv["abs_divergence"], saturation=FADING_SATURATION)
        else:
            # Too short a series to compute a meaningful EMA divergence.
            fdiv = {"abs_divergence": 0.0}
            fading_h = 1.0
            flags |= int(FlagBit.DEGRADED_BASELINE)
        if fading_h < COMPONENT_FLAG_FLOOR:
            flags |= FLAG_FADING_DIVERGENCE

        # ── 2. Profit Quality — claimed return vs the committed market ──────
        claimed_return = feature_values[_IDX[_NET_RETURN_FEATURE]]
        profit_h = profit_quality(
            claimed_return=claimed_return,
            market_return=self._market.effective_market_return,
            market_exposure=self._market.market_exposure,
        )
        if profit_h < PROFIT_QUALITY_FLAG_FLOOR:
            flags |= FLAG_PROFIT_QUALITY_LOW

        # ── 3. Z-scored returns against the agent's own history ─────────────
        ret_idx = _IDX[_NET_RETURN_FEATURE]
        ret_z = zscore(
            claimed_return,
            baseline.feature_means[ret_idx],
            baseline.feature_stds[ret_idx],
        )
        zscore_h = zscore_health(ret_z)
        if ret_z <= ZSCORE_OUTLIER_FLOOR:
            flags |= FLAG_ZSCORE_OUTLIER

        # ── 4. Aggregate into the 0..200 score ──────────────────────────────
        score_total = int(round(
            profit_h * PROFIT_QUALITY_MAX_POINTS +
            zscore_h * ZSCORE_MAX_POINTS         +
            fading_h * FADING_MAX_POINTS
        ))
        score_total = max(0, min(score_total, 200))

        sub_scores: Mapping[str, float] = {
            "fading_factor_divergence": fading_h,
            "profit_quality_score":     profit_h,
            "zscore_normalised":        zscore_h,
        }

        return DimensionResult(
            dimension=DimensionId.PERFORMANCE,
            score=score_total,
            max_score=200,
            flags=flags,
            sub_scores=sub_scores,
            algo_version=self.algo_version,
        )


# Static check: the real detector conforms to the Detector Protocol.
_: Detector = PerformanceDetector()
