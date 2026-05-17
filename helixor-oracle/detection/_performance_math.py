"""
detection/_performance_math.py — performance-scoring primitives, pure stdlib.

Three families of primitive, all deterministic (Phase-4 BFT rule — no
numpy, no scipy):

  DUAL FADING FACTORS — a fast EMA (α=0.10) and a slow EMA (α=0.01) over a
  performance time series. The fast EMA tracks recent behaviour; the slow
  EMA tracks the long-run level. Their DIVERGENCE is a recent-shift signal:
  the agent's performance has moved away from its own long-run baseline.

  PROFIT QUALITY — correlates an agent's claimed profit direction against
  the market move over the same window. Genuine trading profit lines up
  with favourable price action; profit booked while the market moved
  AGAINST the agent's exposure is low-quality (un-earned — likely faked).
  This is the fraud-resistant core: to score well an agent must show
  profit that matches real price action, which requires actually trading.

  Z-SCORED RETURNS — the agent's current return normalised against the
  mean / std of its own historical returns. Answers "is this return
  normal FOR THIS AGENT".
"""

from __future__ import annotations

import math
from collections.abc import Sequence


# =============================================================================
# Dual fading factors (fast + slow EMA)
# =============================================================================

FADING_ALPHA_FAST = 0.10      # recent-behaviour EMA
FADING_ALPHA_SLOW = 0.01      # long-run-level EMA


def exponential_moving_average(series: Sequence[float], alpha: float) -> float:
    """
    EMA of a time series with smoothing factor `alpha`.

        ema_0 = series[0]
        ema_t = alpha * series[t] + (1 - alpha) * ema_{t-1}

    Returns the EMA after the final observation. Empty series → 0.0.
    `alpha` must be in (0, 1].
    """
    if not series:
        return 0.0
    if not (0.0 < alpha <= 1.0):
        raise ValueError(f"alpha must be in (0, 1], got {alpha}")
    ema = series[0]
    for x in series[1:]:
        ema = alpha * x + (1.0 - alpha) * ema
    return ema


def fading_divergence(series: Sequence[float]) -> dict:
    """
    Compute the fast and slow EMAs of a performance series and their
    divergence.

    Returns a dict:
      fast        — fast EMA (α=0.10)
      slow        — slow EMA (α=0.01)
      divergence  — fast - slow (signed: positive = recent improvement)
      abs_divergence — |fast - slow|

    A series that is flat or steadily trending has small divergence; a
    series with a recent regime change has the fast EMA pulling away from
    the slow one.
    """
    if not series:
        return {"fast": 0.0, "slow": 0.0, "divergence": 0.0, "abs_divergence": 0.0}
    fast = exponential_moving_average(series, FADING_ALPHA_FAST)
    slow = exponential_moving_average(series, FADING_ALPHA_SLOW)
    div = fast - slow
    return {
        "fast": fast,
        "slow": slow,
        "divergence": div,
        "abs_divergence": abs(div),
    }


def fading_health(abs_divergence: float, *, saturation: float) -> float:
    """
    Map fading-EMA divergence magnitude to a [0, 1] health score.

      abs_divergence 0          → 1.0  (recent == long-run; stable)
      abs_divergence >= saturation → 0.0 (sharp recent shift)

    NOTE: divergence is direction-agnostic here — both a recent COLLAPSE
    and a recent SPIKE are "performance instability". The detector layer
    decides whether an upward shift is benign; this primitive only measures
    magnitude of change.
    """
    if not math.isfinite(abs_divergence) or saturation <= 0.0:
        return 0.0
    return max(0.0, min(1.0, 1.0 - abs_divergence / saturation))


# =============================================================================
# Profit Quality — claimed profit vs the market move
# =============================================================================

def profit_quality(
    *,
    claimed_return:  float,    # the agent's net value change over the window
    market_return:   float,    # the market move over the same window
    market_exposure: float = 1.0,   # how "long the market" the agent is, in [-1, 1]
) -> float:
    """
    A [0, 1] profit-quality score. 1.0 = the claimed profit is fully
    consistent with the market move; 0.0 = the profit is inconsistent with
    (or contradicts) the market — un-earned, likely faked.

    The core idea: a long-exposed agent making money in a RISING market is
    plausible; the SAME agent making money in a CRASHING market is
    suspicious — that profit cannot be explained by price action and must
    come from somewhere unverifiable.

    Mechanism:
      expected_sign = sign(market_return * market_exposure)
        — the P&L direction price action alone would produce.
      If claimed_return agrees with expected_sign → high quality.
      If it contradicts it → quality falls, scaled by how STRONG the
        contradicting market move was (a large adverse move makes a
        claimed profit far more suspicious than a flat market does).

    A flat market (market_return ≈ 0) is uninformative — quality defaults
    to a neutral 0.5 rather than punishing or rewarding.
    """
    if not (math.isfinite(claimed_return) and math.isfinite(market_return)):
        return 0.0

    # A flat / unknown market gives no evidence either way.
    if abs(market_return) < 1e-9:
        return 0.5

    expected_direction = market_return * market_exposure
    # Degenerate exposure → no directional expectation.
    if abs(expected_direction) < 1e-12:
        return 0.5

    # No claimed profit AND no claimed loss → nothing to assess.
    if abs(claimed_return) < 1e-12:
        return 0.5

    aligned = (claimed_return > 0) == (expected_direction > 0)

    # Strength of the market signal — how hard price action pushed.
    # Normalised by a reference move so a tiny wobble isn't decisive.
    signal_strength = min(1.0, abs(market_return) / PROFIT_QUALITY_REFERENCE_MOVE)

    if aligned:
        # Profit consistent with the market. Quality high; rises with how
        # clearly the market explains it.
        return max(0.5, min(1.0, 0.5 + 0.5 * signal_strength))
    else:
        # Profit CONTRADICTS the market. Quality low; falls with how
        # strongly the market contradicts it.
        return max(0.0, min(0.5, 0.5 - 0.5 * signal_strength))


# A market move of this magnitude (fractional, e.g. 0.10 = 10%) is treated
# as a "full-strength" signal for profit-quality scaling.
PROFIT_QUALITY_REFERENCE_MOVE = 0.10


# =============================================================================
# Z-scored returns
# =============================================================================

def zscore(value: float, mean: float, std: float) -> float:
    """
    Standard z-score (value - mean) / std, with a zero-variance guard.
    A std at or below the epsilon → z = 0 (no historical spread, no signal).
    """
    if std <= 1e-9 or not math.isfinite(std):
        return 0.0
    z = (value - mean) / std
    # Clamp — a lone corrupt value should not dominate the dimension.
    return max(-Z_CLAMP, min(Z_CLAMP, z))


Z_CLAMP = 12.0


def zscore_health(z: float, *, saturation: float = 6.0) -> float:
    """
    Map a return z-score to a [0, 1] health score.

    Unlike the anomaly dimension, performance z-scores are DIRECTIONAL: a
    strongly NEGATIVE return z (returns far below the agent's norm) is a
    performance problem; a strongly POSITIVE one is not — outperforming
    your own history is good.

    So:
      z >= 0            → 1.0  (at or above own historical mean)
      z = -saturation   → 0.0  (returns catastrophically below norm)
      linear in between.
    """
    if not math.isfinite(z) or saturation <= 0.0:
        return 0.0
    if z >= 0.0:
        return 1.0
    return max(0.0, min(1.0, 1.0 + z / saturation))
