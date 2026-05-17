"""
detection/_consistency_math.py — consistency-scoring primitives, pure stdlib.

Consistency asks: "does the agent behave like ITSELF, and like what it
DECLARED?" Four families of primitive, all deterministic (Phase-4 BFT
rule — no numpy, no scipy):

  DISTRIBUTION DIVERGENCE — Jensen-Shannon divergence between two
  probability distributions. Used for tool-stability (current program-mix
  vs baseline) and domain-conformance (observed txtype-mix vs the declared
  domain's expected signature).

  RHYTHM DIVERGENCE — how far the agent's current activity-rhythm features
  have moved from its own baseline rhythm. A predictable agent that turns
  erratic — OR an erratic one that turns clockwork — is inconsistent.

  CONJUNCTION SCORING — counterparty-outcome consistency is a conjunction:
  success-rate deviation only matters when the agent is transacting with
  REPEAT counterparties (it should know them). New-counterparty churn
  explains away outcome variance; repeat-counterparty churn does not.

  All bounded, all stdlib.
"""

from __future__ import annotations

import math
from collections.abc import Sequence


# =============================================================================
# Distribution divergence — Jensen-Shannon
# =============================================================================

def _normalise(dist: Sequence[float]) -> list[float]:
    """Normalise a non-negative vector to sum 1. All-zero → uniform."""
    total = sum(dist)
    if total <= 1e-12:
        n = len(dist)
        return [1.0 / n] * n if n else []
    return [x / total for x in dist]


def _kl_divergence(p: Sequence[float], q: Sequence[float]) -> float:
    """KL(p || q) with epsilon-smoothing. Both must be same-length, normalised."""
    eps = 1e-12
    total = 0.0
    for pi, qi in zip(p, q):
        if pi <= eps:
            continue
        total += pi * math.log((pi + eps) / (qi + eps))
    return total


def jensen_shannon_divergence(
    dist_a: Sequence[float],
    dist_b: Sequence[float],
) -> float:
    """
    Jensen-Shannon divergence between two distributions, in [0, 1]
    (using log base 2). Symmetric, bounded, and finite even when the
    distributions have disjoint support — unlike raw KL.

      0.0 = identical distributions
      1.0 = maximally different (disjoint support)

    Mismatched lengths raise ValueError.
    """
    if len(dist_a) != len(dist_b):
        raise ValueError(
            f"JSD length mismatch: {len(dist_a)} vs {len(dist_b)}"
        )
    if not dist_a:
        return 0.0
    p = _normalise(dist_a)
    q = _normalise(dist_b)
    m = [(pi + qi) / 2.0 for pi, qi in zip(p, q)]
    # JSD = 0.5 KL(p||m) + 0.5 KL(q||m), converted to base 2.
    jsd_nats = 0.5 * _kl_divergence(p, m) + 0.5 * _kl_divergence(q, m)
    jsd = jsd_nats / math.log(2.0)
    # Numerical guard — JSD is mathematically in [0, 1].
    return max(0.0, min(1.0, jsd))


def divergence_to_health(divergence: float, *, saturation: float) -> float:
    """
    Map a divergence/instability magnitude in [0, ∞) to a [0, 1] health
    score. 1.0 = identical/stable, 0.0 = fully diverged.
    """
    if not math.isfinite(divergence) or saturation <= 0.0:
        return 0.0
    if divergence <= 0.0:
        return 1.0
    return max(0.0, min(1.0, 1.0 - divergence / saturation))


# =============================================================================
# Rhythm divergence — current rhythm features vs baseline
# =============================================================================

def rhythm_divergence(
    current_rhythm:   Sequence[float],
    baseline_means:   Sequence[float],
    baseline_stds:    Sequence[float],
) -> float:
    """
    Mean absolute z-score of the rhythm-group features — how far the
    agent's current activity rhythm has moved from its own baseline.

    Direction-agnostic: a regular agent turning erratic and an erratic
    agent turning clockwork are BOTH rhythm breaks (an operator change
    can show up either way).

    Returns a non-negative magnitude (0 = rhythm unchanged). Features with
    zero baseline variance contribute nothing.
    """
    n = len(current_rhythm)
    if n == 0 or n != len(baseline_means) or n != len(baseline_stds):
        return 0.0
    z_sum = 0.0
    counted = 0
    for x, mu, sigma in zip(current_rhythm, baseline_means, baseline_stds):
        if sigma <= 1e-9:
            continue
        z = abs(x - mu) / sigma
        z_sum += min(z, 12.0)           # clamp a lone corrupt feature
        counted += 1
    return z_sum / counted if counted else 0.0


# =============================================================================
# Counterparty-outcome consistency — a conjunction
# =============================================================================

def counterparty_outcome_consistency(
    *,
    repeat_ratio:        float,   # cp_repeat_ratio — how much the agent reuses CPs, [0,1]
    current_success_rate: float,  # current success_rate_30d, [0,1]
    baseline_success_rate: float, # baseline success_rate_30d mean, [0,1]
    baseline_success_std: float,  # baseline std for success_rate_30d
    success_volatility:  float = 0.0,  # secondary stabilizer, [0,1]-ish
) -> float:
    """
    A [0, 1] consistency score for counterparty outcomes.

    The signal is a CONJUNCTION. An agent transacting mostly with NEW
    counterparties can legitimately have variable outcomes — it does not
    know them yet. An agent transacting mostly with REPEAT counterparties
    should get STABLE outcomes — it has a track record with them. So
    success-rate deviation from the agent's own baseline only counts against
    consistency to the extent the agent is dealing with repeat counterparties.
    `success_volatility` remains a secondary stabilizer: a repeat-CP agent
    with wildly unstable daily outcomes is also inconsistent.

      consistency = 1 - repeat_ratio * max(success_z_penalty, volatility_penalty)

    high repeat + baseline-like success → ~1.0
    high repeat + large success z-score → low
    low  repeat + large success z-score → mostly excused
    """
    rr = _clamp01(repeat_ratio)

    if baseline_success_std <= 1e-9:
        success_z = 0.0 if abs(current_success_rate - baseline_success_rate) <= 1e-9 else 6.0
    else:
        success_z = abs(current_success_rate - baseline_success_rate) / baseline_success_std
    success_z = min(success_z, 6.0)
    success_z_penalty = 1.0 - divergence_to_health(success_z, saturation=3.0)

    # success_volatility is roughly in [0, 0.5] in practice; normalise to [0,1].
    volatility_penalty = _clamp01(success_volatility / 0.5)

    inconsistency = rr * max(success_z_penalty, volatility_penalty)
    return _clamp01(1.0 - inconsistency)


# =============================================================================
# Helpers
# =============================================================================

def _clamp01(x: float) -> float:
    if not math.isfinite(x):
        return 0.0
    return max(0.0, min(1.0, x))
