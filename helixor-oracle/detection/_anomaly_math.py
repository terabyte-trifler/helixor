"""
detection/_anomaly_math.py — anomaly-ensemble primitives, pure stdlib.

Day 7 implements Methods 1-3 of the 5-method anomaly ensemble. Methods 4-5
and the Isolation Forest land on Day 8.

Why no numpy / scipy / sklearn? Same Phase-4 BFT rule as Days 5-6: three
oracle nodes must compute byte-identical anomaly scores. Mahalanobis is a
sum of squares; log-likelihood is a sum of logs; group-variance is mean +
stddev. All trivially stdlib, all IEEE-stable.

THE THREE METHODS — and why they are genuinely different signals
----------------------------------------------------------------
All three consume the per-feature z-scores  z_i = (x_i - μ_i) / σ_i, but
they aggregate them differently, so they disagree in informative ways:

  Method 1 — feature-group disagreement (a.k.a. "prediction uncertainty").
      Each of the 9 feature groups produces its own anomaly estimate (the
      RMS of that group's z-scores). Method 1 is the VARIANCE across those
      9 group estimates. A healthy agent is uniformly normal — all groups
      agree "I'm fine", variance ≈ 0. An anomalous agent is anomalous in
      SOME dimensions but not others — the groups disagree, variance is high.
      This is the ensemble-uncertainty signal without needing 100 sub-models.

  Method 2 — diagonal Mahalanobis distance.
      sqrt( Σ z_i² ).  The L2 norm of the z-vector. Geometric "how far from
      the baseline centroid". DOMINATED BY THE SINGLE WORST FEATURE — one
      feature at z=10 produces distance ≈ 10 regardless of the other 99.
      (Diagonal = assumes feature independence; see note below.)

  Method 3 — joint negative log-likelihood.
      Under the model "each feature ~ N(μ_i, σ_i²)", the joint log-likelihood
      is Σ log p(x_i). Method 3 is the mean per-feature surprisal. DOMINATED
      BY HOW MANY features are improbable, not by the single worst one. An
      agent with 50 features each mildly off scores worse here than an agent
      with one extreme feature — the opposite emphasis to Method 2.

NOTE ON DIAGONAL MAHALANOBIS
----------------------------
True Mahalanobis needs the full feature covariance matrix Σ. BaselineStats
stores only the diagonal (per-feature means + stds). Storing a 100×100 Σ
would 100× the baseline size and the on-chain commitment payload. The
diagonal approximation (a.k.a. standardized Euclidean distance) assumes
feature independence — defensible because the 100 features were chosen to
be semantically distinct. Full-covariance Mahalanobis is a documented
Phase-2 upgrade if measurement shows correlation distorts scores.
"""

from __future__ import annotations

import math
from collections.abc import Sequence


# =============================================================================
# Constants
# =============================================================================

# Numerical floor for a feature's baseline stddev. A feature whose baseline
# σ ≈ 0 never varied historically; its z-score is undefined. We treat such
# features as carrying no anomaly signal (z = 0) rather than dividing by ~0.
STD_EPSILON = 1e-9

# Per-feature z-score is clamped to this magnitude before aggregation. A
# single corrupt feature at z = 10_000 should not swamp the ensemble; real
# anomalies are detectable well within ±12σ. This makes every method robust
# to a lone arithmetic outlier.
Z_CLAMP = 12.0


# =============================================================================
# Shared primitive — per-feature z-scores
# =============================================================================

def feature_z_scores(
    current:  Sequence[float],
    means:    Sequence[float],
    stds:     Sequence[float],
) -> list[float]:
    """
    z_i = (x_i - μ_i) / σ_i, clamped to ±Z_CLAMP.

    Features with σ_i <= STD_EPSILON carry no anomaly signal → z_i = 0.
    All three anomaly methods build on this vector.

    Raises ValueError on length mismatch.
    """
    n = len(current)
    if not (n == len(means) == len(stds)):
        raise ValueError(
            f"length mismatch: current={n}, means={len(means)}, stds={len(stds)}"
        )
    zs: list[float] = []
    for x, mu, sigma in zip(current, means, stds, strict=True):
        if sigma <= STD_EPSILON:
            zs.append(0.0)
        else:
            z = (x - mu) / sigma
            # Clamp — robustness against a lone corrupt feature.
            z = max(-Z_CLAMP, min(Z_CLAMP, z))
            zs.append(z)
    return zs


# =============================================================================
# Method 1 — feature-group disagreement ("prediction uncertainty")
# =============================================================================

def group_rms(z_scores: Sequence[float]) -> float:
    """Root-mean-square of a group's z-scores — that group's anomaly estimate."""
    if not z_scores:
        return 0.0
    return math.sqrt(sum(z * z for z in z_scores) / len(z_scores))


def method1_group_disagreement(group_z_scores: dict[str, Sequence[float]]) -> float:
    """
    Method 1 — variance of per-group anomaly estimates.

    `group_z_scores` maps group name → that group's z-score list.
    Each group's estimate is its RMS z-score. The method returns the
    POPULATION VARIANCE across the group estimates.

      healthy agent  → all groups ≈ same low RMS → variance ≈ 0
      anomalous agent→ some groups high, others low → high variance

    Returns a non-negative anomaly magnitude (0 = healthy).
    """
    if not group_z_scores:
        return 0.0
    estimates = [group_rms(zs) for zs in group_z_scores.values()]
    k = len(estimates)
    if k < 2:
        return 0.0
    mean_est = sum(estimates) / k
    variance = sum((e - mean_est) ** 2 for e in estimates) / k
    return variance


# =============================================================================
# Method 2 — diagonal Mahalanobis distance
# =============================================================================

def method2_mahalanobis(z_scores: Sequence[float]) -> float:
    """
    Method 2 — diagonal Mahalanobis distance = L2 norm of the z-vector.

        d = sqrt( Σ z_i² )

    Geometric distance from the baseline centroid in standard-deviation
    units. Dominated by the single worst feature.

    Returns a non-negative anomaly magnitude (0 = healthy).
    """
    if not z_scores:
        return 0.0
    return math.sqrt(sum(z * z for z in z_scores))


# =============================================================================
# Method 3 — joint negative log-likelihood (mean per-feature surprisal)
# =============================================================================

# Per-feature standard-normal log-density at z = 0 is the maximum:
#   log p(0) = -0.5 * log(2π).  The "surprisal" of a feature is how far
# BELOW that maximum its log-density falls.
_LOG_2PI = math.log(2.0 * math.pi)


def standard_normal_logpdf(z: float) -> float:
    """log of the standard-normal density at z:  -0.5 (z² + log 2π)."""
    return -0.5 * (z * z + _LOG_2PI)


def method3_mean_surprisal(z_scores: Sequence[float]) -> float:
    """
    Method 3 — mean per-feature surprisal under N(μ_i, σ_i²).

    Surprisal of feature i = logp(0) - logp(z_i) = 0.5 * z_i²
    (the standard normal's surprisal above its mode). Method 3 returns the
    MEAN surprisal across all features.

    Because surprisal is averaged (not summed and not max'd), this method
    is dominated by HOW MANY features are improbable — an agent with many
    mildly-off features scores worse here than one with a single extreme
    feature. This is the deliberate counterpoint to Method 2.

    Returns a non-negative anomaly magnitude (0 = healthy).
    """
    if not z_scores:
        return 0.0
    # surprisal_i = logp(0) - logp(z_i) = 0.5 z_i²  (the log-2π terms cancel)
    total_surprisal = sum(0.5 * z * z for z in z_scores)
    return total_surprisal / len(z_scores)


# =============================================================================
# Magnitude → health-score mapping
# =============================================================================
#
# Every method produces an anomaly MAGNITUDE in [0, ∞). The DimensionResult
# sub-score contract (Day 4) requires a value in [0, 1], and Days 5-6 fixed
# the convention 1.0 = healthy, 0.0 = anomalous. Each method has its own
# natural scale, so each gets its own saturation point.
# =============================================================================

def magnitude_to_health(magnitude: float, *, saturation: float) -> float:
    """
    Map an anomaly magnitude in [0, ∞) to a health sub-score in [0, 1].

      magnitude 0           → 1.0   (perfectly healthy)
      magnitude >= saturation → 0.0  (fully anomalous)
      linear in between.

    `saturation` is the method-specific magnitude at which we declare
    "maximally anomalous". Non-finite magnitude → 0.0 (treat as anomalous).
    """
    if not math.isfinite(magnitude):
        return 0.0
    if magnitude <= 0.0:
        return 1.0
    if saturation <= 0.0:
        return 0.0
    return max(0.0, min(1.0, 1.0 - magnitude / saturation))
