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


# =============================================================================
# Method 4 — n-gram sequence deviation
# =============================================================================
#
# The Day-1 feature extractor's `sequence` group (14 features) is computed
# directly FROM the agent's action n-grams: bigram/trigram entropy, bigram
# concentration, self-transition fraction, longest-repeat run, etc.
#
# Method 4 measures how far the current vector's 14 sequence-group features
# have moved from their baseline — a focused, sequence-specific deviation.
# A tool-invocation pattern that no longer matches the baseline n-gram
# structure shows up as a large RMS z-score over exactly these features.
#
# Why not store the raw n-gram distribution on the baseline? Because the
# `sequence` group ALREADY encodes it — bigram entropy IS the n-gram
# distribution's entropy. Working with the existing features avoids a
# fourth BaselineStats schema bump.
# =============================================================================

def method4_sequence_deviation(sequence_z_scores: Sequence[float]) -> float:
    """
    Method 4 — RMS of the sequence-group z-scores.

    `sequence_z_scores` is the z-score sub-vector for exactly the 14
    `sequence`-group features. Returns a non-negative anomaly magnitude
    (0 = the agent's n-gram structure matches its baseline).
    """
    if not sequence_z_scores:
        return 0.0
    return math.sqrt(
        sum(z * z for z in sequence_z_scores) / len(sequence_z_scores)
    )


# =============================================================================
# Method 5 — adversarial signal (sudden feature-space jumps)
# =============================================================================
#
# A "sudden jump" is hard to define from a single snapshot — but the SHAPE
# of an adversarial deviation is distinctive. Natural drift moves many
# features together, smoothly: the z-score distribution stays roughly
# bell-shaped. An adversarial manipulation pushes a FEW features to extreme
# values while leaving the rest pristine — a sparse, spiky deviation.
#
# That sparsity is exactly EXCESS KURTOSIS of the z-score distribution.
# A bell-shaped (drift-like) z-distribution has excess kurtosis ≈ 0; a
# spiky (adversarial) one has high positive excess kurtosis.
#
# Method 5 returns the excess kurtosis of the z-vector, floored at 0
# (we only care about spikiness, not flatness).
# =============================================================================

def method5_adversarial_kurtosis(z_scores: Sequence[float]) -> float:
    """
    Method 5 — excess kurtosis of the z-score distribution, floored at 0.

    excess kurtosis = ( E[(z-μ)^4] / (E[(z-μ)^2])^2 ) - 3

    A drift-like (broadly Gaussian) deviation → excess kurtosis ≈ 0.
    A sparse adversarial spike (few huge z's, rest near 0) → large positive.

    Returns a non-negative anomaly magnitude (0 = not spiky).
    """
    n = len(z_scores)
    if n < 4:
        return 0.0
    mean = sum(z_scores) / n
    m2 = sum((z - mean) ** 2 for z in z_scores) / n
    if m2 <= 1e-12:
        return 0.0   # no variance → no spikiness
    m4 = sum((z - mean) ** 4 for z in z_scores) / n
    excess_kurtosis = (m4 / (m2 * m2)) - 3.0
    return max(0.0, excess_kurtosis)


# =============================================================================
# Isolation Forest — DETERMINISTIC implementation
# =============================================================================
#
# Liu, Ting & Zhou (2008). The standard implementation (sklearn) is
# RANDOM by construction: it samples random split features + random split
# values, so two runs — or two oracle nodes — produce different forests.
# That is incompatible with Phase-4 BFT consensus.
#
# This implementation is DETERMINISTIC: the randomness is driven by an
# explicitly-seeded stdlib PRNG. Given the same seed it builds a
# bit-identical forest on every machine. The detector derives the seed
# from the baseline's stats_hash, so the whole IsoForest is a pure
# function of (features, baseline).
#
# Algorithm:
#   - Build N_TREES isolation trees over a synthetic reference population
#     sampled from the agent's own baseline N(μ_i, σ_i) per feature.
#   - Each tree recursively splits on a random feature at a random value
#     until points are isolated or max depth is hit.
#   - A point's anomaly score is 2^(-E[h(x)] / c(n)), where E[h(x)] is the
#     mean isolation depth across trees and c(n) is the average path
#     length of an unsuccessful BST search (the normalisation constant).
#   - Score near 1.0 = anomalous (isolates quickly); near 0.5 = normal.
# =============================================================================

import random as _random

ISO_N_TREES         = 64        # number of isolation trees
ISO_SAMPLE_SIZE     = 128       # sub-sample size per tree (psi in the paper)
ISO_REFERENCE_SIZE  = 256       # synthetic reference population size
# Tree depth cap. The paper uses ceil(log2(psi)) because anomalies isolate
# FAST and that depth suffices. But in HIGH DIMENSION (100 features) a
# sparse anomaly is rarely hit by random splits, so trees need to go
# deeper for the isolation depth to be meaningful. We use a generous cap;
# anomalies still isolate well before it, normal points hit it + get the
# c(n) correction.
ISO_MAX_DEPTH       = 40


def _iso_c(n: int) -> float:
    """
    c(n): average path length of an unsuccessful search in a BST of n nodes.
    The Isolation Forest normalisation constant.
        c(n) = 2 H(n-1) - 2(n-1)/n,  H(i) ≈ ln(i) + Euler-Mascheroni
    """
    if n <= 1:
        return 1.0
    euler = 0.5772156649015329
    harmonic = math.log(n - 1) + euler
    return 2.0 * harmonic - (2.0 * (n - 1) / n)


def _iso_path_length(point: Sequence[float],
                      sample: list[list[float]],
                      rng: _random.Random,
                      depth: int,
                      max_depth: int) -> float:
    """
    Recursively isolate `point` within `sample`. Returns the path length
    (number of splits) needed to isolate it, plus a c() correction if the
    recursion bottoms out before full isolation.
    """
    n = len(sample)
    if depth >= max_depth or n <= 1:
        return depth + _iso_c(n)

    # Pick a random split feature that actually has spread. The split RANGE
    # must include the scored point — otherwise an out-of-range anomaly (a
    # point beyond every reference value on a feature) can never be isolated
    # on that feature: every split sends it to the same side with the bulk
    # of the sample. Extending the range to cover the point lets a split
    # land between the point and the reference cluster.
    n_features = len(point)
    for _ in range(8):
        f = rng.randrange(n_features)
        col = [row[f] for row in sample]
        lo = min(min(col), point[f])
        hi = max(max(col), point[f])
        if hi > lo:
            break
    else:
        # No feature has spread — the sample is degenerate; stop.
        return depth + _iso_c(n)

    split = rng.uniform(lo, hi)
    left  = [row for row in sample if row[f] < split]
    right = [row for row in sample if row[f] >= split]

    # Recurse into whichever side the point falls.
    # If the point lands on an EMPTY side, the split fully isolated it —
    # the path ends here at depth+1. (Returning depth + c(n) here was a bug:
    # it penalised an isolated anomaly with the average-BST-depth of the
    # whole remaining sample, flattening anomaly/normal separation.)
    if point[f] < split:
        if not left:
            return float(depth + 1)
        return _iso_path_length(point, left, rng, depth + 1, max_depth)
    else:
        if not right:
            return float(depth + 1)
        return _iso_path_length(point, right, rng, depth + 1, max_depth)


def isolation_forest_score(
    point:       Sequence[float],
    means:       Sequence[float],
    stds:        Sequence[float],
    *,
    seed:        int,
    n_trees:     int = ISO_N_TREES,
    sample_size: int = ISO_SAMPLE_SIZE,
) -> float:
    """
    Deterministic Isolation Forest anomaly score for a single point.

    The forest is trained on a synthetic reference population sampled from
    N(μ_i, σ_i) per feature — i.e. "the agent's own baseline distribution".
    The `seed` makes the whole computation a pure function: identical seed
    -> identical forest -> identical score, on every machine.

    Returns the standard Isolation Forest anomaly score in [0, 1]:
        ~1.0 = strongly anomalous (point isolates very quickly)
        ~0.5 = normal
        ~0.0 = very deep in the distribution
    """
    n_features = len(point)
    if not (n_features == len(means) == len(stds)):
        raise ValueError("point/means/stds length mismatch")
    if n_features == 0:
        return 0.5

    rng = _random.Random(seed)

    # 1. Build a deterministic synthetic reference population from the
    #    agent's baseline distribution.
    reference: list[list[float]] = []
    for _ in range(ISO_REFERENCE_SIZE):
        row = [
            rng.gauss(mu, sigma if sigma > 1e-12 else 1e-9)
            for mu, sigma in zip(means, stds)
        ]
        reference.append(row)

    # 2. Tree depth limit. See ISO_MAX_DEPTH — generous in high dimension.
    max_depth = ISO_MAX_DEPTH

    # 3. Build n_trees, each on a fresh sub-sample; accumulate path length.
    total_path = 0.0
    point_list = list(point)
    for _ in range(n_trees):
        if len(reference) <= sample_size:
            sub = list(reference)
        else:
            sub = rng.sample(reference, sample_size)
        total_path += _iso_path_length(point_list, sub, rng, 0, max_depth)

    mean_path = total_path / n_trees

    # 4. Anomaly score: s(x) = 2^(-E[h(x)] / c(psi)).
    c = _iso_c(min(sample_size, len(reference)))
    if c <= 0:
        return 0.5
    return 2.0 ** (-mean_path / c)


def isolation_forest_health(iso_score: float) -> float:
    """
    Map the raw Isolation Forest anomaly score in [0, 1] to a health
    sub-score in [0, 1], where 1.0 = healthy.

    Standard IsoForest interpretation:
       score < 0.5  → normal      → health high
       score ≈ 0.5  → borderline
       score > 0.5  → anomalous   → health low
       score ≈ 1.0  → strongly anomalous → health 0

    We map [0.5, 1.0] linearly onto [1.0, 0.0]; scores below 0.5 are
    fully healthy.
    """
    if not math.isfinite(iso_score):
        return 0.0
    if iso_score <= 0.5:
        return 1.0
    return max(0.0, min(1.0, 1.0 - (iso_score - 0.5) / 0.5))
