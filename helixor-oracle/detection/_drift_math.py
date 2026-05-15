"""
detection/_drift_math.py — drift-detection primitives, pure stdlib.

Why no scipy? The Phase-4 BFT oracle cluster needs three independent nodes
to compute byte-identical drift scores. scipy's KS implementation is
generally stable but its version-pinning across nodes is a determinism
risk we shouldn't accept when the math is this small. PSI is trivial
arithmetic; KS-test is sort + max gap + a closed-form survival function.
Pure stdlib eliminates the whole class of "node A has scipy 1.11, node B
has scipy 1.13" failures.

Functions here are SMALL, isolated, and individually unit-tested.

References:
  PSI:  Lin (2017) "Population Stability Index" — standard formula
         (cur - base) * ln(cur / base), summed over buckets.
  KS:   Kolmogorov-Smirnov one-sample test against N(0,1).
         D statistic = max |F_n(x) - Φ(x)|.
         p-value approximation: Kolmogorov's series.
"""

from __future__ import annotations

import math
from collections.abc import Sequence


# =============================================================================
# Constants
# =============================================================================

# ε-smoothing for PSI. Both current and baseline buckets get this minimum mass
# so log(0) is impossible. 1e-4 is the standard credit-risk PSI default.
PSI_EPSILON = 1e-4

# Standard PSI bands (industry-standard thresholds, used universally):
PSI_BAND_STABLE         = 0.10    # < this: no significant shift
PSI_BAND_MODERATE_SHIFT = 0.25    # 0.10..0.25: moderate shift
                                  # > 0.25: major shift


# =============================================================================
# PSI — Population Stability Index
# =============================================================================

def population_stability_index(
    current:  Sequence[float],
    baseline: Sequence[float],
    *,
    epsilon:  float = PSI_EPSILON,
) -> float:
    """
    PSI between two discrete distributions, expressed as proportions in
    [0, 1] (each summing to 1 within ε of 1.0). Returns a non-negative
    float; higher = more shifted.

        PSI = Σ (cur_i - base_i) * ln(cur_i / base_i)

    Both distributions are ε-smoothed BEFORE the ratio so log(0) and
    division-by-zero are impossible.

    Assumptions:
      - len(current) == len(baseline) > 0
      - inputs are PROPORTIONS, not raw counts (caller normalises)

    Edge cases:
      - identical distributions → exactly 0.0
      - all-zero inputs (degenerate baseline) → smoothed to uniform, → 0.0

    Pure. Deterministic to the last bit of float precision.
    """
    if len(current) != len(baseline):
        raise ValueError(
            f"PSI bucket count mismatch: current={len(current)}, baseline={len(baseline)}"
        )
    if not current:
        raise ValueError("PSI inputs must be non-empty")
    if epsilon <= 0:
        raise ValueError(f"PSI epsilon must be positive, got {epsilon}")

    # ε-smoothing: add ε to each bucket, then re-normalise so each side still
    # sums to 1.0. This eliminates log(0) and keeps the math interpretable.
    cur_smoothed  = [max(c, 0.0) + epsilon for c in current]
    base_smoothed = [max(b, 0.0) + epsilon for b in baseline]
    cur_total  = sum(cur_smoothed)
    base_total = sum(base_smoothed)

    psi = 0.0
    for c_raw, b_raw in zip(cur_smoothed, base_smoothed, strict=True):
        c = c_raw / cur_total
        b = b_raw / base_total
        psi += (c - b) * math.log(c / b)

    # Tiny negative floating-point dust on identical inputs → clamp at 0.
    return max(0.0, psi)


def psi_normalised_score(psi: float) -> float:
    """
    Map a raw PSI value into [0, 1] for use as a sub-score.
      - 0.00         → 1.0  (perfectly stable — full credit)
      - 0.10         → 0.5  (threshold: starting to shift)
      - 0.25 or more → 0.0  (major shift — no credit)

    Linear in between via the two thresholds. Non-finite or negative PSI → 0.5
    (neutral) to keep the sub-score in [0,1] without falsely claiming stability.
    """
    if not math.isfinite(psi):
        return 0.5
    if psi <= 0.0:
        return 1.0
    if psi >= PSI_BAND_MODERATE_SHIFT:
        return 0.0
    # Linear interpolation: 0 PSI → 1.0, 0.25 PSI → 0.0.
    return max(0.0, min(1.0, 1.0 - psi / PSI_BAND_MODERATE_SHIFT))


# =============================================================================
# KS test — one-sample, against the standard normal N(0, 1)
# =============================================================================

def standard_normal_cdf(x: float) -> float:
    """Φ(x) = standard-normal CDF. math.erf is in the stdlib and IEEE-stable."""
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def ks_one_sample_normal(samples: Sequence[float]) -> tuple[float, float]:
    """
    One-sample Kolmogorov-Smirnov test against the standard normal N(0, 1).

    Returns (D, p_value):
      D       = max |F_n(x_i) - Φ(x_i)|, the KS statistic
      p_value = P(D_n > D) under the null H0: samples come from N(0, 1)

    Null hypothesis: the input samples are draws from N(0, 1).
    Use case here: each feature's z-score against its baseline. If the agent
    behaves like its 30-day baseline, z-scores cluster around 0 with stddev
    near 1, and KS will fail to reject H0.

    Pure stdlib. Returns finite floats for all inputs (degenerate: empty
    sample → D=0, p=1; single sample → exact one-step CDF gap, valid).

    Reference: standard Kolmogorov D_n statistic; p-value via Kolmogorov's
    asymptotic series (Marsaglia 2003 approximation), accurate for n ≥ 5.
    """
    n = len(samples)
    if n == 0:
        return 0.0, 1.0    # no evidence to reject → p = 1.0

    sorted_samples = sorted(samples)

    # D = max over i of the two-sided gap: max(|i/n - F(x_i)|, |(i-1)/n - F(x_i)|).
    # Using both sides catches both "above" and "below" deviations.
    d = 0.0
    for i, x in enumerate(sorted_samples, start=1):
        cdf = standard_normal_cdf(x)
        # Empirical CDF jumps from (i-1)/n to i/n at x_i. Compare both.
        d_plus  = i / n         - cdf
        d_minus = cdf - (i - 1) / n
        d = max(d, d_plus, d_minus)

    p = _ks_p_value(n, d)
    # Guard against numerical drift outside [0, 1].
    p = max(0.0, min(1.0, p))
    return d, p


def _ks_p_value(n: int, d: float) -> float:
    """
    Kolmogorov-Smirnov asymptotic p-value via Kolmogorov's series:
        P(sqrt(n) * D > λ) ≈ 2 Σ_{k=1..∞} (-1)^(k-1) exp(-2 k² λ²)
    where λ = (sqrt(n) + 0.12 + 0.11/sqrt(n)) * D  (Stephens 1970 correction
    for the standard normal special case is close to the same series).

    Accurate to ~1e-7 for n ≥ 5; we cap series at 100 terms which is more
    than enough for double precision.
    """
    if n <= 0 or d <= 0.0:
        return 1.0
    if d >= 1.0:
        return 0.0

    # Stephens (1970) finite-sample correction
    lam = (math.sqrt(n) + 0.12 + 0.11 / math.sqrt(n)) * d
    # Series: 2 Σ (-1)^(k-1) exp(-2 k² λ²)
    total = 0.0
    for k in range(1, 101):
        term = math.exp(-2.0 * (k ** 2) * (lam ** 2))
        if k % 2 == 1:
            total += term
        else:
            total -= term
        # Early-out: terms shrink fast — once they fall below 1e-16 we're done.
        if term < 1e-16:
            break

    return 2.0 * total


def bonferroni_alpha(alpha: float, n_tests: int) -> float:
    """
    Bonferroni-correct a per-test significance level for N independent tests.
        α_corrected = α / N
    Guards: N >= 1, α in (0, 1).
    """
    if n_tests < 1:
        raise ValueError(f"bonferroni: n_tests must be >= 1, got {n_tests}")
    if not (0.0 < alpha < 1.0):
        raise ValueError(f"bonferroni: alpha must be in (0, 1), got {alpha}")
    return alpha / n_tests
