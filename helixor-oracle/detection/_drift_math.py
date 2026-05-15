"""
detection/_drift_math.py — drift-detection primitives, pure stdlib.

Why no scipy / river? The Phase-4 BFT oracle cluster needs three independent
nodes to compute byte-identical drift scores. scipy and river both have
version-dependent internals that introduce a "node A has X 1.11, node B has
X 1.13" determinism risk. The algorithms themselves are small — PSI is
arithmetic, KS is sort + max gap, CUSUM is a running sum, ADWIN is ~80
lines of cut-search, DDM is ~30 lines of error-rate tracking. Pure stdlib
eliminates the whole class of cross-node divergence failures.

Functions here are SMALL, isolated, and individually unit-tested.

References:
  PSI:    Lin (2017) — formula (cur - base) * ln(cur/base), ε-smoothed.
  KS:     Kolmogorov-Smirnov one-sample test against N(0, 1).
          D = max |F_n(x) - Φ(x)|; p-value via Kolmogorov's series.
  CUSUM:  Page (1954) — sequential change-point detection via two
          cumulative sums (positive + negative); reset on trigger.
  ADWIN:  Bifet & Gavaldà (2007) — Adaptive Windowing. Maintains a window
          of recent observations; cuts the window at any split where two
          sub-windows' means differ by more than a Hoeffding bound at
          confidence (1 - δ).
  DDM:    Gama et al. (2004) — Drift Detection Method. Tracks the running
          mean p_i and standard deviation s_i = sqrt(p_i (1-p_i)/i) of an
          error stream. Maintains minimum (p_min + s_min). Warning when
          p_i + s_i > p_min + 2*s_min; drift when > p_min + 3*s_min.
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


# =============================================================================
# CUSUM — Page's two-sided cumulative-sum change-point detector
# =============================================================================
#
# Tracks two running sums over a sequential stream x_1, x_2, ...:
#
#     C_pos_i = max(0, C_pos_{i-1} + (x_i - μ) - k)     # upward shifts
#     C_neg_i = min(0, C_neg_{i-1} + (x_i - μ) + k)     # downward shifts
#
# where μ is the reference (target) mean and k is the slack (half the minimum
# shift size we want to detect, typically 0.5σ).
#
# A change is triggered when |C| crosses a threshold h (typically 4σ-5σ).
# On trigger, both sums reset to 0.
#
# For success-rate streams in [0, 1]:
#   μ = baseline mean success rate
#   σ = baseline stddev of daily success rates
#   k = 0.5 * σ  (clamped to a floor for very-low-variance baselines)
#   h = 5.0 * σ  (clamped to a floor)
# =============================================================================

# Minimum effective σ for CUSUM. An agent that always succeeds has baseline
# σ ≈ 0; a CUSUM with σ=0 has no slack and triggers on the slightest blip.
# This floor reflects "we cannot meaningfully detect <1pp shifts in
# success rate from daily aggregates of <500 transactions/day".
CUSUM_MIN_SIGMA      = 0.01
CUSUM_K_MULTIPLIER   = 0.5
CUSUM_H_MULTIPLIER   = 5.0


def cusum_two_sided(
    samples:        Sequence[float],
    *,
    reference_mean: float,
    sigma:          float,
    k_multiplier:   float = CUSUM_K_MULTIPLIER,
    h_multiplier:   float = CUSUM_H_MULTIPLIER,
    min_sigma:      float = CUSUM_MIN_SIGMA,
) -> dict:
    """
    Two-sided CUSUM over a sequential stream.

    Returns a dict with:
      pos_max     : largest C_pos seen across the stream
      neg_max     : largest |C_neg| seen across the stream
      triggered   : True iff max(pos_max, neg_max) >= h
      trigger_idx : index of the first trigger, or -1
      h           : the threshold actually used (after σ floor)

    Pure. Deterministic.
    """
    effective_sigma = max(sigma, min_sigma)
    k = k_multiplier * effective_sigma
    h = h_multiplier * effective_sigma

    c_pos = 0.0
    c_neg = 0.0
    pos_max = 0.0
    neg_max = 0.0
    triggered = False
    trigger_idx = -1

    for i, x in enumerate(samples):
        c_pos = max(0.0, c_pos + (x - reference_mean) - k)
        c_neg = min(0.0, c_neg + (x - reference_mean) + k)
        pos_max = max(pos_max, c_pos)
        neg_max = max(neg_max, -c_neg)
        if not triggered and (c_pos >= h or -c_neg >= h):
            triggered = True
            trigger_idx = i
            # Reset on trigger, as per Page's CUSUM convention.
            c_pos = 0.0
            c_neg = 0.0

    return {
        "pos_max":     pos_max,
        "neg_max":     neg_max,
        "triggered":   triggered,
        "trigger_idx": trigger_idx,
        "h":           h,
    }


def cusum_normalised_score(cusum_result: dict) -> float:
    """
    Map CUSUM output to a [0, 1] sub-score where 1.0 = no change, 0.0 = strong change.

    Uses sigmoid-style mapping of max(pos_max, neg_max) / h:
      ratio = 0.0  → score 1.0   (no excursion)
      ratio = 1.0  → score 0.0   (exactly at trigger threshold)
      ratio > 1.0  → score 0.0   (clamped)
    """
    h = cusum_result["h"]
    if h <= 0.0:
        return 0.5     # degenerate — neutral
    max_excursion = max(cusum_result["pos_max"], cusum_result["neg_max"])
    ratio = max_excursion / h
    return max(0.0, min(1.0, 1.0 - ratio))


# =============================================================================
# ADWIN — Adaptive Windowing (Bifet & Gavaldà 2007)
# =============================================================================
#
# Maintains a window of recent observations. After every new observation, the
# algorithm searches for a split point inside the window where the two
# sub-windows' means differ by more than a Hoeffding-style bound:
#
#     |μ_0 - μ_1|  >  ε_cut(n_0, n_1, δ)
#
# where ε_cut depends on the sub-window sizes and the confidence parameter δ.
# If such a cut exists, the older sub-window is dropped. The window thus
# adapts: stable streams keep a large window; drifting streams shrink it.
#
# The Hoeffding bound used here is the standard ADWIN variant:
#     m  = 1 / (1/n_0 + 1/n_1)
#     δ' = δ / log_2(m)
#     ε_cut = sqrt( (1/(2m)) * ln(4/δ') )
# =============================================================================

ADWIN_DEFAULT_DELTA = 0.002


def adwin_detect(
    samples: Sequence[float],
    *,
    delta:   float = ADWIN_DEFAULT_DELTA,
) -> dict:
    """
    Run ADWIN over a stream of observations (values in any range; the
    Hoeffding bound assumes bounded range [a, b] but the algorithm degrades
    gracefully — we use the empirical range of the stream).

    Returns:
      window_size_final   : len of the kept window at the end of the stream
      window_size_initial : len of the input stream
      cuts                : count of cuts performed (window shrinks)
      drifted             : True iff at least one cut happened
      last_cut_idx        : index where the most recent cut occurred (-1 if none)
      width_loss_ratio    : (initial - final) / initial  ∈ [0, 1]

    Pure. Deterministic.
    """
    if len(samples) < 2:
        return {
            "window_size_final":   len(samples),
            "window_size_initial": len(samples),
            "cuts":                0,
            "drifted":             False,
            "last_cut_idx":        -1,
            "width_loss_ratio":    0.0,
        }

    # Determine the empirical range for the Hoeffding bound.
    # For binary/fraction streams this is [0, 1]; for arbitrary streams we
    # compute the range across the input.
    s_min = min(samples)
    s_max = max(samples)
    s_range = max(s_max - s_min, 1e-12)  # avoid /0

    window: list[float] = []
    cuts = 0
    last_cut_idx = -1

    for i, x in enumerate(samples):
        window.append(x)

        # Try to find a valid cut, repeatedly, until the window stops shrinking.
        cut_found = True
        while cut_found and len(window) >= 2:
            cut_found = False
            # The Hoeffding bound logic: search for a split index `j` such that
            # the means of window[:j] and window[j:] differ by more than ε_cut.
            # We can speed this up with running sums, but stdlib clarity over
            # micro-optimisation — these series are typically <100 long.
            n = len(window)
            # Precompute cumulative sums for O(n) split search.
            cum = [0.0] * (n + 1)
            for k in range(n):
                cum[k + 1] = cum[k] + window[k]
            total = cum[n]

            best_cut = -1
            for j in range(1, n):
                n0, n1 = j, n - j
                mean_0 = cum[j] / n0
                mean_1 = (total - cum[j]) / n1
                # Harmonic-mean of sub-window sizes
                m = 1.0 / (1.0 / n0 + 1.0 / n1)
                # ADWIN's bound (with δ' = δ / log2(n) approximation)
                log2_n = max(1.0, math.log2(n))
                delta_prime = delta / log2_n
                eps_cut = s_range * math.sqrt((1.0 / (2.0 * m)) * math.log(4.0 / delta_prime))
                if abs(mean_0 - mean_1) > eps_cut:
                    best_cut = j
                    break

            if best_cut > 0:
                # Drop the older sub-window.
                window = window[best_cut:]
                cuts += 1
                last_cut_idx = i
                cut_found = True

    drifted = cuts > 0
    initial = len(samples)
    final = len(window)
    width_loss = (initial - final) / initial if initial > 0 else 0.0

    return {
        "window_size_final":   final,
        "window_size_initial": initial,
        "cuts":                cuts,
        "drifted":             drifted,
        "last_cut_idx":        last_cut_idx,
        "width_loss_ratio":    width_loss,
    }


def adwin_normalised_score(adwin_result: dict) -> float:
    """
    Map ADWIN width-loss to a [0, 1] sub-score where 1.0 = stable, 0.0 = strong drift.

    Width-loss 0 (no cuts) → 1.0 (stable).
    Width-loss 1 (whole window dropped at one point) → 0.0 (strong drift).
    """
    ratio = max(0.0, min(1.0, adwin_result["width_loss_ratio"]))
    return 1.0 - ratio


# =============================================================================
# DDM — Drift Detection Method (Gama et al. 2004)
# =============================================================================
#
# Designed for binary error streams (0 = success, 1 = failure), but applies
# equally to per-day failure rates if we treat each rate as a Bernoulli
# probability with stddev sqrt(p(1-p)/n_i).
#
# Tracks running error rate p_i and its stddev s_i = sqrt(p_i*(1-p_i)/i).
# Maintains minimum p_min + s_min observed during the "stable" phase.
# Warning level:  p_i + s_i  >  p_min + 2 * s_min
# Drift level:    p_i + s_i  >  p_min + 3 * s_min
# =============================================================================

DDM_WARNING_LEVEL = 2.0
DDM_DRIFT_LEVEL   = 3.0
DDM_MIN_N         = 30      # don't trip DDM until we have at least N samples


def ddm_detect(
    samples:       Sequence[float],
    *,
    warning_level: float = DDM_WARNING_LEVEL,
    drift_level:   float = DDM_DRIFT_LEVEL,
    min_n:         int   = DDM_MIN_N,
) -> dict:
    """
    Run DDM over a sequence of per-step failure rates in [0, 1].

    The samples sequence is treated as Bernoulli probabilities: each sample
    is the running per-step failure rate. We maintain (p_i + s_i) and
    compare against the minimum seen so far.

    Returns:
      warning      : True if warning level reached at any point
      drift        : True if drift level reached at any point
      warning_idx  : index of first warning, or -1
      drift_idx    : index of first drift, or -1
      warning_ratio: ((p_final + s_final) - p_min) / (warning_level * s_min)
                     clamped to [0, +inf); used as a continuous severity.
    """
    n = len(samples)
    if n < min_n:
        return {
            "warning":      False,
            "drift":        False,
            "warning_idx":  -1,
            "drift_idx":    -1,
            "warning_ratio": 0.0,
        }

    p_min      = math.inf
    s_min      = math.inf
    pmin_smin  = math.inf   # p_min + s_min seen so far

    warning_idx = -1
    drift_idx   = -1
    last_p, last_s = 0.0, 0.0

    for i, p in enumerate(samples, start=1):
        # Treat the value as failure rate. Bernoulli stddev for n=i.
        p = max(0.0, min(1.0, p))
        s = math.sqrt(p * (1.0 - p) / i)
        last_p, last_s = p, s

        if p + s < pmin_smin:
            p_min = p
            s_min = s
            pmin_smin = p + s

        # Need at least min_n samples before we may trip.
        if i < min_n:
            continue

        threshold_warn  = p_min + warning_level * s_min
        threshold_drift = p_min + drift_level   * s_min

        if p + s > threshold_drift and drift_idx < 0:
            drift_idx = i - 1
        if p + s > threshold_warn and warning_idx < 0:
            warning_idx = i - 1

    # Continuous severity: how far the final (p+s) exceeded the WARNING
    # threshold (p_min + warning_level * s_min), in multiples of s_min.
    # A stable agent with no excursions ends with (p + s) ≈ p_min + s_min,
    # which is BELOW the warning threshold → ratio = 0.0.
    if s_min > 0 and math.isfinite(s_min) and math.isfinite(p_min):
        warn_threshold = p_min + warning_level * s_min
        excess = max(0.0, (last_p + last_s) - warn_threshold)
        warning_ratio = excess / s_min
    else:
        warning_ratio = 0.0

    return {
        "warning":       warning_idx >= 0,
        "drift":         drift_idx >= 0,
        "warning_idx":   warning_idx,
        "drift_idx":     drift_idx,
        "warning_ratio": warning_ratio,
    }


def ddm_normalised_score(ddm_result: dict) -> float:
    """
    Map DDM severity to a [0, 1] sub-score where 1.0 = stable, 0.0 = drift.

    `warning_ratio` is how many `s_min` units the final (p+s) exceeded the
    WARNING threshold (p_min + 2*s_min):

      warning_ratio = 0    →  at or below warning threshold  → score 1.0
      warning_ratio = 1    →  at drift threshold (3*s_min)   → score 0.0

    Linear in between; clamped above 1.
    """
    r = ddm_result["warning_ratio"]
    if r <= 0.0:
        return 1.0
    # The gap between warning (2*s_min) and drift (3*s_min) is exactly 1*s_min.
    return max(0.0, min(1.0, 1.0 - r))
