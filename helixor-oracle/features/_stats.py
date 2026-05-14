"""
features/_stats.py — pure statistical primitives for feature extraction.

Every function here is TOTAL: it returns a finite float for ALL inputs,
including empty sequences, single elements, and zero-variance data. This is
the foundation of the FeatureVector's "no NaN, no inf" guarantee.

No numpy dependency — these run inside the oracle hot path and per-feature
clarity matters more than vectorisation at this scale (hundreds of txs).
"""

from __future__ import annotations

import math
from collections.abc import Sequence


EPS = 1e-12


def safe_div(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Division that returns `default` instead of raising / producing inf."""
    if abs(denominator) < EPS:
        return default
    result = numerator / denominator
    return result if math.isfinite(result) else default


def mean(values: Sequence[float]) -> float:
    """Arithmetic mean. Empty → 0.0."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def stddev(values: Sequence[float], population: bool = True) -> float:
    """
    Standard deviation. Empty or single element → 0.0.
    `population=True` uses N; False uses N-1 (sample). N<2 sample → 0.0.
    """
    n = len(values)
    if n < 2:
        return 0.0
    mu = mean(values)
    sq = sum((v - mu) ** 2 for v in values)
    denom = n if population else n - 1
    var = sq / denom
    return math.sqrt(var) if var > 0 else 0.0


def coefficient_of_variation(values: Sequence[float]) -> float:
    """stddev / mean. Zero mean → 0.0. Always finite."""
    mu = mean(values)
    if abs(mu) < EPS:
        return 0.0
    return safe_div(stddev(values), abs(mu))


def median(values: Sequence[float]) -> float:
    """Median. Empty → 0.0."""
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2 == 1:
        return float(s[mid])
    return (s[mid - 1] + s[mid]) / 2.0


def percentile(values: Sequence[float], q: float) -> float:
    """
    The q-th percentile (q in [0,100]), linear interpolation.
    Empty → 0.0. Single element → that element.
    """
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    s = sorted(values)
    rank = (q / 100.0) * (len(s) - 1)
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return float(s[int(rank)])
    frac = rank - lo
    return s[lo] * (1 - frac) + s[hi] * frac


def median_absolute_deviation(values: Sequence[float]) -> float:
    """
    MAD = median(|x - median(x)|). Robust dispersion measure.
    Empty / single → 0.0.
    """
    if len(values) < 2:
        return 0.0
    med = median(values)
    return median([abs(v - med) for v in values])


def shannon_entropy(counts: Sequence[float], normalised: bool = True) -> float:
    """
    Shannon entropy of a distribution given raw counts.

    `normalised=True` divides by log2(k) so the result is in [0, 1] regardless
    of the number of categories k — this makes entropy features comparable
    across agents with different category counts.

    Empty / all-zero / single-category → 0.0.
    """
    total = sum(counts)
    if total < EPS:
        return 0.0
    probs = [c / total for c in counts if c > 0]
    if len(probs) <= 1:
        return 0.0
    h = -sum(p * math.log2(p) for p in probs)
    if not normalised:
        return h if math.isfinite(h) else 0.0
    max_h = math.log2(len(probs))
    return safe_div(h, max_h)


def herfindahl_index(counts: Sequence[float]) -> float:
    """
    Herfindahl-Hirschman Index: sum of squared shares. In [0, 1].
    1.0 = perfectly concentrated, → 0 = perfectly diffuse.
    Empty / all-zero → 0.0.
    """
    total = sum(counts)
    if total < EPS:
        return 0.0
    return sum((c / total) ** 2 for c in counts)


def top_k_concentration(counts: Sequence[float], k: int) -> float:
    """
    Fraction of the total held by the top-k largest categories.
    In [0, 1]. Empty → 0.0. k larger than #categories → 1.0 (if any data).
    """
    total = sum(counts)
    if total < EPS:
        return 0.0
    top = sorted(counts, reverse=True)[:k]
    return safe_div(sum(top), total)


def linear_slope(values: Sequence[float]) -> float:
    """
    Least-squares slope of `values` against their index 0..n-1.
    Interpreted as "units of change per step".

    Empty / single element / zero x-variance → 0.0.
    """
    n = len(values)
    if n < 2:
        return 0.0
    xs = list(range(n))
    x_mean = mean([float(x) for x in xs])
    y_mean = mean(values)
    num = sum((xs[i] - x_mean) * (values[i] - y_mean) for i in range(n))
    den = sum((xs[i] - x_mean) ** 2 for i in range(n))
    return safe_div(num, den)


def burstiness(values: Sequence[float]) -> float:
    """
    Goh-Barabasi burstiness coefficient: (sigma - mu) / (sigma + mu).
    In [-1, 1]: -1 = perfectly periodic, 0 = Poisson, +1 = extremely bursty.
    Empty / single / zero mean+stddev → 0.0.

    A single value has no inter-event structure, so burstiness is undefined —
    we return 0.0 (the neutral Poisson value) rather than the degenerate -1.0
    that the raw formula would produce (stddev=0 → (0-mu)/(0+mu) = -1).
    """
    if len(values) < 2:
        return 0.0
    mu = mean(values)
    sigma = stddev(values)
    denom = sigma + mu
    if abs(denom) < EPS:
        return 0.0
    return safe_div(sigma - mu, denom)


def clamp(value: float, lo: float, hi: float) -> float:
    """Clamp to [lo, hi]. Non-finite → lo."""
    if not math.isfinite(value):
        return lo
    return max(lo, min(hi, value))


def fraction(numerator: float, denominator: float) -> float:
    """A fraction guaranteed to land in [0, 1]. Zero denom → 0.0."""
    return clamp(safe_div(numerator, denominator), 0.0, 1.0)
