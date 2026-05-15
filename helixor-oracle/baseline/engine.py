"""
baseline/engine.py — Baseline Engine v2.

    compute_baseline(agent_wallet, transactions, window) -> BaselineStats

PURE. No I/O. Given the same inputs, produces a byte-identical BaselineStats
(and therefore a byte-identical stats_hash) on every machine.

HOW THE BASELINE IS BUILT
-------------------------
The MVP computed 3 scalar signals. V2 computes a per-feature mean + stddev
across all 100 dimensions — but "across" *what*? You can't take the stddev of
a single feature vector.

The answer: a baseline is built from a TIME SERIES of feature vectors.

  1. Partition the 30-day window into daily buckets.
  2. For each day that has >=1 transaction, run the Day-1 feature extractor
     over that day's transactions -> one FeatureVector per active day.
  3. The baseline's `feature_means[i]` is the mean of feature i across that
     sequence of daily vectors; `feature_stds[i]` is the stddev.

This is what gives the detectors something to measure against: "feature 47
today is 3.2 standard deviations above this agent's own 30-day daily mean."

DATA SUFFICIENCY
----------------
An agent with 3 transactions over 30 days has a degenerate baseline (mostly
zero daily vectors, near-zero stds). Below MIN_DAYS_WITH_ACTIVITY /
MIN_TRANSACTION_COUNT the baseline is still computed but flagged
`is_provisional=True`. Below an absolute floor it raises InsufficientDataError.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

from baseline import hashing
from baseline.types import (
    BASELINE_ALGO_VERSION,
    MIN_DAYS_WITH_ACTIVITY,
    MIN_TRANSACTION_COUNT,
    BaselineStats,
    InsufficientDataError,
)
from features import (
    FEATURE_SCHEMA_VERSION,
    TOTAL_FEATURES,
    ActionType,
    ExtractionWindow,
    FeatureVector,
    Transaction,
    extract,
)
from features import _stats as st


# Absolute floor: below this, not even a provisional baseline is meaningful.
ABSOLUTE_MIN_TRANSACTIONS = 1


def compute_baseline(
    agent_wallet: str,
    transactions: Sequence[Transaction],
    window:       ExtractionWindow,
    *,
    computed_at:  datetime | None = None,
) -> BaselineStats:
    """
    Compute the v2 BaselineStats for an agent over `window`.

    `computed_at` is injectable for deterministic tests; it defaults to the
    window end (NOT the wall clock — the engine never reads the system clock).
    `computed_at` does not affect the stats_hash.

    Raises InsufficientDataError if the agent has fewer than
    ABSOLUTE_MIN_TRANSACTIONS transactions in the window.
    """
    if computed_at is None:
        computed_at = window.end
    if computed_at.tzinfo is None:
        raise ValueError("computed_at must be timezone-aware UTC")

    # 1. Filter to window, sort canonically (same total order as the extractor).
    in_window = [t for t in transactions if window.contains(t.block_time)]
    txs = sorted(in_window, key=lambda t: (t.block_time, t.slot, t.signature))

    if len(txs) < ABSOLUTE_MIN_TRANSACTIONS:
        raise InsufficientDataError(
            f"agent {agent_wallet} has {len(txs)} transactions in window "
            f"(need >= {ABSOLUTE_MIN_TRANSACTIONS} for any baseline)"
        )

    # 2. Partition into daily buckets, build one FeatureVector per ACTIVE day.
    daily_vectors = _daily_feature_vectors(txs, window)
    days_with_activity = len(daily_vectors)

    # 3. Per-feature mean + stddev across the daily-vector series.
    feature_means, feature_stds = _aggregate_daily_vectors(daily_vectors)

    # 4. Scalar summary statistics over the full window.
    txtype_distribution = _txtype_distribution(txs)
    action_entropy      = _action_entropy(txs)
    success_rate_30d    = st.fraction(sum(1 for t in txs if t.success), len(txs))

    # 5. Data sufficiency.
    is_provisional = (
        days_with_activity < MIN_DAYS_WITH_ACTIVITY
        or len(txs) < MIN_TRANSACTION_COUNT
    )

    # 6. The commitment hash — over statistical content only.
    schema_fp = FeatureVector.feature_schema_fingerprint()
    from scoring.weights import scoring_schema_fingerprint
    scoring_fp = scoring_schema_fingerprint()
    stats_hash = hashing.compute_stats_hash(
        baseline_algo_version=BASELINE_ALGO_VERSION,
        feature_schema_fingerprint=schema_fp,
        feature_means=feature_means,
        feature_stds=feature_stds,
        txtype_distribution=txtype_distribution,
        action_entropy=action_entropy,
        success_rate_30d=success_rate_30d,
    )

    # 7. Construct the frozen, self-validating BaselineStats.
    return BaselineStats(
        agent_wallet=agent_wallet,
        baseline_algo_version=BASELINE_ALGO_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_schema_fingerprint=schema_fp,
        scoring_schema_fingerprint=scoring_fp,
        window_start=window.start,
        window_end=window.end,
        feature_means=feature_means,
        feature_stds=feature_stds,
        txtype_distribution=txtype_distribution,
        action_entropy=action_entropy,
        success_rate_30d=success_rate_30d,
        transaction_count=len(txs),
        days_with_activity=days_with_activity,
        is_provisional=is_provisional,
        computed_at=computed_at,
        stats_hash=stats_hash,
    )


# =============================================================================
# Daily feature-vector series
# =============================================================================

def _daily_feature_vectors(
    txs:    list[Transaction],
    window: ExtractionWindow,
) -> list[FeatureVector]:
    """
    Partition `txs` into calendar-day buckets and extract one FeatureVector
    per ACTIVE day (days with zero transactions are NOT zero-filled — a
    no-activity day is not part of the agent's behavioural rhythm).

    Returned in chronological order of the day. Each day's FeatureVector is
    extracted over a 1-day ExtractionWindow so the extractor's window-relative
    features (success_rate_1d etc.) are computed correctly for that day.
    """
    by_day: dict[str, list[Transaction]] = {}
    for t in txs:
        day_key = t.block_time.strftime("%Y-%m-%d")
        by_day.setdefault(day_key, []).append(t)

    vectors: list[FeatureVector] = []
    for day_key in sorted(by_day):
        day_txs = by_day[day_key]
        # The day's window: [day 00:00 UTC, day 23:59:59.999999 UTC].
        day_start = datetime.strptime(day_key, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        day_end   = day_start + timedelta(days=1) - timedelta(microseconds=1)
        day_window = ExtractionWindow(start=day_start, end=day_end)
        vectors.append(extract(day_txs, day_window))

    return vectors


def _aggregate_daily_vectors(
    daily_vectors: list[FeatureVector],
) -> tuple[tuple[float, ...], tuple[float, ...]]:
    """
    Compute per-feature mean + population stddev across the daily-vector series.

    Returns (means, stds), each a 100-tuple in canonical feature order.

    Edge cases:
      - empty series  -> all-zero means + stds (shouldn't happen given the
        ABSOLUTE_MIN_TRANSACTIONS gate, but defended anyway)
      - single day    -> means = that day's vector, stds = all zeros
    """
    if not daily_vectors:
        zeros = tuple(0.0 for _ in range(TOTAL_FEATURES))
        return zeros, zeros

    # Transpose: collect each feature's value across all days.
    # daily_vectors[d].to_list()[i] -> column i is feature i's daily series.
    columns: list[list[float]] = [[] for _ in range(TOTAL_FEATURES)]
    for fv in daily_vectors:
        values = fv.to_list()
        for i in range(TOTAL_FEATURES):
            columns[i].append(values[i])

    means = tuple(st.mean(col) for col in columns)
    stds  = tuple(st.stddev(col, population=True) for col in columns)
    return means, stds


# =============================================================================
# Scalar summary statistics
# =============================================================================

def _txtype_distribution(txs: list[Transaction]) -> tuple[float, ...]:
    """
    Fraction of transactions in each action class, in canonical ActionType
    order (swap, lend, stake, transfer, other). Sums to ~1.0 (or all-zero if
    empty, which the caller's gate prevents).
    """
    n = len(txs)
    counts = Counter(t.primary_action for t in txs)
    return tuple(
        st.fraction(counts[action], n)
        for action in ActionType.ordered()
    )


def _action_entropy(txs: list[Transaction]) -> float:
    """
    Normalised Shannon entropy of the agent's action-type distribution.
    1.0 = perfectly diverse across the 5 action classes; 0.0 = single class.
    """
    counts = Counter(t.primary_action for t in txs)
    return st.shannon_entropy(
        [float(counts[a]) for a in ActionType.ordered()],
        normalised=True,
    )
