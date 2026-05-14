"""
features/extractor.py — the feature extraction entry point.

    extract(transactions, window) -> FeatureVector

PURE. No I/O, no network, no disk, no system clock. Given the same
(transactions, window), every call on every machine returns a byte-identical
FeatureVector. This determinism is load-bearing: in Phase 4 three oracle
nodes must independently compute identical vectors or consensus fails.

Structure: one private function per feature group, each returning a dict of
{field_name: value}. extract() filters transactions to the window, runs all
nine group computers, merges, and constructs the frozen FeatureVector (whose
__post_init__ asserts 100 finite floats).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import timedelta

from features import _stats as st
from features.types import ActionType, ExtractionWindow, Transaction, classify_program
from features.vector import FeatureVector


# =============================================================================
# Entry point
# =============================================================================

def extract(
    transactions: Sequence[Transaction],
    window:       ExtractionWindow,
) -> FeatureVector:
    """
    Extract the 100-dimensional FeatureVector for `transactions` over `window`.

    Transactions outside the window are ignored. Transactions are processed in
    canonical order: sorted by (block_time, slot, signature) so ties are total
    and deterministic.

    An empty window (no transactions in range) returns FeatureVector.zeros() —
    a valid all-zero 100-dim vector.
    """
    # 1. Filter to window + sort canonically. This is the ONLY ordering used
    #    anywhere downstream; every group computer relies on it.
    in_window = [t for t in transactions if window.contains(t.block_time)]
    txs = sorted(in_window, key=lambda t: (t.block_time, t.slot, t.signature))

    if not txs:
        return FeatureVector.zeros()

    # 2. Run all nine group computers.
    values: dict[str, float] = {}
    values.update(_group_txtype(txs))
    values.update(_group_success(txs, window))
    values.update(_group_counterparty(txs, window))
    values.update(_group_fees(txs))
    values.update(_group_rhythm(txs, window))
    values.update(_group_timing(txs))
    values.update(_group_solflow(txs))
    values.update(_group_sequence(txs))
    values.update(_group_programs(txs, window))

    # 3. Construct. FeatureVector.__post_init__ asserts exactly 100 finite floats.
    return FeatureVector(**values)


# =============================================================================
# Group 1 — transaction-type distribution (5 features)
# =============================================================================

def _group_txtype(txs: list[Transaction]) -> dict[str, float]:
    n = len(txs)
    counts = Counter(t.primary_action for t in txs)
    return {
        "txtype_swap_frac":     st.fraction(counts[ActionType.SWAP], n),
        "txtype_lend_frac":     st.fraction(counts[ActionType.LEND], n),
        "txtype_stake_frac":    st.fraction(counts[ActionType.STAKE], n),
        "txtype_transfer_frac": st.fraction(counts[ActionType.TRANSFER], n),
        "txtype_other_frac":    st.fraction(counts[ActionType.OTHER], n),
    }


# =============================================================================
# Group 2 — success-rate windows + slopes (12 features)
# =============================================================================

def _group_success(txs: list[Transaction], window: ExtractionWindow) -> dict[str, float]:
    end = window.end

    def in_last(days: float) -> list[Transaction]:
        cutoff = end - timedelta(days=days)
        return [t for t in txs if t.block_time >= cutoff]

    txs_1d, txs_7d, txs_30d = in_last(1), in_last(7), in_last(30)

    def rate(group: list[Transaction]) -> float:
        if not group:
            return 0.0
        return st.fraction(sum(1 for t in group if t.success), len(group))

    # Per-day success-rate series over the window, for slope + volatility.
    daily_rates = _daily_success_rates(txs, window)
    rates_7d  = daily_rates[-7:]  if len(daily_rates) >= 1 else []
    rates_30d = daily_rates

    # Failure streaks (over the canonical-ordered tx list).
    max_streak, cur_streak = _failure_streaks(txs)

    return {
        "success_rate_1d":          rate(txs_1d),
        "success_rate_7d":          rate(txs_7d),
        "success_rate_30d":         rate(txs_30d),
        "success_rate_overall":     rate(txs),
        "success_count_1d":         float(sum(1 for t in txs_1d  if t.success)),
        "success_count_7d":         float(sum(1 for t in txs_7d  if t.success)),
        "success_count_30d":        float(sum(1 for t in txs_30d if t.success)),
        "success_slope_7d":         st.linear_slope(rates_7d),
        "success_slope_30d":        st.linear_slope(rates_30d),
        "success_volatility":       st.stddev(daily_rates),
        "failure_streak_max":       float(max_streak),
        "failure_streak_current":   float(cur_streak),
    }


def _daily_success_rates(txs: list[Transaction], window: ExtractionWindow) -> list[float]:
    """
    Success rate per calendar day across the window. Days with no transactions
    are omitted (not zero-filled) — a no-activity day is not a 0% success day.
    Returned in chronological order.
    """
    by_day: dict[str, list[bool]] = {}
    for t in txs:
        key = t.block_time.strftime("%Y-%m-%d")
        by_day.setdefault(key, []).append(t.success)
    return [
        st.fraction(sum(1 for s in by_day[day] if s), len(by_day[day]))
        for day in sorted(by_day)
    ]


def _failure_streaks(txs: list[Transaction]) -> tuple[int, int]:
    """(longest consecutive-failure run, current run at the end). txs in order."""
    max_run = cur_run = 0
    for t in txs:
        if not t.success:
            cur_run += 1
            max_run = max(max_run, cur_run)
        else:
            cur_run = 0
    return max_run, cur_run


# =============================================================================
# Group 3 — counterparty diversity (11 features)
# =============================================================================

def _group_counterparty(txs: list[Transaction], window: ExtractionWindow) -> dict[str, float]:
    with_cp = [t for t in txs if t.counterparty is not None]
    n_total = len(txs)
    n_with_cp = len(with_cp)

    cp_counts = Counter(t.counterparty for t in with_cp)
    cp_volume: dict[str, int] = {}
    for t in with_cp:
        cp_volume[t.counterparty] = cp_volume.get(t.counterparty, 0) + abs(t.sol_change)

    counts_list = list(cp_counts.values())

    # Repeat ratio: fraction of cp-bearing txs whose counterparty had been seen
    # before (in canonical order).
    seen: set[str] = set()
    repeats = 0
    for t in with_cp:
        if t.counterparty in seen:
            repeats += 1
        seen.add(t.counterparty)

    # New counterparties appearing in the last 7 days of the window.
    cutoff_7d = window.end - timedelta(days=7)
    seen_before_7d = {t.counterparty for t in with_cp if t.block_time < cutoff_7d}
    new_in_7d = {
        t.counterparty for t in with_cp
        if t.block_time >= cutoff_7d and t.counterparty not in seen_before_7d
    }

    total_volume = sum(cp_volume.values())
    max_volume = max(cp_volume.values()) if cp_volume else 0

    return {
        "cp_unique_count":           float(len(cp_counts)),
        "cp_unique_ratio":           st.fraction(len(cp_counts), n_with_cp),
        "cp_concentration_top1":     st.top_k_concentration(counts_list, 1),
        "cp_concentration_top3":     st.top_k_concentration(counts_list, 3),
        "cp_concentration_top5":     st.top_k_concentration(counts_list, 5),
        "cp_herfindahl":             st.herfindahl_index(counts_list),
        "cp_repeat_ratio":           st.fraction(repeats, n_with_cp),
        "cp_entropy":                st.shannon_entropy(counts_list, normalised=True),
        "cp_new_rate_7d":            st.fraction(len(new_in_7d), n_with_cp),
        "cp_txs_with_cp_frac":       st.fraction(n_with_cp, n_total),
        "cp_max_single_volume_frac": st.fraction(max_volume, total_volume),
    }


# =============================================================================
# Group 4 — fee & compute patterns (13 features)
# =============================================================================

def _group_fees(txs: list[Transaction]) -> dict[str, float]:
    fees     = [float(t.fee) for t in txs]
    with_pri = [t for t in txs if t.priority_fee > 0]
    pri_fees = [float(t.priority_fee) for t in with_pri]
    compute  = [float(t.compute_units) for t in txs if t.compute_units > 0]

    # fee-per-compute, only for txs that report compute units
    fee_per_compute = [
        st.safe_div(float(t.fee), float(t.compute_units))
        for t in txs if t.compute_units > 0
    ]

    return {
        "fee_mean":                st.mean(fees),
        "fee_stddev":              st.stddev(fees),
        "fee_median":              st.median(fees),
        "fee_p90":                 st.percentile(fees, 90),
        "fee_p99":                 st.percentile(fees, 99),
        "fee_max":                 float(max(fees)) if fees else 0.0,
        "fee_min":                 float(min(fees)) if fees else 0.0,
        "fee_cv":                  st.coefficient_of_variation(fees),
        "priority_fee_usage_frac": st.fraction(len(with_pri), len(txs)),
        "priority_fee_mean":       st.mean(pri_fees),
        "compute_units_mean":      st.mean(compute),
        "compute_units_stddev":    st.stddev(compute),
        "fee_per_compute_mean":    st.mean(fee_per_compute),
    }


# =============================================================================
# Group 5 — time-of-day / day-of-week rhythm (13 features)
# =============================================================================

def _group_rhythm(txs: list[Transaction], window: ExtractionWindow) -> dict[str, float]:
    n = len(txs)
    hours = [t.block_time.hour for t in txs]                 # 0-23
    dows  = [t.block_time.weekday() for t in txs]            # 0=Mon .. 6=Sun

    hour_hist = [0.0] * 24
    for h in hours:
        hour_hist[h] += 1
    dow_hist = [0.0] * 7
    for d in dows:
        dow_hist[d] += 1

    peak_hour_count = max(hour_hist) if hour_hist else 0.0
    peak_hour_idx   = hour_hist.index(peak_hour_count) if n else 0
    peak_dow_count  = max(dow_hist) if dow_hist else 0.0

    weekend = sum(1 for d in dows if d >= 5)
    business = sum(1 for h in hours if 13 <= h < 21)         # 13:00-21:00 UTC band
    night    = sum(1 for h in hours if 0 <= h < 6)           # 00:00-06:00 UTC

    active_hours = sum(1 for c in hour_hist if c > 0)

    # Per-calendar-day transaction counts → regularity.
    by_day: dict[str, int] = {}
    for t in txs:
        key = t.block_time.strftime("%Y-%m-%d")
        by_day[key] = by_day.get(key, 0) + 1
    day_counts = list(by_day.values())
    active_days = len(day_counts)

    # Burst hours: hours whose load exceeded 2x the mean hourly load.
    mean_hour_load = st.mean([c for c in hour_hist if c > 0])
    burst_threshold = 2.0 * mean_hour_load
    burst_txs = sum(c for c in hour_hist if c > burst_threshold)

    # Regularity: 1 - normalised stddev of per-day counts (1.0 = perfectly even).
    day_cv = st.coefficient_of_variation(day_counts)
    regularity = st.clamp(1.0 - day_cv, 0.0, 1.0)

    return {
        "rhythm_hour_entropy":        st.shannon_entropy(hour_hist, normalised=True),
        "rhythm_hour_peak_frac":      st.fraction(peak_hour_count, n),
        "rhythm_hour_peak_idx":       st.safe_div(float(peak_hour_idx), 23.0),
        "rhythm_dow_entropy":         st.shannon_entropy(dow_hist, normalised=True),
        "rhythm_dow_peak_frac":       st.fraction(peak_dow_count, n),
        "rhythm_weekend_frac":        st.fraction(weekend, n),
        "rhythm_business_hours_frac": st.fraction(business, n),
        "rhythm_night_frac":          st.fraction(night, n),
        "rhythm_active_hours_count":  st.safe_div(float(active_hours), 24.0),
        "rhythm_active_days_count":   float(active_days),
        "rhythm_active_days_ratio":   st.fraction(active_days, max(window.duration_days, 1.0)),
        "rhythm_burst_hour_frac":     st.fraction(burst_txs, n),
        "rhythm_regularity_score":    regularity,
    }


# =============================================================================
# Group 6 — inter-transaction timing (11 features)
# =============================================================================

def _group_timing(txs: list[Transaction]) -> dict[str, float]:
    # txs already in canonical chronological order.
    if len(txs) < 2:
        # A single transaction has no inter-tx gaps. All timing features 0.
        return {
            "timing_gap_mean_s":         0.0,
            "timing_gap_median_s":       0.0,
            "timing_gap_stddev_s":       0.0,
            "timing_gap_min_s":          0.0,
            "timing_gap_max_s":          0.0,
            "timing_gap_cv":             0.0,
            "timing_burstiness":         0.0,
            "timing_rapid_fire_frac":    0.0,
            "timing_idle_gap_frac":      0.0,
            "timing_txs_per_active_day": float(len(txs)),
            "timing_longest_idle_s":     0.0,
        }

    gaps = [
        (txs[i].block_time - txs[i - 1].block_time).total_seconds()
        for i in range(1, len(txs))
    ]
    # Clamp negatives to 0 — same-slot ordering ties can produce 0; never negative.
    gaps = [max(0.0, g) for g in gaps]

    rapid_fire = sum(1 for g in gaps if g < 5.0)
    idle_gaps  = sum(1 for g in gaps if g > 3600.0)

    by_day: dict[str, int] = {}
    for t in txs:
        key = t.block_time.strftime("%Y-%m-%d")
        by_day[key] = by_day.get(key, 0) + 1

    return {
        "timing_gap_mean_s":         st.mean(gaps),
        "timing_gap_median_s":       st.median(gaps),
        "timing_gap_stddev_s":       st.stddev(gaps),
        "timing_gap_min_s":          float(min(gaps)),
        "timing_gap_max_s":          float(max(gaps)),
        "timing_gap_cv":             st.coefficient_of_variation(gaps),
        "timing_burstiness":         st.burstiness(gaps),
        "timing_rapid_fire_frac":    st.fraction(rapid_fire, len(gaps)),
        "timing_idle_gap_frac":      st.fraction(idle_gaps, len(gaps)),
        "timing_txs_per_active_day": st.mean([float(c) for c in by_day.values()]),
        "timing_longest_idle_s":     float(max(gaps)),
    }


# =============================================================================
# Group 7 — SOL-flow statistics (12 features)
# =============================================================================

def _group_solflow(txs: list[Transaction]) -> dict[str, float]:
    changes  = [float(t.sol_change) for t in txs]
    inflows  = [c for c in changes if c > 0]
    outflows = [-c for c in changes if c < 0]          # stored as positive magnitudes

    # sum() over an empty list returns int 0 — wrap in float() so every
    # feature is strictly a float (FeatureVector.__post_init__ enforces this).
    total_in  = float(sum(inflows))
    total_out = float(sum(outflows))
    abs_changes = [abs(c) for c in changes]

    mad = st.median_absolute_deviation(changes)
    mean_abs = st.mean(abs_changes)

    return {
        "solflow_total_in":        total_in,
        "solflow_total_out":       total_out,
        "solflow_net":             total_in - total_out,
        "solflow_in_out_ratio":    st.safe_div(total_in, total_out + 1.0),
        "solflow_mean_change":     st.mean(changes),
        "solflow_stddev_change":   st.stddev(changes),
        "solflow_mad":             mad,
        "solflow_max_inflow":      float(max(inflows))  if inflows  else 0.0,
        "solflow_max_outflow":     float(max(outflows)) if outflows else 0.0,
        "solflow_volatility_norm": st.safe_div(mad, mean_abs),
        "solflow_positive_frac":   st.fraction(len(inflows), len(txs)),
        "solflow_zero_frac":       st.fraction(sum(1 for c in changes if c == 0.0), len(txs)),
    }


# =============================================================================
# Group 8 — tool-invocation n-gram features (14 features)
# =============================================================================

def _group_sequence(txs: list[Transaction]) -> dict[str, float]:
    # The action sequence — one ActionType per transaction, canonical order.
    actions = [t.primary_action for t in txs]
    n = len(actions)

    action_counts = Counter(actions)
    dominant_count = max(action_counts.values()) if action_counts else 0

    # Bigrams + trigrams over the action alphabet.
    bigrams  = [(actions[i], actions[i + 1]) for i in range(n - 1)]
    trigrams = [(actions[i], actions[i + 1], actions[i + 2]) for i in range(n - 2)]
    bigram_counts  = Counter(bigrams)
    trigram_counts = Counter(trigrams)

    # Self-transitions (X -> X) and consecutive identical actions.
    self_trans = sum(1 for a, b in bigrams if a == b)
    repeat_actions = self_trans   # same definition: consecutive identical

    # Longest run of an identical action.
    longest_run = _longest_identical_run(actions)

    # Programs-per-transaction stats.
    prog_counts = [len(t.program_ids) for t in txs]
    multi_prog  = sum(1 for c in prog_counts if c > 1)

    top_bigram_count  = max(bigram_counts.values())  if bigram_counts  else 0
    top_trigram_count = max(trigram_counts.values()) if trigram_counts else 0

    return {
        "seq_action_entropy":       st.shannon_entropy(list(action_counts.values()), normalised=True),
        "seq_unique_bigrams":       st.safe_div(float(len(bigram_counts)), 25.0),    # 5x5 alphabet
        "seq_unique_trigrams":      st.safe_div(float(len(trigram_counts)), 125.0),  # 5x5x5
        "seq_bigram_concentration": st.fraction(top_bigram_count, len(bigrams)),
        "seq_trigram_concentration":st.fraction(top_trigram_count, len(trigrams)),
        "seq_repeat_action_frac":   st.fraction(repeat_actions, len(bigrams)),
        "seq_bigram_entropy":       st.shannon_entropy(list(bigram_counts.values()), normalised=True),
        "seq_trigram_entropy":      st.shannon_entropy(list(trigram_counts.values()), normalised=True),
        "seq_self_transition_frac": st.fraction(self_trans, len(bigrams)),
        "seq_dominant_action_frac": st.fraction(dominant_count, n),
        "seq_program_count_mean":   st.mean([float(c) for c in prog_counts]),
        "seq_program_count_max":    float(max(prog_counts)) if prog_counts else 0.0,
        "seq_multi_program_frac":   st.fraction(multi_prog, n),
        "seq_longest_repeat_run":   float(longest_run),
    }


def _longest_identical_run(actions: list[ActionType]) -> int:
    """Longest run of the same action consecutively."""
    if not actions:
        return 0
    longest = run = 1
    for i in range(1, len(actions)):
        if actions[i] == actions[i - 1]:
            run += 1
            longest = max(longest, run)
        else:
            run = 1
    return longest


# =============================================================================
# Group 9 — program-interaction diversity (9 features)
# =============================================================================

def _group_programs(txs: list[Transaction], window: ExtractionWindow) -> dict[str, float]:
    # Flatten all program invocations across all transactions, canonical order.
    all_invocations: list[str] = []
    for t in txs:
        all_invocations.extend(t.program_ids)

    total_invocations = len(all_invocations)
    prog_counts = Counter(all_invocations)
    counts_list = list(prog_counts.values())

    # Known = present in the program→action map (i.e. classify != OTHER, OR
    # explicitly mapped to OTHER is still "known"; here we treat "known" as
    # "appears in the explicit map at all").
    from features.types import _PROGRAM_ACTION_MAP
    known = sum(1 for p in all_invocations if p in _PROGRAM_ACTION_MAP)

    # New programs in the last 7 days of the window.
    cutoff_7d = window.end - timedelta(days=7)
    progs_before_7d: set[str] = set()
    progs_new_7d: set[str] = set()
    for t in txs:
        for p in t.program_ids:
            if t.block_time < cutoff_7d:
                progs_before_7d.add(p)
    for t in txs:
        for p in t.program_ids:
            if t.block_time >= cutoff_7d and p not in progs_before_7d:
                progs_new_7d.add(p)

    return {
        "prog_unique_count":       float(len(prog_counts)),
        "prog_unique_ratio":       st.fraction(len(prog_counts), total_invocations),
        "prog_concentration_top1": st.top_k_concentration(counts_list, 1),
        "prog_concentration_top3": st.top_k_concentration(counts_list, 3),
        "prog_herfindahl":         st.herfindahl_index(counts_list),
        "prog_entropy":            st.shannon_entropy(counts_list, normalised=True),
        "prog_known_frac":         st.fraction(known, total_invocations),
        "prog_invocations_per_tx": st.safe_div(float(total_invocations), float(len(txs))),
        "prog_new_rate_7d":        st.fraction(len(progs_new_7d), len(prog_counts)),
    }
