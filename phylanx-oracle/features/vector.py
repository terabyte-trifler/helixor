"""
features/vector.py — the FeatureVector: exactly 100 named, frozen, finite floats.

CONTRACT
--------
1. EXACTLY 100 features. Not "~100". The count is asserted at construction.
2. Field ORDER is frozen forever. Position N is always the same feature.
   Changing the order or set of features is a FEATURE_SCHEMA_VERSION bump.
3. Every feature is a FINITE float. No NaN, no inf — asserted at construction.
   Degenerate inputs (empty window, single tx, zero variance) resolve to
   documented defaults, never to NaN.
4. The vector is immutable (frozen dataclass).
5. The vector carries its own schema version + can fingerprint its schema,
   so the baseline engine can detect drift.

The 100 features are organised into 9 groups. Each group's size is FIXED:

    txtype           5    transaction-type distribution
    success         12    success-rate windows + slopes
    counterparty    11    counterparty diversity
    fees            13    fee & compute patterns
    rhythm          13    time-of-day / day-of-week rhythm
    timing          11    inter-transaction timing
    solflow         12    SOL-flow statistics
    sequence        14    tool-invocation n-gram features
    programs        09    program-interaction diversity
    --------------------
    TOTAL          100
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import astuple, dataclass, fields


FEATURE_SCHEMA_VERSION = 1


# =============================================================================
# Group sizes — FROZEN. These sum to exactly 100.
# =============================================================================

GROUP_SIZES: dict[str, int] = {
    "txtype":       5,
    "success":     12,
    "counterparty":11,
    "fees":        13,
    "rhythm":      13,
    "timing":      11,
    "solflow":     12,
    "sequence":    14,
    "programs":     9,
}

TOTAL_FEATURES = sum(GROUP_SIZES.values())
assert TOTAL_FEATURES == 100, f"group sizes must sum to 100, got {TOTAL_FEATURES}"


# =============================================================================
# FeatureVector — the frozen output.
#
# Field order below IS the canonical feature order. Do not reorder.
# The names follow {group}_{description} so the group is always recoverable.
# =============================================================================

@dataclass(frozen=True, slots=True)
class FeatureVector:
    # ─── Group 1: transaction-type distribution (5) ──────────────────────────
    # Fraction of transactions in each action class. Sums to ~1.0 (or 0 if empty).
    txtype_swap_frac:            float
    txtype_lend_frac:            float
    txtype_stake_frac:           float
    txtype_transfer_frac:        float
    txtype_other_frac:           float

    # ─── Group 2: success-rate windows + slopes (12) ─────────────────────────
    success_rate_1d:             float   # success fraction, last 1 day of window
    success_rate_7d:             float   # success fraction, last 7 days
    success_rate_30d:            float   # success fraction, full 30-day window
    success_rate_overall:        float   # success fraction, all txs in window
    success_count_1d:            float   # count of successes last 1d (raw)
    success_count_7d:            float
    success_count_30d:           float
    success_slope_7d:            float   # linear slope of daily success rate, 7d
    success_slope_30d:           float   # linear slope of daily success rate, 30d
    success_volatility:          float   # stddev of daily success rates
    failure_streak_max:          float   # longest consecutive-failure run
    failure_streak_current:      float   # current consecutive-failure run at window end

    # ─── Group 3: counterparty diversity (11) ────────────────────────────────
    cp_unique_count:             float   # distinct counterparties
    cp_unique_ratio:             float   # distinct / total txs with a counterparty
    cp_concentration_top1:       float   # fraction of txs to the single top counterparty
    cp_concentration_top3:       float   # fraction to top 3
    cp_concentration_top5:       float   # fraction to top 5
    cp_herfindahl:               float   # Herfindahl-Hirschman index of cp distribution
    cp_repeat_ratio:             float   # fraction of txs to a previously-seen cp
    cp_entropy:                  float   # Shannon entropy of cp distribution (normalised)
    cp_new_rate_7d:              float   # rate of new counterparties appearing, last 7d
    cp_txs_with_cp_frac:         float   # fraction of txs that HAVE a clear counterparty
    cp_max_single_volume_frac:   float   # fraction of SOL volume to the top cp

    # ─── Group 4: fee & compute patterns (13) ────────────────────────────────
    fee_mean:                    float   # mean fee (lamports)
    fee_stddev:                  float
    fee_median:                  float
    fee_p90:                     float
    fee_p99:                     float
    fee_max:                     float
    fee_min:                     float
    fee_cv:                      float   # coefficient of variation (stddev/mean)
    priority_fee_usage_frac:     float   # fraction of txs with priority_fee > 0
    priority_fee_mean:           float   # mean priority fee among txs that set one
    compute_units_mean:          float
    compute_units_stddev:        float
    fee_per_compute_mean:        float   # mean fee / compute_units ratio

    # ─── Group 5: time-of-day / day-of-week rhythm (13) ──────────────────────
    rhythm_hour_entropy:         float   # Shannon entropy of hour-of-day histogram (norm)
    rhythm_hour_peak_frac:       float   # fraction of txs in the single busiest hour
    rhythm_hour_peak_idx:        float   # which hour is busiest (0-23), normalised /23
    rhythm_dow_entropy:          float   # Shannon entropy of day-of-week histogram (norm)
    rhythm_dow_peak_frac:        float   # fraction in the single busiest weekday
    rhythm_weekend_frac:         float   # fraction of txs on Sat/Sun
    rhythm_business_hours_frac:  float   # fraction in 13:00-21:00 UTC ("business" band)
    rhythm_night_frac:           float   # fraction in 00:00-06:00 UTC
    rhythm_active_hours_count:   float   # count of distinct hours-of-day with >=1 tx /24
    rhythm_active_days_count:    float   # count of distinct calendar days with >=1 tx
    rhythm_active_days_ratio:    float   # active days / window duration days
    rhythm_burst_hour_frac:      float   # fraction of txs in hours that had >2x mean load
    rhythm_regularity_score:     float   # 1 - normalised stddev of per-day tx counts

    # ─── Group 6: inter-transaction timing (11) ──────────────────────────────
    timing_gap_mean_s:           float   # mean seconds between consecutive txs
    timing_gap_median_s:         float
    timing_gap_stddev_s:         float
    timing_gap_min_s:            float
    timing_gap_max_s:            float
    timing_gap_cv:               float   # coefficient of variation of gaps
    timing_burstiness:           float   # (stddev-mean)/(stddev+mean), Goh-Barabasi
    timing_rapid_fire_frac:      float   # fraction of gaps < 5 seconds
    timing_idle_gap_frac:        float   # fraction of gaps > 1 hour
    timing_txs_per_active_day:   float   # mean txs on days that had any activity
    timing_longest_idle_s:       float   # longest gap with no transactions

    # ─── Group 7: SOL-flow statistics (12) ───────────────────────────────────
    solflow_total_in:            float   # total lamports inflow
    solflow_total_out:           float   # total lamports outflow (abs)
    solflow_net:                 float   # net flow (in - out)
    solflow_in_out_ratio:        float   # in / (out + eps)
    solflow_mean_change:         float   # mean per-tx sol_change
    solflow_stddev_change:       float
    solflow_mad:                 float   # median absolute deviation of sol_change
    solflow_max_inflow:          float   # largest single inflow
    solflow_max_outflow:         float   # largest single outflow (abs)
    solflow_volatility_norm:     float   # MAD / mean-abs-change, normalised
    solflow_positive_frac:       float   # fraction of txs with positive sol_change
    solflow_zero_frac:           float   # fraction of txs with zero sol_change

    # ─── Group 8: tool-invocation n-gram features (14) ───────────────────────
    seq_action_entropy:          float   # Shannon entropy of the action-type sequence
    seq_unique_bigrams:          float   # count of distinct action bigrams /25 (5x5)
    seq_unique_trigrams:         float   # count of distinct action trigrams /125
    seq_bigram_concentration:    float   # fraction of bigrams that are the top bigram
    seq_trigram_concentration:   float   # fraction of trigrams that are the top trigram
    seq_repeat_action_frac:      float   # fraction of consecutive identical actions
    seq_bigram_entropy:          float   # Shannon entropy of the bigram distribution (norm)
    seq_trigram_entropy:         float   # Shannon entropy of the trigram distribution (norm)
    seq_self_transition_frac:    float   # fraction of bigrams that are X->X
    seq_dominant_action_frac:    float   # fraction of the single most-common action
    seq_program_count_mean:      float   # mean number of programs invoked per tx
    seq_program_count_max:       float   # max programs in a single tx
    seq_multi_program_frac:      float   # fraction of txs invoking >1 program
    seq_longest_repeat_run:      float   # longest run of an identical action

    # ─── Group 9: program-interaction diversity (9) ──────────────────────────
    prog_unique_count:           float   # distinct program IDs touched
    prog_unique_ratio:           float   # distinct programs / total program invocations
    prog_concentration_top1:     float   # fraction of invocations to the top program
    prog_concentration_top3:     float   # fraction to top 3
    prog_herfindahl:             float   # HHI of program-invocation distribution
    prog_entropy:                float   # Shannon entropy of program distribution (norm)
    prog_known_frac:             float   # fraction of invocations to KNOWN (mapped) programs
    prog_invocations_per_tx:     float   # mean program invocations per transaction
    prog_new_rate_7d:            float   # rate of new programs appearing, last 7d

    # =========================================================================
    # Construction-time validation
    # =========================================================================

    def __post_init__(self) -> None:
        all_fields = fields(self)
        # Invariant 1: exactly 100 features
        if len(all_fields) != TOTAL_FEATURES:
            raise AssertionError(
                f"FeatureVector must have exactly {TOTAL_FEATURES} fields, "
                f"has {len(all_fields)}"
            )
        # Invariant 2: every value is a finite float
        for f in all_fields:
            value = getattr(self, f.name)
            if not isinstance(value, float):
                raise TypeError(
                    f"FeatureVector.{f.name} must be float, got {type(value).__name__}"
                )
            if not math.isfinite(value):
                raise ValueError(
                    f"FeatureVector.{f.name} is not finite ({value}). "
                    f"Degenerate inputs must resolve to finite defaults, never NaN/inf."
                )

    # =========================================================================
    # Serialisation + introspection
    # =========================================================================

    @property
    def schema_version(self) -> int:
        return FEATURE_SCHEMA_VERSION

    def to_list(self) -> list[float]:
        """The 100 features as a positional list, in canonical order."""
        return list(astuple(self))

    def to_dict(self) -> dict[str, float]:
        """The 100 features as {name: value}, canonical order preserved."""
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def group(self, group_name: str) -> dict[str, float]:
        """Return just the features belonging to one group."""
        if group_name not in GROUP_SIZES:
            raise KeyError(f"unknown group '{group_name}', valid: {list(GROUP_SIZES)}")
        return {
            f.name: getattr(self, f.name)
            for f in fields(self)
            if group_of(f.name) == group_name
        }

    @classmethod
    def feature_names(cls) -> tuple[str, ...]:
        """The 100 feature names, in canonical positional order. Frozen."""
        return tuple(f.name for f in fields(cls))

    @classmethod
    def feature_schema_fingerprint(cls) -> str:
        """
        A stable hash of (schema_version, ordered feature names).

        The baseline engine stores this alongside committed baselines. If the
        feature schema ever changes without a version bump, this fingerprint
        changes and the mismatch is caught instead of silently corrupting scores.
        """
        payload = f"v{FEATURE_SCHEMA_VERSION}:" + ",".join(cls.feature_names())
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def zeros(cls) -> "FeatureVector":
        """
        The all-zero feature vector — the canonical output for an empty window.
        Every feature defaults to 0.0; the vector is still valid (finite, 100-dim).
        """
        return cls(**{f.name: 0.0 for f in fields(cls)})


# Field-name prefix → group. Most groups use their own name as the prefix,
# but a few fields read more naturally with a domain-specific prefix
# (e.g. `failure_streak_max` belongs to the `success` group). This alias map
# is the single source of truth for those exceptions.
_PREFIX_TO_GROUP: dict[str, str] = {
    "txtype":      "txtype",
    "success":     "success",
    "failure":     "success",     # failure_streak_* belong to the success group
    "cp":          "counterparty",
    "fee":         "fees",
    "priority":    "fees",        # priority_fee_* belong to the fees group
    "compute":     "fees",        # compute_units_* belong to the fees group
    "rhythm":      "rhythm",
    "timing":      "timing",
    "solflow":     "solflow",
    "seq":         "sequence",
    "prog":        "programs",
}


def group_of(feature_name: str) -> str:
    """Return the group a feature belongs to. Raises on unknown features."""
    prefix = feature_name.split("_", 1)[0]
    group = _PREFIX_TO_GROUP.get(prefix)
    if group is None:
        raise KeyError(f"feature '{feature_name}' has no declared group (prefix '{prefix}')")
    return group


# Validate the group→field mapping at import time: every field must belong to
# exactly one declared group, and group counts must match GROUP_SIZES.
def _validate_group_mapping() -> None:
    names = FeatureVector.feature_names()
    counts: dict[str, int] = {g: 0 for g in GROUP_SIZES}
    for name in names:
        group = group_of(name)
        counts[group] += 1
    for group, expected in GROUP_SIZES.items():
        if counts[group] != expected:
            raise AssertionError(
                f"group '{group}' expected {expected} features, found {counts[group]}"
            )


_validate_group_mapping()
