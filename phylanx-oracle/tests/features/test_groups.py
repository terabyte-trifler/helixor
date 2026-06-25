"""
tests/features/test_groups.py — hand-computed expectations for every group.

Each test constructs a SMALL, fully-known transaction set and asserts the
exact feature values. The arithmetic is worked out in the comments so a
reviewer can verify without running anything.
"""

from __future__ import annotations

import math

import pytest

from features import extract
from features.types import ExtractionWindow
from tests.features.conftest import (
    PROG_LEND, PROG_STAKE, PROG_SWAP, PROG_TRANSFER, PROG_UNKNOWN,
    REF_END, make_tx,
)

WINDOW = ExtractionWindow.ending_at(REF_END, 30)
APPROX = 1e-9


# =============================================================================
# Group 1 — transaction-type distribution
# =============================================================================

class TestTxTypeGroup:

    def test_pure_swap_agent(self):
        # 4 swaps → swap_frac = 1.0, everything else 0.
        txs = [make_tx(offset_hours=float(i), programs=(PROG_SWAP,)) for i in range(1, 5)]
        fv = extract(txs, WINDOW)
        assert fv.txtype_swap_frac == 1.0
        assert fv.txtype_lend_frac == 0.0
        assert fv.txtype_stake_frac == 0.0
        assert fv.txtype_transfer_frac == 0.0
        assert fv.txtype_other_frac == 0.0

    def test_even_mix(self):
        # 1 of each of 5 classes → each frac = 0.2.
        txs = [
            make_tx(offset_hours=1.0, programs=(PROG_SWAP,)),
            make_tx(offset_hours=2.0, programs=(PROG_LEND,)),
            make_tx(offset_hours=3.0, programs=(PROG_STAKE,)),
            make_tx(offset_hours=4.0, programs=(PROG_TRANSFER,)),
            make_tx(offset_hours=5.0, programs=(PROG_UNKNOWN,)),  # → OTHER
        ]
        fv = extract(txs, WINDOW)
        assert fv.txtype_swap_frac     == pytest.approx(0.2, abs=APPROX)
        assert fv.txtype_lend_frac     == pytest.approx(0.2, abs=APPROX)
        assert fv.txtype_stake_frac    == pytest.approx(0.2, abs=APPROX)
        assert fv.txtype_transfer_frac == pytest.approx(0.2, abs=APPROX)
        assert fv.txtype_other_frac    == pytest.approx(0.2, abs=APPROX)

    def test_fractions_sum_to_one(self):
        txs = [
            make_tx(offset_hours=1.0, programs=(PROG_SWAP,)),
            make_tx(offset_hours=2.0, programs=(PROG_SWAP,)),
            make_tx(offset_hours=3.0, programs=(PROG_LEND,)),
        ]
        fv = extract(txs, WINDOW)
        total = (fv.txtype_swap_frac + fv.txtype_lend_frac + fv.txtype_stake_frac
                 + fv.txtype_transfer_frac + fv.txtype_other_frac)
        assert total == pytest.approx(1.0, abs=APPROX)

    def test_primary_action_uses_first_recognised_program(self):
        # [UNKNOWN, SWAP] → first recognised is SWAP, so action = SWAP.
        txs = [make_tx(offset_hours=1.0, programs=(PROG_UNKNOWN, PROG_SWAP))]
        fv = extract(txs, WINDOW)
        assert fv.txtype_swap_frac == 1.0


# =============================================================================
# Group 2 — success-rate windows + slopes
# =============================================================================

class TestSuccessGroup:

    def test_all_success(self):
        txs = [make_tx(offset_hours=float(i), success=True) for i in range(1, 11)]
        fv = extract(txs, WINDOW)
        assert fv.success_rate_overall == 1.0
        assert fv.failure_streak_max == 0.0
        assert fv.failure_streak_current == 0.0

    def test_half_success(self):
        # 5 success, 5 fail → overall rate 0.5.
        txs = [make_tx(offset_hours=float(i), success=(i % 2 == 0)) for i in range(1, 11)]
        fv = extract(txs, WINDOW)
        assert fv.success_rate_overall == pytest.approx(0.5, abs=APPROX)

    def test_window_buckets(self):
        # 2 txs within last 1d (offsets 2h, 10h), all success.
        # 1 more within last 7d (offset 100h ~4.2d). 1 more within 30d (offset 600h ~25d).
        txs = [
            make_tx(offset_hours=2.0,   success=True),
            make_tx(offset_hours=10.0,  success=True),
            make_tx(offset_hours=100.0, success=False),   # ~4.2d → in 7d, not 1d
            make_tx(offset_hours=600.0, success=True),    # ~25d → in 30d only
        ]
        fv = extract(txs, WINDOW)
        # 1d: offsets <24h → 2h, 10h. both success → 1.0
        assert fv.success_rate_1d == pytest.approx(1.0, abs=APPROX)
        assert fv.success_count_1d == 2.0
        # 7d: offsets <168h → 2,10,100. successes 2 of 3 → 0.6667
        assert fv.success_rate_7d == pytest.approx(2/3, abs=1e-6)
        assert fv.success_count_7d == 2.0
        # 30d: all 4 → 3 of 4 success
        assert fv.success_rate_30d == pytest.approx(0.75, abs=APPROX)
        assert fv.success_count_30d == 3.0

    def test_failure_streak_max_and_current(self):
        # Order (oldest→newest by offset DESC): we want a run of failures
        # at the end. offset larger = older.
        txs = [
            make_tx(offset_hours=50.0, success=True),   # oldest
            make_tx(offset_hours=40.0, success=False),
            make_tx(offset_hours=30.0, success=False),
            make_tx(offset_hours=20.0, success=True),
            make_tx(offset_hours=10.0, success=False),
            make_tx(offset_hours=5.0,  success=False),  # newest
        ]
        fv = extract(txs, WINDOW)
        # streaks over canonical order [T,F,F,T,F,F]: max run = 2, current = 2
        assert fv.failure_streak_max == 2.0
        assert fv.failure_streak_current == 2.0

    def test_failure_streak_current_zero_when_ends_success(self):
        txs = [
            make_tx(offset_hours=30.0, success=False),
            make_tx(offset_hours=20.0, success=False),
            make_tx(offset_hours=10.0, success=True),   # newest is success
        ]
        fv = extract(txs, WINDOW)
        assert fv.failure_streak_max == 2.0
        assert fv.failure_streak_current == 0.0


# =============================================================================
# Group 3 — counterparty diversity
# =============================================================================

class TestCounterpartyGroup:

    def test_unique_counterparties(self):
        # 3 txs, counterparties cpA, cpB, cpC → 3 unique, ratio 1.0.
        txs = [
            make_tx(offset_hours=1.0, counterparty="cpA"),
            make_tx(offset_hours=2.0, counterparty="cpB"),
            make_tx(offset_hours=3.0, counterparty="cpC"),
        ]
        fv = extract(txs, WINDOW)
        assert fv.cp_unique_count == 3.0
        assert fv.cp_unique_ratio == pytest.approx(1.0, abs=APPROX)
        assert fv.cp_repeat_ratio == pytest.approx(0.0, abs=APPROX)
        assert fv.cp_txs_with_cp_frac == pytest.approx(1.0, abs=APPROX)

    def test_repeat_ratio(self):
        # cpA, cpA, cpB → second cpA is a repeat → 1 repeat of 3 = 0.3333.
        txs = [
            make_tx(offset_hours=1.0, counterparty="cpA"),
            make_tx(offset_hours=2.0, counterparty="cpA"),
            make_tx(offset_hours=3.0, counterparty="cpB"),
        ]
        fv = extract(txs, WINDOW)
        assert fv.cp_repeat_ratio == pytest.approx(1/3, abs=1e-6)
        assert fv.cp_unique_count == 2.0

    def test_concentration_top1(self):
        # cpA x3, cpB x1 → top1 concentration = 3/4 = 0.75.
        txs = [
            make_tx(offset_hours=1.0, counterparty="cpA"),
            make_tx(offset_hours=2.0, counterparty="cpA"),
            make_tx(offset_hours=3.0, counterparty="cpA"),
            make_tx(offset_hours=4.0, counterparty="cpB"),
        ]
        fv = extract(txs, WINDOW)
        assert fv.cp_concentration_top1 == pytest.approx(0.75, abs=APPROX)

    def test_herfindahl_full_concentration(self):
        # All txs to one cp → HHI = 1.0.
        txs = [make_tx(offset_hours=float(i), counterparty="cpA") for i in range(1, 5)]
        fv = extract(txs, WINDOW)
        assert fv.cp_herfindahl == pytest.approx(1.0, abs=APPROX)

    def test_no_counterparties_all_zero(self):
        # No tx has a counterparty → all cp features 0, cp_txs_with_cp_frac 0.
        txs = [make_tx(offset_hours=float(i), counterparty=None) for i in range(1, 5)]
        fv = extract(txs, WINDOW)
        assert fv.cp_unique_count == 0.0
        assert fv.cp_txs_with_cp_frac == 0.0
        assert fv.cp_herfindahl == 0.0

    def test_max_single_volume_frac(self):
        # cpA gets |1_000_000| + |500_000| = 1_500_000, cpB gets |500_000|.
        # total = 2_000_000, top = 1_500_000 → 0.75.
        txs = [
            make_tx(offset_hours=1.0, counterparty="cpA", sol_change=1_000_000),
            make_tx(offset_hours=2.0, counterparty="cpA", sol_change=-500_000),
            make_tx(offset_hours=3.0, counterparty="cpB", sol_change=500_000),
        ]
        fv = extract(txs, WINDOW)
        assert fv.cp_max_single_volume_frac == pytest.approx(0.75, abs=APPROX)


# =============================================================================
# Group 4 — fee & compute patterns
# =============================================================================

class TestFeesGroup:

    def test_constant_fees(self):
        # All fees 5000 → mean 5000, stddev 0, cv 0, median 5000.
        txs = [make_tx(offset_hours=float(i), fee=5000) for i in range(1, 11)]
        fv = extract(txs, WINDOW)
        assert fv.fee_mean == pytest.approx(5000.0, abs=APPROX)
        assert fv.fee_stddev == pytest.approx(0.0, abs=APPROX)
        assert fv.fee_cv == pytest.approx(0.0, abs=APPROX)
        assert fv.fee_median == pytest.approx(5000.0, abs=APPROX)
        assert fv.fee_max == 5000.0
        assert fv.fee_min == 5000.0

    def test_fee_mean_and_extremes(self):
        # fees 1000, 2000, 3000 → mean 2000, min 1000, max 3000, median 2000.
        txs = [
            make_tx(offset_hours=1.0, fee=1000),
            make_tx(offset_hours=2.0, fee=2000),
            make_tx(offset_hours=3.0, fee=3000),
        ]
        fv = extract(txs, WINDOW)
        assert fv.fee_mean == pytest.approx(2000.0, abs=APPROX)
        assert fv.fee_min == 1000.0
        assert fv.fee_max == 3000.0
        assert fv.fee_median == pytest.approx(2000.0, abs=APPROX)

    def test_priority_fee_usage(self):
        # 2 of 4 txs have priority fee → usage frac 0.5.
        # priority fees present: 1000, 3000 → mean among present = 2000.
        txs = [
            make_tx(offset_hours=1.0, priority_fee=1000),
            make_tx(offset_hours=2.0, priority_fee=0),
            make_tx(offset_hours=3.0, priority_fee=3000),
            make_tx(offset_hours=4.0, priority_fee=0),
        ]
        fv = extract(txs, WINDOW)
        assert fv.priority_fee_usage_frac == pytest.approx(0.5, abs=APPROX)
        assert fv.priority_fee_mean == pytest.approx(2000.0, abs=APPROX)

    def test_compute_units(self):
        # compute units 100k, 200k, 300k → mean 200k.
        txs = [
            make_tx(offset_hours=1.0, compute_units=100_000),
            make_tx(offset_hours=2.0, compute_units=200_000),
            make_tx(offset_hours=3.0, compute_units=300_000),
        ]
        fv = extract(txs, WINDOW)
        assert fv.compute_units_mean == pytest.approx(200_000.0, abs=APPROX)

    def test_fee_per_compute(self):
        # fee 10000 / compute 200000 = 0.05 for each → mean 0.05.
        txs = [
            make_tx(offset_hours=1.0, fee=10_000, compute_units=200_000),
            make_tx(offset_hours=2.0, fee=10_000, compute_units=200_000),
        ]
        fv = extract(txs, WINDOW)
        assert fv.fee_per_compute_mean == pytest.approx(0.05, abs=APPROX)

    def test_zero_compute_units_no_nan(self):
        # All compute_units 0 → fee_per_compute_mean should be 0, not NaN.
        txs = [make_tx(offset_hours=float(i), compute_units=0) for i in range(1, 5)]
        fv = extract(txs, WINDOW)
        assert fv.fee_per_compute_mean == 0.0
        assert fv.compute_units_mean == 0.0


# =============================================================================
# Group 5 — time-of-day / day-of-week rhythm
# =============================================================================

class TestRhythmGroup:

    def test_all_same_hour_zero_entropy(self):
        # All txs at the same hour → hour entropy 0, peak frac 1.0.
        # REF_END is 12:00 UTC. offsets that are multiples of 24h keep hour=12.
        txs = [make_tx(offset_hours=24.0 * i) for i in range(1, 6)]
        fv = extract(txs, WINDOW)
        assert fv.rhythm_hour_entropy == pytest.approx(0.0, abs=APPROX)
        assert fv.rhythm_hour_peak_frac == pytest.approx(1.0, abs=APPROX)
        # peak hour is 12 → normalised 12/23
        assert fv.rhythm_hour_peak_idx == pytest.approx(12 / 23, abs=1e-6)

    def test_night_fraction(self):
        # REF_END = 12:00 UTC. To land at hour 03:00, offset by 9h (12-9=3).
        # offset 9h → 03:00 (night). offset 0.0 not allowed (window edge), use small.
        txs = [
            make_tx(offset_hours=9.0),    # 03:00 UTC → night
            make_tx(offset_hours=33.0),   # 03:00 UTC next day back → night
            make_tx(offset_hours=2.0),    # 10:00 UTC → not night
        ]
        fv = extract(txs, WINDOW)
        # 2 of 3 in night band [00:00,06:00)
        assert fv.rhythm_night_frac == pytest.approx(2/3, abs=1e-6)

    def test_active_days_count(self):
        # 3 txs on 3 distinct calendar days.
        txs = [
            make_tx(offset_hours=2.0),     # day A
            make_tx(offset_hours=26.0),    # day B (~24h earlier)
            make_tx(offset_hours=50.0),    # day C
        ]
        fv = extract(txs, WINDOW)
        assert fv.rhythm_active_days_count == 3.0

    def test_regularity_perfect_when_even(self):
        # Exactly 1 tx per day for several days → per-day counts all equal →
        # CV 0 → regularity 1.0.
        txs = [make_tx(offset_hours=24.0 * i + 2.0) for i in range(0, 5)]
        fv = extract(txs, WINDOW)
        assert fv.rhythm_regularity_score == pytest.approx(1.0, abs=APPROX)

    def test_weekend_fraction(self):
        # REF_END 2026-05-01 is a Friday. Need to land txs on Sat/Sun.
        # 2026-05-02 is Sat, 2026-05-03 is Sun. But those are AFTER REF_END.
        # Going backwards: 2026-04-25 Sat, 2026-04-26 Sun.
        # REF_END - 2026-04-25 12:00 = 6 days = 144h. - 2026-04-26 = 120h.
        txs = [
            make_tx(offset_hours=144.0),   # Sat
            make_tx(offset_hours=120.0),   # Sun
            make_tx(offset_hours=2.0),     # Fri (REF_END day)
        ]
        fv = extract(txs, WINDOW)
        assert fv.rhythm_weekend_frac == pytest.approx(2/3, abs=1e-6)


# =============================================================================
# Group 6 — inter-transaction timing
# =============================================================================

class TestTimingGroup:

    def test_single_transaction_zero_timing(self):
        fv = extract([make_tx(offset_hours=5.0)], WINDOW)
        assert fv.timing_gap_mean_s == 0.0
        assert fv.timing_gap_stddev_s == 0.0
        assert fv.timing_burstiness == 0.0
        assert fv.timing_txs_per_active_day == 1.0

    def test_even_gaps(self):
        # txs every 1 hour → gaps all 3600s → mean 3600, stddev 0, cv 0.
        txs = [make_tx(offset_hours=float(i)) for i in range(1, 6)]
        fv = extract(txs, WINDOW)
        assert fv.timing_gap_mean_s == pytest.approx(3600.0, abs=APPROX)
        assert fv.timing_gap_stddev_s == pytest.approx(0.0, abs=APPROX)
        assert fv.timing_gap_cv == pytest.approx(0.0, abs=APPROX)
        assert fv.timing_gap_min_s == pytest.approx(3600.0, abs=APPROX)
        assert fv.timing_gap_max_s == pytest.approx(3600.0, abs=APPROX)

    def test_rapid_fire_fraction(self):
        # txs at offsets 10.0, then +1s, +2s, then +1h.
        # offsets in hours: 10.0, 9.99972..., that's fiddly — use seconds directly
        # via tiny offsets. Build 4 txs: gaps of 1s, 2s, 3600s.
        # offset_hours: t0=10h, t1=10h - 1s, t2 = t1 - 2s, t3 = t2 - 3600s
        # but make_tx older = larger offset. We want newest-first sort handled.
        h = 3600.0
        txs = [
            make_tx(offset_hours=10.0),                       # oldest
            make_tx(offset_hours=10.0 - 1/h),                 # +1s
            make_tx(offset_hours=10.0 - 3/h),                 # +2s
            make_tx(offset_hours=10.0 - 3/h - 1.0),           # +3600s
        ]
        fv = extract(txs, WINDOW)
        # gaps: 1s, 2s, 3600s → 2 of 3 are <5s → 0.6667
        assert fv.timing_rapid_fire_frac == pytest.approx(2/3, abs=1e-6)
        # 1 of 3 gaps > 1h? 3600s is not >3600 strictly → 0
        assert fv.timing_idle_gap_frac == pytest.approx(0.0, abs=APPROX)

    def test_longest_idle(self):
        # gaps of 1h and 5h → longest idle = 5h = 18000s.
        txs = [
            make_tx(offset_hours=10.0),   # oldest
            make_tx(offset_hours=9.0),    # +1h
            make_tx(offset_hours=4.0),    # +5h
        ]
        fv = extract(txs, WINDOW)
        assert fv.timing_longest_idle_s == pytest.approx(18000.0, abs=APPROX)


# =============================================================================
# Group 7 — SOL-flow statistics
# =============================================================================

class TestSolFlowGroup:

    def test_pure_inflow(self):
        # 3 txs each +1_000_000 → total_in 3M, total_out 0, net 3M.
        txs = [make_tx(offset_hours=float(i), sol_change=1_000_000) for i in range(1, 4)]
        fv = extract(txs, WINDOW)
        assert fv.solflow_total_in == pytest.approx(3_000_000.0, abs=APPROX)
        assert fv.solflow_total_out == pytest.approx(0.0, abs=APPROX)
        assert fv.solflow_net == pytest.approx(3_000_000.0, abs=APPROX)
        assert fv.solflow_positive_frac == pytest.approx(1.0, abs=APPROX)

    def test_mixed_flow(self):
        # +1M, -500k, -500k → in 1M, out 1M, net 0.
        txs = [
            make_tx(offset_hours=1.0, sol_change=1_000_000),
            make_tx(offset_hours=2.0, sol_change=-500_000),
            make_tx(offset_hours=3.0, sol_change=-500_000),
        ]
        fv = extract(txs, WINDOW)
        assert fv.solflow_total_in == pytest.approx(1_000_000.0, abs=APPROX)
        assert fv.solflow_total_out == pytest.approx(1_000_000.0, abs=APPROX)
        assert fv.solflow_net == pytest.approx(0.0, abs=APPROX)
        assert fv.solflow_positive_frac == pytest.approx(1/3, abs=1e-6)

    def test_max_inflow_outflow(self):
        txs = [
            make_tx(offset_hours=1.0, sol_change=2_000_000),
            make_tx(offset_hours=2.0, sol_change=-3_000_000),
            make_tx(offset_hours=3.0, sol_change=500_000),
        ]
        fv = extract(txs, WINDOW)
        assert fv.solflow_max_inflow == pytest.approx(2_000_000.0, abs=APPROX)
        assert fv.solflow_max_outflow == pytest.approx(3_000_000.0, abs=APPROX)

    def test_zero_change_fraction(self):
        # 2 of 4 txs have zero sol_change.
        txs = [
            make_tx(offset_hours=1.0, sol_change=0),
            make_tx(offset_hours=2.0, sol_change=1000),
            make_tx(offset_hours=3.0, sol_change=0),
            make_tx(offset_hours=4.0, sol_change=-1000),
        ]
        fv = extract(txs, WINDOW)
        assert fv.solflow_zero_frac == pytest.approx(0.5, abs=APPROX)

    def test_all_zero_change_no_nan(self):
        txs = [make_tx(offset_hours=float(i), sol_change=0) for i in range(1, 5)]
        fv = extract(txs, WINDOW)
        assert fv.solflow_volatility_norm == 0.0
        assert fv.solflow_mad == 0.0
        assert math.isfinite(fv.solflow_in_out_ratio)


# =============================================================================
# Group 8 — tool-invocation n-gram features
# =============================================================================

class TestSequenceGroup:

    def test_all_same_action_zero_entropy(self):
        # All swaps → action entropy 0, dominant frac 1.0.
        txs = [make_tx(offset_hours=float(i), programs=(PROG_SWAP,)) for i in range(1, 6)]
        fv = extract(txs, WINDOW)
        assert fv.seq_action_entropy == pytest.approx(0.0, abs=APPROX)
        assert fv.seq_dominant_action_frac == pytest.approx(1.0, abs=APPROX)
        # all bigrams are SWAP->SWAP → self transition frac 1.0
        assert fv.seq_self_transition_frac == pytest.approx(1.0, abs=APPROX)
        # longest run = 5
        assert fv.seq_longest_repeat_run == 5.0

    def test_alternating_actions(self):
        # SWAP, LEND, SWAP, LEND → 2 distinct bigrams (S->L, L->S).
        txs = [
            make_tx(offset_hours=4.0, programs=(PROG_SWAP,)),
            make_tx(offset_hours=3.0, programs=(PROG_LEND,)),
            make_tx(offset_hours=2.0, programs=(PROG_SWAP,)),
            make_tx(offset_hours=1.0, programs=(PROG_LEND,)),
        ]
        fv = extract(txs, WINDOW)
        # bigrams: (S,L),(L,S),(S,L) → 2 unique of 25 → 0.08
        assert fv.seq_unique_bigrams == pytest.approx(2/25, abs=1e-9)
        # no self transitions
        assert fv.seq_self_transition_frac == pytest.approx(0.0, abs=APPROX)
        # longest identical run = 1
        assert fv.seq_longest_repeat_run == 1.0
        # repeat action frac = 0
        assert fv.seq_repeat_action_frac == pytest.approx(0.0, abs=APPROX)

    def test_multi_program_fraction(self):
        # 2 of 4 txs invoke >1 program.
        txs = [
            make_tx(offset_hours=1.0, programs=(PROG_SWAP, PROG_LEND)),
            make_tx(offset_hours=2.0, programs=(PROG_SWAP,)),
            make_tx(offset_hours=3.0, programs=(PROG_STAKE, PROG_SWAP, PROG_LEND)),
            make_tx(offset_hours=4.0, programs=(PROG_TRANSFER,)),
        ]
        fv = extract(txs, WINDOW)
        assert fv.seq_multi_program_frac == pytest.approx(0.5, abs=APPROX)
        # program count mean: (2+1+3+1)/4 = 1.75
        assert fv.seq_program_count_mean == pytest.approx(1.75, abs=APPROX)
        assert fv.seq_program_count_max == 3.0

    def test_longest_repeat_run(self):
        # SWAP, SWAP, SWAP, LEND, SWAP → longest run of identical = 3.
        txs = [
            make_tx(offset_hours=5.0, programs=(PROG_SWAP,)),
            make_tx(offset_hours=4.0, programs=(PROG_SWAP,)),
            make_tx(offset_hours=3.0, programs=(PROG_SWAP,)),
            make_tx(offset_hours=2.0, programs=(PROG_LEND,)),
            make_tx(offset_hours=1.0, programs=(PROG_SWAP,)),
        ]
        fv = extract(txs, WINDOW)
        assert fv.seq_longest_repeat_run == 3.0


# =============================================================================
# Group 9 — program-interaction diversity
# =============================================================================

class TestProgramsGroup:

    def test_single_program(self):
        # All txs touch only PROG_SWAP → unique count 1, HHI 1.0, concentration 1.0.
        txs = [make_tx(offset_hours=float(i), programs=(PROG_SWAP,)) for i in range(1, 5)]
        fv = extract(txs, WINDOW)
        assert fv.prog_unique_count == 1.0
        assert fv.prog_herfindahl == pytest.approx(1.0, abs=APPROX)
        assert fv.prog_concentration_top1 == pytest.approx(1.0, abs=APPROX)
        assert fv.prog_invocations_per_tx == pytest.approx(1.0, abs=APPROX)

    def test_known_fraction(self):
        # 3 known programs + 1 unknown → known_frac = 3/4.
        txs = [
            make_tx(offset_hours=1.0, programs=(PROG_SWAP,)),
            make_tx(offset_hours=2.0, programs=(PROG_LEND,)),
            make_tx(offset_hours=3.0, programs=(PROG_STAKE,)),
            make_tx(offset_hours=4.0, programs=(PROG_UNKNOWN,)),
        ]
        fv = extract(txs, WINDOW)
        assert fv.prog_known_frac == pytest.approx(0.75, abs=APPROX)

    def test_invocations_per_tx(self):
        # txs invoke 1, 2, 3 programs → total 6 invocations / 3 txs = 2.0.
        txs = [
            make_tx(offset_hours=1.0, programs=(PROG_SWAP,)),
            make_tx(offset_hours=2.0, programs=(PROG_SWAP, PROG_LEND)),
            make_tx(offset_hours=3.0, programs=(PROG_SWAP, PROG_LEND, PROG_STAKE)),
        ]
        fv = extract(txs, WINDOW)
        assert fv.prog_invocations_per_tx == pytest.approx(2.0, abs=APPROX)

    def test_unique_ratio(self):
        # 6 total invocations, 3 distinct programs → ratio 0.5.
        txs = [
            make_tx(offset_hours=1.0, programs=(PROG_SWAP, PROG_LEND)),
            make_tx(offset_hours=2.0, programs=(PROG_SWAP, PROG_STAKE)),
            make_tx(offset_hours=3.0, programs=(PROG_LEND, PROG_STAKE)),
        ]
        fv = extract(txs, WINDOW)
        assert fv.prog_unique_ratio == pytest.approx(0.5, abs=APPROX)
        assert fv.prog_unique_count == 3.0


# =============================================================================
# Cross-group: a realistic mixed agent, spot-checking several groups at once
# =============================================================================

class TestRealisticAgent:

    def test_mixed_agent_spot_checks(self):
        txs = [
            make_tx(offset_hours=1.0,  programs=(PROG_SWAP,), success=True,
                    sol_change=1_000_000, fee=5000, counterparty="cpA"),
            make_tx(offset_hours=2.0,  programs=(PROG_SWAP,), success=True,
                    sol_change=-300_000, fee=5000, counterparty="cpA"),
            make_tx(offset_hours=3.0,  programs=(PROG_LEND,), success=False,
                    sol_change=-100_000, fee=7000, counterparty="cpB"),
            make_tx(offset_hours=4.0,  programs=(PROG_TRANSFER,), success=True,
                    sol_change=-50_000, fee=5000, counterparty="cpC"),
        ]
        fv = extract(txs, WINDOW)

        # txtype: 2 swap, 1 lend, 1 transfer of 4
        assert fv.txtype_swap_frac == pytest.approx(0.5, abs=APPROX)
        assert fv.txtype_lend_frac == pytest.approx(0.25, abs=APPROX)
        assert fv.txtype_transfer_frac == pytest.approx(0.25, abs=APPROX)
        # success: 3 of 4
        assert fv.success_rate_overall == pytest.approx(0.75, abs=APPROX)
        # counterparties: cpA x2, cpB, cpC → 3 unique, 1 repeat
        assert fv.cp_unique_count == 3.0
        assert fv.cp_repeat_ratio == pytest.approx(0.25, abs=APPROX)
        # solflow: in 1M, out 450k, net 550k
        assert fv.solflow_total_in == pytest.approx(1_000_000.0, abs=APPROX)
        assert fv.solflow_total_out == pytest.approx(450_000.0, abs=APPROX)
        assert fv.solflow_net == pytest.approx(550_000.0, abs=APPROX)
        # all 100 finite
        assert all(math.isfinite(v) for v in fv.to_list())
