"""
tests/baseline/test_engine.py — compute_baseline behaviour.

Covers: the 100-feature mean/std contract, daily-vector aggregation, scalar
summaries, data-sufficiency gating, determinism, and the InsufficientData
floor.
"""

from __future__ import annotations

import math

import pytest

from baseline import (
    BASELINE_ALGO_VERSION,
    MIN_DAYS_WITH_ACTIVITY,
    MIN_TRANSACTION_COUNT,
    InsufficientDataError,
    compute_baseline,
)
from features import FEATURE_SCHEMA_VERSION, TOTAL_FEATURES, ExtractionWindow, FeatureVector
from tests.baseline.conftest import (
    PROG_LEND, PROG_STAKE, PROG_SWAP, PROG_TRANSFER,
    REF_END, make_active_agent_txs, make_tx,
)

WINDOW = ExtractionWindow.ending_at(REF_END, days=30)


# =============================================================================
# Output shape contract
# =============================================================================

class TestOutputShape:

    def test_means_and_stds_are_100_elements(self):
        txs = make_active_agent_txs(days=30, txs_per_day=5)
        b = compute_baseline("agentX", txs, WINDOW)
        assert len(b.feature_means) == TOTAL_FEATURES == 100
        assert len(b.feature_stds) == 100

    def test_all_means_and_stds_finite(self):
        txs = make_active_agent_txs(days=30, txs_per_day=5)
        b = compute_baseline("agentX", txs, WINDOW)
        assert all(math.isfinite(m) for m in b.feature_means)
        assert all(math.isfinite(s) for s in b.feature_stds)

    def test_stds_non_negative(self):
        txs = make_active_agent_txs(days=30, txs_per_day=5)
        b = compute_baseline("agentX", txs, WINDOW)
        assert all(s >= 0.0 for s in b.feature_stds)

    def test_txtype_distribution_is_5_elements_summing_to_one(self):
        txs = make_active_agent_txs(days=10, txs_per_day=4)
        b = compute_baseline("agentX", txs, WINDOW)
        assert len(b.txtype_distribution) == 5
        assert sum(b.txtype_distribution) == pytest.approx(1.0, abs=1e-9)

    def test_carries_correct_versions(self):
        txs = make_active_agent_txs(days=10, txs_per_day=4)
        b = compute_baseline("agentX", txs, WINDOW)
        assert b.baseline_algo_version == BASELINE_ALGO_VERSION == 2
        assert b.feature_schema_version == FEATURE_SCHEMA_VERSION
        assert b.feature_schema_fingerprint == FeatureVector.feature_schema_fingerprint()

    def test_stats_hash_is_64_hex(self):
        txs = make_active_agent_txs(days=10, txs_per_day=4)
        b = compute_baseline("agentX", txs, WINDOW)
        assert len(b.stats_hash) == 64
        assert all(c in "0123456789abcdef" for c in b.stats_hash)


# =============================================================================
# Daily-vector aggregation
# =============================================================================

class TestDailyAggregation:

    def test_days_with_activity_counts_distinct_days(self):
        # 3 txs on 3 distinct days.
        txs = [
            make_tx(offset_hours=2.0),     # day 0
            make_tx(offset_hours=26.0),    # day 1
            make_tx(offset_hours=50.0),    # day 2
        ]
        b = compute_baseline("agentX", txs, WINDOW)
        assert b.days_with_activity == 3

    def test_multiple_txs_same_day_count_as_one_active_day(self):
        # 5 txs all on the same calendar day.
        txs = [make_tx(offset_hours=1.0 + k) for k in range(5)]
        b = compute_baseline("agentX", txs, WINDOW)
        assert b.days_with_activity == 1

    def test_single_active_day_gives_zero_stds(self):
        # Only one daily vector -> stddev across the series is 0 everywhere.
        txs = [make_tx(offset_hours=1.0 + k) for k in range(10)]
        b = compute_baseline("agentX", txs, WINDOW)
        assert b.days_with_activity == 1
        assert all(s == 0.0 for s in b.feature_stds)
        # means equal that single day's feature vector
        assert any(m != 0.0 for m in b.feature_means)  # non-trivial


# =============================================================================
# Scalar summaries
# =============================================================================

class TestScalarSummaries:

    def test_success_rate_30d(self):
        # 8 success, 2 fail over 10 txs -> 0.8
        txs = [
            make_tx(offset_hours=float(i), success=(i > 2))
            for i in range(1, 11)
        ]
        b = compute_baseline("agentX", txs, WINDOW)
        assert b.success_rate_30d == pytest.approx(0.8, abs=1e-9)

    def test_txtype_distribution_pure_swap(self):
        txs = [make_tx(offset_hours=float(i), programs=(PROG_SWAP,)) for i in range(1, 11)]
        b = compute_baseline("agentX", txs, WINDOW)
        # ActionType order: swap, lend, stake, transfer, other
        assert b.txtype_distribution[0] == pytest.approx(1.0, abs=1e-9)
        assert sum(b.txtype_distribution[1:]) == pytest.approx(0.0, abs=1e-9)

    def test_action_entropy_zero_for_single_type(self):
        txs = [make_tx(offset_hours=float(i), programs=(PROG_SWAP,)) for i in range(1, 11)]
        b = compute_baseline("agentX", txs, WINDOW)
        assert b.action_entropy == pytest.approx(0.0, abs=1e-9)

    def test_action_entropy_high_for_even_mix(self):
        # equal mix of all 5 action types -> normalised entropy = 1.0
        progs = [PROG_SWAP, PROG_LEND, PROG_STAKE, PROG_TRANSFER,
                 "UnknownXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"]
        txs = []
        for day in range(5):
            for i, p in enumerate(progs):
                txs.append(make_tx(offset_hours=day * 24 + i + 1.0, programs=(p,)))
        b = compute_baseline("agentX", txs, WINDOW)
        assert b.action_entropy == pytest.approx(1.0, abs=1e-9)


# =============================================================================
# Data sufficiency gating
# =============================================================================

class TestDataSufficiency:

    def test_rich_agent_is_not_provisional(self):
        # 30 days x 5 txs = 150 txs, 30 active days -> well above both bars.
        txs = make_active_agent_txs(days=30, txs_per_day=5)
        b = compute_baseline("agentX", txs, WINDOW)
        assert b.is_provisional is False
        assert b.days_with_activity >= MIN_DAYS_WITH_ACTIVITY
        assert b.transaction_count >= MIN_TRANSACTION_COUNT

    def test_few_active_days_is_provisional(self):
        # 30 txs but all on 3 days -> below MIN_DAYS_WITH_ACTIVITY.
        # REF_END is 12:00 UTC, so to keep a day's txs within ONE calendar day
        # we spread them across only a few hours starting just after midnight
        # of that day. Day d: offsets place txs at ~01:00-06:00 UTC of that day.
        txs = []
        for day in range(3):
            # midnight of `day` days ago is at offset (12 + day*24) hours.
            # put 10 txs in the 01:00-06:00 band of that day.
            day_midnight_offset = 12 + day * 24
            for k in range(10):
                txs.append(make_tx(offset_hours=day_midnight_offset - 1.0 - k * 0.4))
        b = compute_baseline("agentX", txs, WINDOW)
        assert b.days_with_activity == 3
        assert b.transaction_count == 30
        assert b.is_provisional is True   # days < MIN_DAYS_WITH_ACTIVITY

    def test_few_transactions_is_provisional(self):
        # 10 txs spread over 10 days -> above day bar, below tx bar.
        txs = [make_tx(offset_hours=day * 24 + 1.0) for day in range(10)]
        b = compute_baseline("agentX", txs, WINDOW)
        assert b.days_with_activity == 10
        assert b.transaction_count == 10
        assert b.is_provisional is True   # txs < MIN_TRANSACTION_COUNT

    def test_zero_transactions_raises_insufficient_data(self):
        with pytest.raises(InsufficientDataError):
            compute_baseline("agentX", [], WINDOW)

    def test_transactions_outside_window_ignored_for_sufficiency(self):
        # 100 txs but all OUTSIDE the 30d window -> treated as zero -> raises.
        far_past = [make_tx(offset_hours=24 * 60 + i) for i in range(100)]  # ~60d ago
        with pytest.raises(InsufficientDataError):
            compute_baseline("agentX", far_past, WINDOW)


# =============================================================================
# Determinism — same input -> same baseline -> same stats_hash
# =============================================================================

class TestDeterminism:

    def test_same_input_same_stats_hash(self):
        txs = make_active_agent_txs(days=20, txs_per_day=4)
        b1 = compute_baseline("agentX", txs, WINDOW)
        b2 = compute_baseline("agentX", txs, WINDOW)
        assert b1.stats_hash == b2.stats_hash
        assert b1.feature_means == b2.feature_means
        assert b1.feature_stds == b2.feature_stds

    def test_input_order_does_not_change_baseline(self):
        import random
        txs = make_active_agent_txs(days=20, txs_per_day=4)
        canonical = compute_baseline("agentX", txs, WINDOW)
        rng = random.Random(123)
        for _ in range(5):
            shuffled = txs[:]
            rng.shuffle(shuffled)
            b = compute_baseline("agentX", shuffled, WINDOW)
            assert b.stats_hash == canonical.stats_hash

    def test_computed_at_does_not_affect_stats_hash(self):
        from datetime import timedelta
        txs = make_active_agent_txs(days=20, txs_per_day=4)
        b1 = compute_baseline("agentX", txs, WINDOW, computed_at=REF_END)
        b2 = compute_baseline("agentX", txs, WINDOW, computed_at=REF_END + timedelta(days=1))
        # computed_at differs but is NOT in the hashed payload
        assert b1.computed_at != b2.computed_at
        assert b1.stats_hash == b2.stats_hash

    def test_agent_wallet_does_not_affect_stats_hash(self):
        # Two agents with byte-identical behaviour -> identical stats_hash.
        # (agent_wallet is deliberately excluded from the commitment.)
        txs = make_active_agent_txs(days=20, txs_per_day=4)
        b1 = compute_baseline("agentAAA", txs, WINDOW)
        b2 = compute_baseline("agentBBB", txs, WINDOW)
        assert b1.stats_hash == b2.stats_hash

    def test_different_behaviour_different_hash(self):
        txs_a = make_active_agent_txs(days=20, txs_per_day=4, success_rate=0.95)
        txs_b = make_active_agent_txs(days=20, txs_per_day=4, success_rate=0.60)
        b_a = compute_baseline("agentX", txs_a, WINDOW)
        b_b = compute_baseline("agentX", txs_b, WINDOW)
        assert b_a.stats_hash != b_b.stats_hash
