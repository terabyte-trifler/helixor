"""
tests/features/test_contract.py — the FeatureVector CONTRACT.

These tests guard the invariants that everything downstream depends on:
exactly 100 features, frozen order, all-finite, schema fingerprint stable.
If any of these break, the baseline engine and detectors break silently.
"""

from __future__ import annotations

import math

import pytest

from features import extract
from features.types import ExtractionWindow
from features.vector import (
    FEATURE_SCHEMA_VERSION,
    GROUP_SIZES,
    TOTAL_FEATURES,
    FeatureVector,
)
from tests.features.conftest import REF_END, make_tx


# =============================================================================
# Invariant 1 — exactly 100 features
# =============================================================================

def test_exactly_100_features():
    assert TOTAL_FEATURES == 100
    assert len(FeatureVector.feature_names()) == 100

def test_group_sizes_sum_to_100():
    assert sum(GROUP_SIZES.values()) == 100

def test_zeros_vector_has_100_finite_fields():
    z = FeatureVector.zeros()
    values = z.to_list()
    assert len(values) == 100
    assert all(math.isfinite(v) for v in values)
    assert all(v == 0.0 for v in values)


# =============================================================================
# Invariant 2 — frozen field order
# =============================================================================

def test_feature_order_is_frozen():
    """
    This is the canonical feature order. If this test fails, someone reordered
    or renamed a field — that is a FEATURE_SCHEMA_VERSION bump, not a silent change.
    """
    names = FeatureVector.feature_names()
    # Spot-check anchored positions across the vector.
    assert names[0]  == "txtype_swap_frac"
    assert names[4]  == "txtype_other_frac"
    assert names[5]  == "success_rate_1d"
    assert names[14] == "success_volatility"
    assert names[16] == "failure_streak_current"
    assert names[99] == "prog_new_rate_7d"
    # First field of every group sits where the cumulative group sizes say.
    assert names[5]  == "success_rate_1d"        # after 5 txtype
    assert names[17] == "cp_unique_count"        # after 5+12
    assert names[28] == "fee_mean"               # after 5+12+11
    assert names[41] == "rhythm_hour_entropy"    # after 5+12+11+13
    assert names[54] == "timing_gap_mean_s"      # after +13
    assert names[65] == "solflow_total_in"       # after +11
    assert names[77] == "seq_action_entropy"     # after +12
    assert names[91] == "prog_unique_count"      # after +14

def test_to_list_matches_feature_names_order():
    txs = [make_tx(offset_hours=h) for h in (1, 2, 3)]
    fv = extract(txs, ExtractionWindow.ending_at(REF_END, 30))
    as_list = fv.to_list()
    as_dict = fv.to_dict()
    names = FeatureVector.feature_names()
    for i, name in enumerate(names):
        assert as_list[i] == as_dict[name], f"position {i} ({name}) mismatch"


# =============================================================================
# Invariant 3 — all features finite for ALL inputs
# =============================================================================

def test_empty_window_returns_finite_zeros(empty_txs, window_30d):
    fv = extract(empty_txs, window_30d)
    assert all(math.isfinite(v) for v in fv.to_list())
    assert fv == FeatureVector.zeros()

def test_single_transaction_all_finite(window_30d):
    fv = extract([make_tx(offset_hours=5)], window_30d)
    assert all(math.isfinite(v) for v in fv.to_list())

def test_all_identical_transactions_all_finite(window_30d):
    # Zero variance everywhere — classic NaN trap for stddev/CV.
    txs = [make_tx(offset_hours=float(i), fee=5000, sol_change=0) for i in range(1, 20)]
    fv = extract(txs, window_30d)
    assert all(math.isfinite(v) for v in fv.to_list())

def test_all_failures_all_finite(window_30d):
    txs = [make_tx(offset_hours=float(i), success=False) for i in range(1, 10)]
    fv = extract(txs, window_30d)
    assert all(math.isfinite(v) for v in fv.to_list())

def test_constructing_with_nan_raises():
    bad = {name: 0.0 for name in FeatureVector.feature_names()}
    bad["fee_mean"] = float("nan")
    with pytest.raises(ValueError, match="not finite"):
        FeatureVector(**bad)

def test_constructing_with_inf_raises():
    bad = {name: 0.0 for name in FeatureVector.feature_names()}
    bad["solflow_net"] = float("inf")
    with pytest.raises(ValueError, match="not finite"):
        FeatureVector(**bad)

def test_constructing_with_wrong_type_raises():
    bad = {name: 0.0 for name in FeatureVector.feature_names()}
    bad["fee_mean"] = 5000  # int, not float
    with pytest.raises(TypeError, match="must be float"):
        FeatureVector(**bad)


# =============================================================================
# Invariant 4 — immutability
# =============================================================================

def test_feature_vector_is_frozen(window_30d):
    fv = extract([make_tx(offset_hours=1)], window_30d)
    with pytest.raises((AttributeError, Exception)):
        fv.fee_mean = 999.0  # type: ignore[misc]


# =============================================================================
# Invariant 5 — schema fingerprint
# =============================================================================

def test_schema_version_is_1():
    assert FEATURE_SCHEMA_VERSION == 1

def test_fingerprint_is_stable():
    fp1 = FeatureVector.feature_schema_fingerprint()
    fp2 = FeatureVector.feature_schema_fingerprint()
    assert fp1 == fp2
    assert len(fp1) == 64  # sha256 hex

def test_fingerprint_covers_all_names():
    # Changing any name must change the fingerprint — proven by reconstructing it.
    import hashlib
    names = FeatureVector.feature_names()
    expected_payload = f"v{FEATURE_SCHEMA_VERSION}:" + ",".join(names)
    expected = hashlib.sha256(expected_payload.encode()).hexdigest()
    assert FeatureVector.feature_schema_fingerprint() == expected
