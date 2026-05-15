"""
tests/baseline/test_types.py — BaselineStats construction + compatibility checks.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from baseline.types import (
    BASELINE_ALGO_VERSION,
    BaselineStats,
    IncompatibleBaselineError,
)
from features import FEATURE_SCHEMA_VERSION, TOTAL_FEATURES, FeatureVector
from scoring.weights import scoring_schema_fingerprint

REF = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


def _valid_kwargs(**overrides):
    kwargs = dict(
        agent_wallet="agentX",
        baseline_algo_version=BASELINE_ALGO_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_schema_fingerprint=FeatureVector.feature_schema_fingerprint(),
        scoring_schema_fingerprint=scoring_schema_fingerprint(),
        window_start=REF - timedelta(days=30),
        window_end=REF,
        feature_means=tuple(0.5 for _ in range(TOTAL_FEATURES)),
        feature_stds=tuple(0.1 for _ in range(TOTAL_FEATURES)),
        txtype_distribution=(0.2, 0.2, 0.2, 0.2, 0.2),
        action_entropy=0.9,
        success_rate_30d=0.95,
        transaction_count=150,
        days_with_activity=30,
        is_provisional=False,
        computed_at=REF,
        stats_hash="a" * 64,
    )
    kwargs.update(overrides)
    return kwargs


# =============================================================================
# Construction validation
# =============================================================================

class TestConstruction:

    def test_valid_construction(self):
        b = BaselineStats(**_valid_kwargs())
        assert b.agent_wallet == "agentX"
        assert len(b.feature_means) == 100

    def test_wrong_means_length_rejected(self):
        with pytest.raises(ValueError, match="feature_means must have 100"):
            BaselineStats(**_valid_kwargs(feature_means=tuple(0.5 for _ in range(99))))

    def test_wrong_stds_length_rejected(self):
        with pytest.raises(ValueError, match="feature_stds must have 100"):
            BaselineStats(**_valid_kwargs(feature_stds=tuple(0.1 for _ in range(101))))

    def test_wrong_txtype_length_rejected(self):
        with pytest.raises(ValueError, match="txtype_distribution must have 5"):
            BaselineStats(**_valid_kwargs(txtype_distribution=(0.5, 0.5)))

    def test_nan_in_means_rejected(self):
        bad = list(0.5 for _ in range(TOTAL_FEATURES))
        bad[42] = float("nan")
        with pytest.raises(ValueError, match="not a finite float"):
            BaselineStats(**_valid_kwargs(feature_means=tuple(bad)))

    def test_inf_in_stds_rejected(self):
        bad = list(0.1 for _ in range(TOTAL_FEATURES))
        bad[7] = float("inf")
        with pytest.raises(ValueError, match="not a finite float"):
            BaselineStats(**_valid_kwargs(feature_stds=tuple(bad)))

    def test_negative_stddev_rejected(self):
        bad = list(0.1 for _ in range(TOTAL_FEATURES))
        bad[3] = -0.5
        with pytest.raises(ValueError, match="negative"):
            BaselineStats(**_valid_kwargs(feature_stds=tuple(bad)))

    def test_naive_datetime_rejected(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            BaselineStats(**_valid_kwargs(computed_at=datetime(2026, 5, 1, 12, 0, 0)))

    def test_window_end_before_start_rejected(self):
        with pytest.raises(ValueError, match="window_end must be >= window_start"):
            BaselineStats(**_valid_kwargs(
                window_start=REF, window_end=REF - timedelta(days=1),
            ))

    def test_is_frozen(self):
        b = BaselineStats(**_valid_kwargs())
        with pytest.raises((AttributeError, Exception)):
            b.success_rate_30d = 0.0  # type: ignore[misc]


# =============================================================================
# Compatibility checks
# =============================================================================

class TestCompatibility:

    def test_current_baseline_is_compatible(self):
        b = BaselineStats(**_valid_kwargs())
        assert b.is_compatible_with_current_engine() is True
        b.assert_compatible()  # should not raise

    def test_old_algo_version_incompatible(self):
        b = BaselineStats(**_valid_kwargs(baseline_algo_version=1))
        assert b.is_compatible_with_current_engine() is False
        with pytest.raises(IncompatibleBaselineError):
            b.assert_compatible()

    def test_wrong_schema_fingerprint_incompatible(self):
        b = BaselineStats(**_valid_kwargs(feature_schema_fingerprint="deadbeef" * 8))
        assert b.is_compatible_with_current_engine() is False
        with pytest.raises(IncompatibleBaselineError):
            b.assert_compatible()

    def test_wrong_scoring_schema_fingerprint_incompatible(self):
        b = BaselineStats(**_valid_kwargs(scoring_schema_fingerprint="deadbeef" * 8))
        assert b.is_compatible_with_current_engine() is False
        with pytest.raises(IncompatibleBaselineError):
            b.assert_compatible()

    def test_old_schema_version_incompatible(self):
        b = BaselineStats(**_valid_kwargs(feature_schema_version=0))
        assert b.is_compatible_with_current_engine() is False

    def test_window_days_property(self):
        b = BaselineStats(**_valid_kwargs())
        assert b.window_days == pytest.approx(30.0, abs=1e-6)
