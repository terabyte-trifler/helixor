"""
tests/detection/test_base.py — Detector Protocol runtime conformance + error hierarchy.
"""

from __future__ import annotations

import pytest

from baseline import BaselineStats
from detection.base import (
    Detector,
    DetectorContractError,
    DetectorError,
    DetectorInternalError,
    assert_baseline_compatible,
    assert_features_finite,
)
from detection.types import DimensionId, DimensionResult


# =============================================================================
# Error hierarchy
# =============================================================================

class TestErrorHierarchy:

    def test_contract_error_is_detector_error(self):
        assert issubclass(DetectorContractError, DetectorError)

    def test_internal_error_is_detector_error(self):
        assert issubclass(DetectorInternalError, DetectorError)

    def test_errors_are_distinct(self):
        assert DetectorContractError is not DetectorInternalError


# =============================================================================
# Protocol runtime conformance
# =============================================================================

class _ProperDetector:
    """A minimal valid Detector for runtime-check tests."""
    @property
    def dimension(self) -> DimensionId:
        return DimensionId.DRIFT
    @property
    def algo_version(self) -> int:
        return 1
    def score(self, features, baseline) -> DimensionResult:
        return DimensionResult.empty(DimensionId.DRIFT)


class _MissingScore:
    @property
    def dimension(self) -> DimensionId:
        return DimensionId.DRIFT
    @property
    def algo_version(self) -> int:
        return 1
    # no score()


class _MissingDimension:
    @property
    def algo_version(self) -> int:
        return 1
    def score(self, features, baseline) -> DimensionResult:
        return DimensionResult.empty(DimensionId.DRIFT)


class TestProtocolConformance:

    def test_proper_detector_is_runtime_detector(self):
        assert isinstance(_ProperDetector(), Detector)

    def test_missing_score_method_fails_check(self):
        assert not isinstance(_MissingScore(), Detector)

    def test_missing_dimension_fails_check(self):
        assert not isinstance(_MissingDimension(), Detector)


# =============================================================================
# assert_features_finite — guard helper
# =============================================================================

class TestAssertFeaturesFinite:

    def test_passes_for_valid_features(self, features):
        # FeatureVector's own constructor enforces finiteness; the helper
        # is a no-op for any FeatureVector that exists.
        assert_features_finite(features)


# =============================================================================
# assert_baseline_compatible — guard helper
# =============================================================================

class TestAssertBaselineCompatible:

    def test_passes_for_current_baseline(self, baseline):
        # Fresh baselines from compute_baseline are always compatible with the
        # current engine — the assertion passes silently.
        assert_baseline_compatible(baseline)

    def test_raises_detector_contract_error_for_incompatible(self, baseline):
        # Build an incompatible baseline by mutating a copy via the dataclass
        # replace pattern — frozen, so we round-trip through the constructor.
        from dataclasses import replace
        bad = replace(baseline, baseline_algo_version=99)  # algo never seen
        with pytest.raises(DetectorContractError):
            assert_baseline_compatible(bad)
