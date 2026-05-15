"""
tests/detection/test_stubs.py — the five stub detectors.

Day 4 status: every stub returns DimensionResult.empty() with INSUFFICIENT_DATA.
These tests pin that behaviour AND verify each stub conforms to the Protocol.
"""

from __future__ import annotations

import pytest

from detection import (
    Detector,
    DetectorRegistry,
    DimensionId,
    DimensionResult,
    FlagBit,
    default_registry,
)
from detection.anomaly import AnomalyDetector
from detection.consistency import ConsistencyDetector
from detection.drift import DriftDetector
from detection.performance import PerformanceDetector
from detection.security import SecurityDetector


ALL_STUBS = [
    (DimensionId.DRIFT,       DriftDetector()),
    (DimensionId.ANOMALY,     AnomalyDetector()),
    (DimensionId.PERFORMANCE, PerformanceDetector()),
    (DimensionId.CONSISTENCY, ConsistencyDetector()),
    (DimensionId.SECURITY,    SecurityDetector()),
]


@pytest.mark.parametrize("expected_dim,detector", ALL_STUBS)
def test_stub_dimension_matches(expected_dim, detector):
    assert detector.dimension is expected_dim


@pytest.mark.parametrize("_dim,detector", ALL_STUBS)
def test_stub_conforms_to_detector_protocol(_dim, detector):
    assert isinstance(detector, Detector)


@pytest.mark.parametrize("_dim,detector", ALL_STUBS)
def test_stub_algo_version_is_positive(_dim, detector):
    assert isinstance(detector.algo_version, int)
    assert detector.algo_version >= 1


@pytest.mark.parametrize("expected_dim,detector", ALL_STUBS)
def test_stub_score_returns_empty_with_insufficient_data(expected_dim, detector, features, baseline):
    result = detector.score(features, baseline)
    assert isinstance(result, DimensionResult)
    assert result.dimension is expected_dim
    assert result.score == 0
    assert result.has_flag(FlagBit.INSUFFICIENT_DATA)
    # No spurious sub-scores from a stub
    assert dict(result.sub_scores) == {}


@pytest.mark.parametrize("_dim,detector", ALL_STUBS)
def test_stub_is_deterministic(_dim, detector, features, baseline):
    r1 = detector.score(features, baseline)
    r2 = detector.score(features, baseline)
    assert r1 == r2


# =============================================================================
# Registry
# =============================================================================

class TestDefaultRegistry:

    def test_default_registry_has_all_five(self):
        reg = default_registry()
        keys = set(reg.all().keys())
        assert keys == set(DimensionId.ordered())

    def test_default_registry_returns_correct_detector_per_slot(self):
        reg = default_registry()
        for dim in DimensionId.ordered():
            assert reg.get(dim).dimension is dim

    def test_default_registry_algo_versions(self):
        reg = default_registry()
        versions = reg.algo_versions()
        assert set(versions.keys()) == set(DimensionId.ordered())
        for v in versions.values():
            assert v >= 1


class TestDetectorRegistryValidation:

    def test_rejects_missing_dimension(self):
        # Build with only 4 of 5
        bad = {
            DimensionId.DRIFT: DriftDetector(),
            DimensionId.ANOMALY: AnomalyDetector(),
            DimensionId.PERFORMANCE: PerformanceDetector(),
            DimensionId.CONSISTENCY: ConsistencyDetector(),
            # SECURITY missing
        }
        with pytest.raises(ValueError, match="five DimensionIds"):
            DetectorRegistry(bad)

    def test_rejects_mismatched_slot(self):
        # Put a SecurityDetector into the DRIFT slot
        bad = {
            DimensionId.DRIFT:       SecurityDetector(),   # MISMATCH
            DimensionId.ANOMALY:     AnomalyDetector(),
            DimensionId.PERFORMANCE: PerformanceDetector(),
            DimensionId.CONSISTENCY: ConsistencyDetector(),
            DimensionId.SECURITY:    SecurityDetector(),
        }
        with pytest.raises(ValueError, match="mismatched wiring"):
            DetectorRegistry(bad)

    def test_rejects_non_detector(self):
        class NotADetector:
            pass
        bad = {
            DimensionId.DRIFT:       NotADetector(),       # not a Detector
            DimensionId.ANOMALY:     AnomalyDetector(),
            DimensionId.PERFORMANCE: PerformanceDetector(),
            DimensionId.CONSISTENCY: ConsistencyDetector(),
            DimensionId.SECURITY:    SecurityDetector(),
        }
        with pytest.raises(TypeError, match="Detector Protocol"):
            DetectorRegistry(bad)

    def test_registry_is_immutable(self):
        reg = default_registry()
        # Internal map is wrapped in MappingProxyType — direct mutation fails.
        with pytest.raises(TypeError):
            reg.all()[DimensionId.DRIFT] = AnomalyDetector()   # type: ignore[index]
