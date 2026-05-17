"""
tests/detection/test_engine.py — run_detection_engine end-to-end.

Covers:
  - Happy path: registry of stubs -> valid 0-1000 ScoreResult, score = 0,
    every flag set to INSUFFICIENT_DATA (the Day-4 done-when).
  - Isolation barrier: a broken detector does NOT crash the engine.
  - Defensive checks: a detector returning the wrong type / dimension is caught.
"""

from __future__ import annotations

import pytest

from detection import (
    DetectorContractError,
    DetectorInternalError,
    DetectorRegistry,
    DimensionId,
    DimensionResult,
    FlagBit,
    default_registry,
    run_detection_engine,
)
from detection.anomaly import AnomalyDetector
from detection.consistency import ConsistencyDetector
from detection.drift import DriftDetector
from detection.performance import PerformanceDetector
from detection.security import SecurityDetector
from scoring import AlertTier, ScoreResult


# =============================================================================
# Happy path: stubs through to ScoreResult
# =============================================================================

class TestHappyPath:

    def test_runs_end_to_end_with_default_registry(self, features, baseline):
        result = run_detection_engine(features, baseline, default_registry())
        assert isinstance(result, ScoreResult)
        # Drift/anomaly/security are real now; performance + consistency are
        # still stubs, so this clean sample lands in the middle band.
        assert 400 <= result.score < 700
        assert result.alert is AlertTier.YELLOW
        # INSUFFICIENT_DATA still aggregates from the remaining stub dimensions.
        assert result.has_flag(FlagBit.INSUFFICIENT_DATA)
        # No IMMEDIATE_RED came from any detector.
        assert not result.immediate_red

    def test_all_five_dimension_results_present(self, features, baseline):
        result = run_detection_engine(features, baseline, default_registry())
        assert set(result.dimension_results.keys()) == set(DimensionId.ordered())
        for dim in DimensionId.ordered():
            r = result.dimension_results[dim]
            assert r.dimension is dim
        # DRIFT + ANOMALY + SECURITY are real now → may be non-zero.
        # PERFORMANCE / CONSISTENCY are still Day-4 stubs → zero.
        assert result.dimension_results[DimensionId.PERFORMANCE].score == 0
        assert result.dimension_results[DimensionId.CONSISTENCY].score == 0
        assert result.dimension_results[DimensionId.SECURITY].score > 0

    def test_weighted_contributions_sum_to_score(self, features, baseline):
        # Day-13 invariant carried into V2.
        result = run_detection_engine(features, baseline, default_registry())
        assert sum(result.weighted_contributions.values()) == result.score


# =============================================================================
# Isolation barrier
# =============================================================================

class _RaisingDetector:
    """A detector that always raises a given exception class."""
    def __init__(self, dim, exc_class, msg="boom"):
        self._dim = dim
        self._exc = exc_class
        self._msg = msg
    @property
    def dimension(self):
        return self._dim
    @property
    def algo_version(self):
        return 1
    def score(self, features, baseline):
        raise self._exc(self._msg)


class _BadReturnDetector:
    """A detector that returns the wrong TYPE — engine must catch this."""
    def __init__(self, dim, returns):
        self._dim = dim
        self._ret = returns
    @property
    def dimension(self):
        return self._dim
    @property
    def algo_version(self):
        return 1
    def score(self, features, baseline):
        return self._ret


def _registry_replacing(dim, replacement):
    """Build a registry replacing one slot with `replacement`."""
    detectors = {
        DimensionId.DRIFT:       DriftDetector(),
        DimensionId.ANOMALY:     AnomalyDetector(),
        DimensionId.PERFORMANCE: PerformanceDetector(),
        DimensionId.CONSISTENCY: ConsistencyDetector(),
        DimensionId.SECURITY:    SecurityDetector(),
    }
    detectors[dim] = replacement
    return DetectorRegistry(detectors)


class TestIsolationBarrier:

    def test_contract_error_substitutes_empty_with_flags(self, features, baseline):
        bad = _RaisingDetector(DimensionId.DRIFT, DetectorContractError)
        reg = _registry_replacing(DimensionId.DRIFT, bad)
        result = run_detection_engine(features, baseline, reg)
        drift = result.dimension_results[DimensionId.DRIFT]
        assert drift.score == 0
        assert drift.has_flag(FlagBit.INSUFFICIENT_DATA)
        assert drift.has_flag(FlagBit.INCOMPATIBLE_INPUT)

    def test_internal_error_substitutes_empty(self, features, baseline):
        bad = _RaisingDetector(DimensionId.ANOMALY, DetectorInternalError)
        reg = _registry_replacing(DimensionId.ANOMALY, bad)
        result = run_detection_engine(features, baseline, reg)
        anom = result.dimension_results[DimensionId.ANOMALY]
        assert anom.score == 0
        assert anom.has_flag(FlagBit.INSUFFICIENT_DATA)
        # INCOMPATIBLE_INPUT is reserved for contract errors only
        assert not anom.has_flag(FlagBit.INCOMPATIBLE_INPUT)

    def test_unexpected_exception_does_not_crash_engine(self, features, baseline):
        bad = _RaisingDetector(DimensionId.SECURITY, RuntimeError)  # not a DetectorError
        reg = _registry_replacing(DimensionId.SECURITY, bad)
        # Engine MUST NOT propagate the exception.
        result = run_detection_engine(features, baseline, reg)
        sec = result.dimension_results[DimensionId.SECURITY]
        assert sec.score == 0
        assert sec.has_flag(FlagBit.INSUFFICIENT_DATA)

    def test_one_broken_does_not_break_others(self, features, baseline):
        bad = _RaisingDetector(DimensionId.DRIFT, RuntimeError)
        reg = _registry_replacing(DimensionId.DRIFT, bad)
        result = run_detection_engine(features, baseline, reg)
        # The other four still ran and produced valid empty results.
        for dim in DimensionId.ordered():
            assert isinstance(result.dimension_results[dim], DimensionResult)

    def test_non_dimension_result_return_is_substituted(self, features, baseline):
        bad = _BadReturnDetector(DimensionId.CONSISTENCY, returns="not a result")
        reg = _registry_replacing(DimensionId.CONSISTENCY, bad)
        result = run_detection_engine(features, baseline, reg)
        cons = result.dimension_results[DimensionId.CONSISTENCY]
        assert isinstance(cons, DimensionResult)
        assert cons.has_flag(FlagBit.INSUFFICIENT_DATA)

    def test_wrong_dimension_return_is_substituted(self, features, baseline):
        # Detector for CONSISTENCY slot returns a SECURITY-tagged result
        wrong = DimensionResult.empty(DimensionId.SECURITY)
        bad = _BadReturnDetector(DimensionId.CONSISTENCY, returns=wrong)
        reg = _registry_replacing(DimensionId.CONSISTENCY, bad)
        result = run_detection_engine(features, baseline, reg)
        cons = result.dimension_results[DimensionId.CONSISTENCY]
        assert cons.dimension is DimensionId.CONSISTENCY  # corrected
        assert cons.has_flag(FlagBit.INSUFFICIENT_DATA)
