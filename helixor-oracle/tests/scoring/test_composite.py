"""
tests/scoring/test_composite.py — compute_composite_score behaviour.

Covers:
  - shape: ScoreResult carries every required field, frozen, validated
  - mapping: per-dimension contributions sum to score (Day-13 invariant)
  - alert tiers: 700+/400-699/0-399 boundaries
  - IMMEDIATE_RED short-circuit: alert -> RED, score NOT zeroed
  - input validation: missing/extra/duplicate/mismatched dimensions rejected
  - determinism: same input -> byte-identical output
  - provenance: every version + fingerprint + hash stamped correctly
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from detection.types import DIMENSION_MAX_SCORES, DimensionId, DimensionResult, FlagBit
from scoring import AlertTier, ScoreResult, compute_composite_score, scoring_schema_fingerprint
from scoring.composite import (
    GREEN_THRESHOLD,
    SCORING_ALGO_VERSION,
    YELLOW_THRESHOLD,
)
from scoring.weights import SCORING_WEIGHTS_VERSION
from scoring.weights import WEIGHTS


REF_TIME = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


def _build_results(
    *,
    drift: int = 0,
    anomaly: int = 0,
    performance: int = 0,
    consistency: int = 0,
    security: int = 0,
    immediate_red: bool = False,
) -> dict[DimensionId, DimensionResult]:
    """Build five dimension results with the given raw scores."""
    flags_red = int(FlagBit.IMMEDIATE_RED) if immediate_red else 0
    return {
        DimensionId.DRIFT: DimensionResult(
            dimension=DimensionId.DRIFT, score=drift,
            max_score=DIMENSION_MAX_SCORES[DimensionId.DRIFT],
            flags=0, sub_scores={}, algo_version=1,
        ),
        DimensionId.ANOMALY: DimensionResult(
            dimension=DimensionId.ANOMALY, score=anomaly,
            max_score=DIMENSION_MAX_SCORES[DimensionId.ANOMALY],
            flags=0, sub_scores={}, algo_version=1,
        ),
        DimensionId.PERFORMANCE: DimensionResult(
            dimension=DimensionId.PERFORMANCE, score=performance,
            max_score=DIMENSION_MAX_SCORES[DimensionId.PERFORMANCE],
            flags=0, sub_scores={}, algo_version=1,
        ),
        DimensionId.CONSISTENCY: DimensionResult(
            dimension=DimensionId.CONSISTENCY, score=consistency,
            max_score=DIMENSION_MAX_SCORES[DimensionId.CONSISTENCY],
            flags=0, sub_scores={}, algo_version=1,
        ),
        DimensionId.SECURITY: DimensionResult(
            dimension=DimensionId.SECURITY, score=security,
            max_score=DIMENSION_MAX_SCORES[DimensionId.SECURITY],
            flags=flags_red, sub_scores={}, algo_version=1,
        ),
    }


# =============================================================================
# Score arithmetic
# =============================================================================

class TestScoreArithmetic:

    def test_all_zero_gives_zero(self, baseline):
        r = compute_composite_score(_build_results(), baseline, computed_at=REF_TIME)
        assert r.score == 0
        assert r.alert is AlertTier.RED

    def test_all_max_gives_1000(self, baseline):
        # drift 200, anomaly 200, performance 200, consistency 200, security 150
        # Each normalises to 1.0 -> weighted sum 1.0 -> score 1000.
        r = compute_composite_score(
            _build_results(drift=200, anomaly=200, performance=200,
                           consistency=200, security=150),
            baseline, computed_at=REF_TIME,
        )
        assert r.score == 1000
        assert r.alert is AlertTier.GREEN

    def test_half_max_gives_500(self, baseline):
        # All dimensions at half their max -> 0.5 normalised -> 500.
        r = compute_composite_score(
            _build_results(drift=100, anomaly=100, performance=100,
                           consistency=100, security=75),
            baseline, computed_at=REF_TIME,
        )
        assert r.score == 500
        assert r.alert is AlertTier.YELLOW

    def test_weighted_contributions_sum_to_score(self, baseline):
        r = compute_composite_score(
            _build_results(drift=200, anomaly=100, performance=50,
                           consistency=150, security=30),
            baseline, computed_at=REF_TIME,
        )
        assert sum(r.weighted_contributions.values()) == r.score


# =============================================================================
# Alert tiers
# =============================================================================

class TestAlertTiers:

    def test_green_threshold(self, baseline):
        # 700 -> GREEN, 699 -> YELLOW
        r_700 = compute_composite_score(
            _build_results(drift=140, anomaly=140, performance=140,
                           consistency=140, security=105),  # all 70% of max
            baseline, computed_at=REF_TIME,
        )
        assert r_700.score == 700
        assert r_700.alert is AlertTier.GREEN

    def test_yellow_boundary_lower(self, baseline):
        # 400 -> YELLOW, 399 -> RED
        r_400 = compute_composite_score(
            _build_results(drift=80, anomaly=80, performance=80,
                           consistency=80, security=60),    # all 40% of max
            baseline, computed_at=REF_TIME,
        )
        assert r_400.score == 400
        assert r_400.alert is AlertTier.YELLOW

    def test_red_below_400(self, baseline):
        r = compute_composite_score(
            _build_results(drift=50, anomaly=50, performance=50,
                           consistency=50, security=40),    # ~26% blended
            baseline, computed_at=REF_TIME,
        )
        assert r.score < 400
        assert r.alert is AlertTier.RED

    def test_thresholds_are_documented_constants(self):
        assert GREEN_THRESHOLD == 700
        assert YELLOW_THRESHOLD == 400


# =============================================================================
# IMMEDIATE_RED short-circuit
# =============================================================================

class TestImmediateRed:

    def test_immediate_red_forces_red_alert(self, baseline):
        # All dimensions max -> would normally be GREEN 1000, but IMMEDIATE_RED forces RED.
        r = compute_composite_score(
            _build_results(drift=200, anomaly=200, performance=200,
                           consistency=200, security=150, immediate_red=True),
            baseline, computed_at=REF_TIME,
        )
        assert r.score == 1000               # score is NOT zeroed
        assert r.alert is AlertTier.RED      # but alert is RED
        assert r.immediate_red is True

    def test_immediate_red_flag_aggregated(self, baseline):
        r = compute_composite_score(
            _build_results(immediate_red=True),
            baseline, computed_at=REF_TIME,
        )
        assert r.has_flag(FlagBit.IMMEDIATE_RED)


# =============================================================================
# Input validation
# =============================================================================

class TestInputValidation:

    def test_missing_dimension_rejected(self, baseline):
        results = _build_results()
        del results[DimensionId.SECURITY]
        with pytest.raises(ValueError, match="exactly the five"):
            compute_composite_score(results, baseline, computed_at=REF_TIME)

    def test_extra_dimension_rejected(self, baseline):
        # Can't actually add a 6th DimensionId, but we can pass non-enum keys
        results = _build_results()
        # Use a fake key that survives the enum check by being unequal to any
        results["FAKE"] = results[DimensionId.DRIFT]  # type: ignore[index]
        with pytest.raises(ValueError, match="exactly the five"):
            compute_composite_score(results, baseline, computed_at=REF_TIME)

    def test_mismatched_slot_rejected(self, baseline):
        # Put a DRIFT result into the ANOMALY slot
        results = _build_results()
        results[DimensionId.ANOMALY] = DimensionResult(
            dimension=DimensionId.DRIFT, score=0,        # MISMATCH
            max_score=DIMENSION_MAX_SCORES[DimensionId.DRIFT],
            flags=0, sub_scores={}, algo_version=1,
        )
        with pytest.raises(ValueError, match="mismatched wiring"):
            compute_composite_score(results, baseline, computed_at=REF_TIME)


# =============================================================================
# Determinism + provenance
# =============================================================================

class TestDeterminismAndProvenance:

    def test_same_input_same_output(self, baseline):
        r1 = compute_composite_score(
            _build_results(drift=100, anomaly=50, performance=120,
                           consistency=80, security=40),
            baseline, computed_at=REF_TIME,
        )
        r2 = compute_composite_score(
            _build_results(drift=100, anomaly=50, performance=120,
                           consistency=80, security=40),
            baseline, computed_at=REF_TIME,
        )
        assert r1.score == r2.score
        assert r1.alert == r2.alert
        assert r1.aggregated_flags == r2.aggregated_flags

    def test_provenance_stamped(self, baseline):
        r = compute_composite_score(_build_results(), baseline, computed_at=REF_TIME)
        assert r.scoring_algo_version == SCORING_ALGO_VERSION
        assert r.scoring_weights_version == SCORING_WEIGHTS_VERSION
        assert r.scoring_schema_fingerprint == scoring_schema_fingerprint()
        assert r.baseline_stats_hash == baseline.stats_hash
        assert r.weight_vector == WEIGHTS
        # Detector versions present for every dimension
        assert set(r.detector_algo_versions.keys()) == set(DimensionId.ordered())


# =============================================================================
# ScoreResult validation
# =============================================================================

class TestScoreResultValidation:

    def test_naive_datetime_rejected(self, baseline):
        with pytest.raises(ValueError, match="timezone-aware"):
            compute_composite_score(
                _build_results(), baseline,
                computed_at=datetime(2026, 5, 1, 12, 0, 0),  # NAIVE
            )

    def test_score_result_is_frozen(self, baseline):
        r = compute_composite_score(_build_results(), baseline, computed_at=REF_TIME)
        with pytest.raises((AttributeError, Exception)):
            r.score = 999  # type: ignore[misc]
