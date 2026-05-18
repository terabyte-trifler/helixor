"""
tests/scoring/test_composite_v2.py — Composite Scorer v2, Day 13.

THE DAY-13 DONE-WHEN
--------------------
"The full pipeline (100 features -> baseline -> 5 detectors -> composite)
 produces a real 0-1000 score with a 5-dimension breakdown; all components
 tested; the score is deterministic for fixed input."

These tests exercise the composite through the real engine, so they cover
the genuine 100-feature -> baseline -> 5-detector -> composite path.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone

import pytest

from baseline import compute_baseline
from detection import DimensionId, default_registry, run_detection_engine
from features import ExtractionWindow, FeatureVector, Transaction, extract
from scoring import AlertTier
from scoring.composite import SCORING_ALGO_VERSION, ScoreResult, compute_composite_score


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
PROG_JUPITER = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"


# =============================================================================
# Pipeline fixtures — real transactions through the real extractor
# =============================================================================

def _transactions(program: str = PROG_JUPITER, days: int = 30) -> list[Transaction]:
    """A healthy agent's transaction history — varied, mostly successful."""
    txs: list[Transaction] = []
    for d in range(days):
        for k in range(5):
            i = d * 5 + k
            txs.append(Transaction(
                signature=f"S{i:08d}".ljust(64, "x"),
                slot=100_000_000 + i,
                block_time=REF_END - timedelta(hours=d * 24 + k * 2 + 1),
                success=(i % 20) != 0,
                program_ids=(program,),
                sol_change=1_000_000 if k % 2 == 0 else -400_000,
                fee=5000,
                priority_fee=1000 if k % 3 == 0 else 0,
                compute_units=200_000,
                counterparty=f"cp{i % 7}",
            ))
    return txs


def _pipeline(*, previous_score: int | None = None) -> ScoreResult:
    """Run the full 100-feature -> baseline -> 5-detector -> composite path."""
    w30 = ExtractionWindow.ending_at(REF_END, days=30)
    w1 = ExtractionWindow.ending_at(REF_END, days=1)
    history = _transactions()
    baseline = compute_baseline("agentX", history, w30, computed_at=REF_END)
    current = extract(_transactions(days=1), w1)
    return run_detection_engine(
        current, baseline, default_registry(),
        previous_score=previous_score, computed_at=REF_END,
    )


# =============================================================================
# THE DONE-WHEN — full pipeline produces a real 0-1000, 5-dimension score
# =============================================================================

class TestFullPipeline:

    def test_pipeline_produces_valid_score(self):
        result = _pipeline()
        assert isinstance(result, ScoreResult)
        assert 0 <= result.score <= 1000

    def test_pipeline_has_five_dimension_breakdown(self):
        result = _pipeline()
        assert set(result.dimension_results.keys()) == set(DimensionId.ordered())
        # Every dimension contributed a real (non-stub) result.
        for dim in DimensionId.ordered():
            assert result.dimension_results[dim].dimension is dim

    def test_pipeline_clean_agent_scores_well(self):
        result = _pipeline()
        assert result.score > 600
        assert result.alert in (AlertTier.GREEN, AlertTier.YELLOW)

    def test_weighted_contributions_cover_all_dimensions(self):
        result = _pipeline()
        assert set(result.weighted_contributions.keys()) == set(DimensionId.ordered())

    def test_scoring_algo_version_is_2(self):
        result = _pipeline()
        assert result.scoring_algo_version == 2
        assert SCORING_ALGO_VERSION == 2


# =============================================================================
# THE DONE-WHEN — determinism for fixed input
# =============================================================================

class TestDeterminism:

    def test_pipeline_deterministic(self):
        a = _pipeline()
        b = _pipeline()
        assert a == b

    def test_pipeline_deterministic_repeated(self):
        first = _pipeline()
        for _ in range(10):
            assert _pipeline() == first

    def test_score_stable_across_runs(self):
        scores = {_pipeline().score for _ in range(5)}
        assert len(scores) == 1


# =============================================================================
# Confidence
# =============================================================================

class TestConfidence:

    def test_confidence_present_and_in_range(self):
        result = _pipeline()
        assert 0 <= result.confidence <= 1000

    def test_full_history_high_confidence(self):
        # The fixture is a 30-day, 150-tx agent → confidence should be high.
        result = _pipeline()
        assert result.confidence >= 900

    def test_sparse_agent_low_confidence(self):
        # A 3-day, 15-tx agent → low confidence.
        w3 = ExtractionWindow.ending_at(REF_END, days=3)
        w1 = ExtractionWindow.ending_at(REF_END, days=1)
        history = _transactions(days=3)
        baseline = compute_baseline("sparse", history, w3, computed_at=REF_END)
        current = extract(_transactions(days=1), w1)
        result = run_detection_engine(
            current, baseline, default_registry(), computed_at=REF_END,
        )
        assert result.confidence < 500


# =============================================================================
# Gaming detection
# =============================================================================

class TestGamingDetection:

    def _baseline_with_entropy(self, action_entropy: float):
        """A baseline whose action_entropy can be set directly."""
        w30 = ExtractionWindow.ending_at(REF_END, days=30)
        base = compute_baseline("agentG", _transactions(), w30, computed_at=REF_END)
        return dataclasses.replace(base, action_entropy=action_entropy)

    def _features_with_entropy(self, seq_action_entropy: float) -> FeatureVector:
        """A feature vector whose seq_action_entropy can be set directly."""
        w1 = ExtractionWindow.ending_at(REF_END, days=1)
        feats = extract(_transactions(days=1), w1)
        return dataclasses.replace(feats, seq_action_entropy=seq_action_entropy)

    def test_entropy_collapse_flags_gaming(self):
        # Baseline entropy 0.90, current entropy 0.40 — a 55% collapse.
        baseline = self._baseline_with_entropy(0.90)
        features = self._features_with_entropy(0.40)
        result = compute_composite_score(
            {dim: run_detection_engine(features, baseline, default_registry(),
                                       computed_at=REF_END).dimension_results[dim]
             for dim in DimensionId.ordered()},
            baseline,
            features=features,
            computed_at=REF_END,
        )
        assert result.gaming_detected is True
        assert result.gaming_drop_fraction > 0.25

    def test_stable_entropy_no_gaming_flag(self):
        baseline = self._baseline_with_entropy(0.90)
        features = self._features_with_entropy(0.88)
        engine_result = run_detection_engine(
            features, baseline, default_registry(), computed_at=REF_END,
        )
        assert engine_result.gaming_detected is False

    def test_gaming_fields_present_on_pipeline(self):
        result = _pipeline()
        assert isinstance(result.gaming_detected, bool)
        assert 0.0 <= result.gaming_drop_fraction <= 1.0


# =============================================================================
# 200-point delta guard rail
# =============================================================================

class TestDeltaGuardRail:

    def test_no_previous_score_no_clamp(self):
        result = _pipeline(previous_score=None)
        assert result.delta_clamped is False

    def test_large_jump_is_clamped(self):
        # The clean pipeline scores ~900. With a previous score of 400, the
        # ~500-point jump must be clamped to +200 → 600.
        result = _pipeline(previous_score=400)
        assert result.delta_clamped is True
        assert result.score == 600

    def test_clamp_cannot_be_bypassed(self):
        # Whatever the raw score, the result can never be more than 200 from
        # the previous score.
        for prev in (0, 200, 500, 800, 1000):
            result = _pipeline(previous_score=prev)
            assert abs(result.score - prev) <= 200

    def test_small_change_not_clamped(self):
        # A previous score close to the real score → no clamp.
        real = _pipeline().score
        result = _pipeline(previous_score=real - 50)
        assert result.delta_clamped is False
        assert result.score == real

    def test_clamped_score_still_valid_result(self):
        # A clamped ScoreResult is still internally consistent.
        result = _pipeline(previous_score=100)
        assert 0 <= result.score <= 1000
        assert result.alert is not None


# =============================================================================
# ScoreResult v2 shape
# =============================================================================

class TestScoreResultShape:

    def test_carries_all_v2_fields(self):
        result = _pipeline()
        # Day-13 fields exist and are typed.
        assert isinstance(result.confidence, int)
        assert isinstance(result.gaming_detected, bool)
        assert isinstance(result.gaming_drop_fraction, float)
        assert isinstance(result.delta_clamped, bool)

    def test_frozen(self):
        result = _pipeline()
        with pytest.raises((AttributeError, dataclasses.FrozenInstanceError)):
            result.score = 0  # type: ignore[misc]

    def test_provenance_chain_intact(self):
        result = _pipeline()
        assert result.baseline_stats_hash
        assert result.feature_schema_fingerprint
        assert result.scoring_schema_fingerprint
