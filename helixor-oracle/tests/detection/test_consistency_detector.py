"""
tests/detection/test_consistency_detector.py — ConsistencyDetector, Day 12.

THE DAY-12 DONE-WHEN
--------------------
"ConsistencyDetector.score() returns dim4 0-200; an agent that abruptly
 changes behavioural domain scores low on consistency."
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone

import pytest

from baseline.types import BASELINE_ALGO_VERSION, BaselineStats
from detection import DimensionId, DimensionResult, FlagBit, default_registry
from detection.consistency import (
    FLAG_DOMAIN_DRIFT,
    FLAG_RHYTHM_BROKEN,
    FLAG_TOOL_INSTABILITY,
    ConsistencyDetector,
)
from detection.consistency_context import ConsistencyContext
from features import FEATURE_SCHEMA_VERSION, FeatureVector
from features.vector import TOTAL_FEATURES, group_of


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
_FIELD_NAMES = [f.name for f in dataclasses.fields(FeatureVector)]
_IDX = {n: i for i, n in enumerate(_FIELD_NAMES)}
_TXTYPE = ("txtype_swap_frac", "txtype_lend_frac", "txtype_stake_frac",
           "txtype_transfer_frac", "txtype_other_frac")
_PROGRAM_IDX = [i for i, n in enumerate(_FIELD_NAMES) if group_of(n) == "programs"]


# =============================================================================
# Fixtures
# =============================================================================

def _baseline(*, program_means: list[float] | None = None) -> BaselineStats:
    means = [0.5] * TOTAL_FEATURES
    if program_means is not None:
        for slot, idx in enumerate(_PROGRAM_IDX):
            means[idx] = program_means[slot]
    return BaselineStats(
        agent_wallet="agentCONS",
        baseline_algo_version=BASELINE_ALGO_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_schema_fingerprint=FeatureVector.feature_schema_fingerprint(),
        window_start=REF_END - timedelta(days=30),
        window_end=REF_END,
        feature_means=tuple(means),
        feature_stds=tuple(0.1 for _ in range(TOTAL_FEATURES)),
        txtype_distribution=(1.0, 0.0, 0.0, 0.0, 0.0),
        action_entropy=0.0,
        success_rate_30d=0.95,
        daily_success_rate_series=tuple([0.95] * 30),
        transaction_count=150,
        days_with_activity=30,
        is_provisional=False,
        computed_at=REF_END,
        stats_hash="abc" * 21 + "a",
    )


def _features(
    *,
    txtype: tuple[float, ...] = (0.2, 0.2, 0.2, 0.2, 0.2),
    program_values: list[float] | None = None,
    rhythm_shift: float = 0.0,
    repeat_ratio: float = 0.3,
    success_volatility: float = 0.05,
) -> FeatureVector:
    vals = [0.5] * TOTAL_FEATURES
    for name, v in zip(_TXTYPE, txtype):
        vals[_IDX[name]] = v
    if program_values is not None:
        for slot, idx in enumerate(_PROGRAM_IDX):
            vals[idx] = program_values[slot]
    if rhythm_shift:
        for i, n in enumerate(_FIELD_NAMES):
            if group_of(n) == "rhythm":
                vals[i] = 0.5 + rhythm_shift
    vals[_IDX["cp_repeat_ratio"]] = repeat_ratio
    vals[_IDX["success_volatility"]] = success_volatility
    return FeatureVector(**dict(zip(_FIELD_NAMES, vals)))


# =============================================================================
# DONE-WHEN, part 1 — score() returns dim4 in [0, 200]
# =============================================================================

class TestScoreContract:

    def test_returns_dimension_result(self):
        r = ConsistencyDetector().score(_features(), _baseline())
        assert isinstance(r, DimensionResult)
        assert r.dimension is DimensionId.CONSISTENCY

    def test_score_in_0_200(self):
        r = ConsistencyDetector().score(_features(), _baseline())
        assert r.max_score == 200
        assert 0 <= r.score <= 200

    def test_algo_version_is_2(self):
        r = ConsistencyDetector().score(_features(), _baseline())
        assert r.algo_version == 2

    def test_all_four_sub_scores_present(self):
        r = ConsistencyDetector().score(_features(), _baseline())
        for key in ("tool_stability", "rhythm_regularity",
                    "counterparty_consistency", "domain_alignment"):
            assert key in r.sub_scores
            assert 0.0 <= r.sub_scores[key] <= 1.0


# =============================================================================
# DONE-WHEN, part 2 — abrupt domain change scores low
# =============================================================================

class TestDomainDriftDetection:

    def test_lending_agent_doing_lending_scores_high(self):
        # A lending agent whose txtype-mix matches the lending profile.
        ctx = ConsistencyContext(declared_domain="lending")
        feats = _features(txtype=(0.10, 0.70, 0.05, 0.10, 0.05))
        r = ConsistencyDetector(ctx).score(feats, _baseline())
        assert r.sub_scores["domain_alignment"] > 0.8
        assert not (r.flags & FLAG_DOMAIN_DRIFT)

    def test_lending_agent_doing_nft_mints_scores_low(self):
        """
        THE DONE-WHEN: an agent declaring "lending" but behaving like an
        NFT-marketplace agent scores low on consistency.
        """
        ctx = ConsistencyContext(declared_domain="lending")
        # An NFT-marketplace txtype-mix — almost all "other".
        feats = _features(txtype=(0.10, 0.02, 0.03, 0.25, 0.60))
        r = ConsistencyDetector(ctx).score(feats, _baseline())
        # Domain alignment collapses.
        assert r.sub_scores["domain_alignment"] < 0.5
        assert r.flags & FLAG_DOMAIN_DRIFT
        # The overall dimension score is dragged down.
        assert r.score < 160

    def test_domain_drift_lowers_score_vs_aligned(self):
        ctx = ConsistencyContext(declared_domain="defi-trading")
        base = _baseline()
        aligned = ConsistencyDetector(ctx).score(
            _features(txtype=(0.75, 0.05, 0.05, 0.10, 0.05)), base,
        )
        drifted = ConsistencyDetector(ctx).score(
            _features(txtype=(0.05, 0.05, 0.05, 0.05, 0.80)), base,
        )
        assert drifted.score < aligned.score

    def test_no_declared_domain_classifier_abstains(self):
        # No declared domain → domain_alignment is full marks, no penalty.
        r = ConsistencyDetector().score(_features(), _baseline())
        assert r.sub_scores["domain_alignment"] == 1.0
        assert not (r.flags & FLAG_DOMAIN_DRIFT)

    def test_unknown_domain_classifier_abstains(self):
        # A domain Helixor has no profile for → abstain, no penalty.
        ctx = ConsistencyContext(declared_domain="quantum-underwriting")
        r = ConsistencyDetector(ctx).score(_features(), _baseline())
        assert r.sub_scores["domain_alignment"] == 1.0


# =============================================================================
# Tool-stability
# =============================================================================

class TestToolStability:

    def test_stable_program_mix_high(self):
        # Current program-mix == baseline program-mix.
        pm = [0.5] * len(_PROGRAM_IDX)
        r = ConsistencyDetector().score(
            _features(program_values=pm), _baseline(program_means=pm),
        )
        assert r.sub_scores["tool_stability"] > 0.9

    def test_reshaped_program_mix_low(self):
        # Baseline program-mix concentrated on slot 0; current on the last.
        n = len(_PROGRAM_IDX)
        base_pm = [1.0] + [0.0] * (n - 1)
        cur_pm = [0.0] * (n - 1) + [1.0]
        r = ConsistencyDetector().score(
            _features(program_values=cur_pm), _baseline(program_means=base_pm),
        )
        assert r.sub_scores["tool_stability"] < 0.5
        assert r.flags & FLAG_TOOL_INSTABILITY


# =============================================================================
# Rhythm regularity
# =============================================================================

class TestRhythmRegularity:

    def test_unchanged_rhythm_high(self):
        r = ConsistencyDetector().score(_features(rhythm_shift=0.0), _baseline())
        assert r.sub_scores["rhythm_regularity"] == 1.0

    def test_broken_rhythm_low(self):
        # Every rhythm feature shifted far from baseline.
        r = ConsistencyDetector().score(_features(rhythm_shift=0.45), _baseline())
        assert r.sub_scores["rhythm_regularity"] < 0.5
        assert r.flags & FLAG_RHYTHM_BROKEN


# =============================================================================
# Counterparty-outcome consistency
# =============================================================================

class TestCounterpartyConsistency:

    def test_repeat_cps_stable_outcomes_high(self):
        r = ConsistencyDetector().score(
            _features(repeat_ratio=0.9, success_volatility=0.0), _baseline(),
        )
        assert r.sub_scores["counterparty_consistency"] > 0.95

    def test_repeat_cps_erratic_outcomes_low(self):
        r = ConsistencyDetector().score(
            _features(repeat_ratio=0.9, success_volatility=0.5), _baseline(),
        )
        assert r.sub_scores["counterparty_consistency"] < 0.3

    def test_new_cps_erratic_outcomes_excused(self):
        # New counterparties → outcome variance expected → not penalised.
        r = ConsistencyDetector().score(
            _features(repeat_ratio=0.05, success_volatility=0.5), _baseline(),
        )
        assert r.sub_scores["counterparty_consistency"] > 0.9


# =============================================================================
# Determinism + registry
# =============================================================================

class TestDeterminismAndRegistry:

    def test_deterministic(self):
        det = ConsistencyDetector(ConsistencyContext(declared_domain="lending"))
        f, b = _features(txtype=(0.1, 0.7, 0.05, 0.1, 0.05)), _baseline()
        assert det.score(f, b) == det.score(f, b)

    def test_default_registry_consistency_is_real_v2(self):
        det = default_registry().get(DimensionId.CONSISTENCY)
        assert det.algo_version == 2
        assert isinstance(det, ConsistencyDetector)

    def test_fully_consistent_agent_scores_high(self):
        # Aligned domain, stable tools, unchanged rhythm, stable CP outcomes.
        ctx = ConsistencyContext(declared_domain="lending")
        pm = [0.5] * len(_PROGRAM_IDX)
        r = ConsistencyDetector(ctx).score(
            _features(
                txtype=(0.10, 0.70, 0.05, 0.10, 0.05),
                program_values=pm,
                rhythm_shift=0.0,
                repeat_ratio=0.8,
                success_volatility=0.02,
            ),
            _baseline(program_means=pm),
        )
        assert r.score >= 185
