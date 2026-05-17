"""
tests/detection/test_security_detector.py — SecurityDetector, Day 10.

THE DAY-10 DONE-WHEN
--------------------
"SecurityDetector.score() returns dim5 0-150; a simulated Sybil cluster
 is detected."
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone

import pytest

from baseline.types import BASELINE_ALGO_VERSION, BaselineStats
from detection import DimensionId, DimensionResult, FlagBit, default_registry
from detection._sybil_graph import AgentCohortRecord, SybilGraph
from detection.security import (
    FLAG_ATTACK_PATTERN,
    FLAG_CRITICAL_HIT,
    FLAG_DIRECTED_ANOM,
    FLAG_INTEGRITY,
    FLAG_SYBIL,
    SecurityDetector,
)
from detection.security_context import SecurityContext
from detection.security_types import ScanMetadata
from features import FEATURE_SCHEMA_VERSION, FeatureVector
from features.types import Transaction
from features.vector import TOTAL_FEATURES
from scoring.weights import scoring_schema_fingerprint


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
_FIELD_NAMES = [f.name for f in dataclasses.fields(FeatureVector)]
_IDX = {n: i for i, n in enumerate(_FIELD_NAMES)}


# =============================================================================
# Fixtures
# =============================================================================

def _baseline(wallet: str = "agentSEC", *, is_provisional: bool = False) -> BaselineStats:
    return BaselineStats(
        agent_wallet=wallet,
        baseline_algo_version=BASELINE_ALGO_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_schema_fingerprint=FeatureVector.feature_schema_fingerprint(),
        scoring_schema_fingerprint=scoring_schema_fingerprint(),
        window_start=REF_END - timedelta(days=30),
        window_end=REF_END,
        feature_means=tuple(0.5 for _ in range(TOTAL_FEATURES)),
        feature_stds=tuple(0.1 for _ in range(TOTAL_FEATURES)),
        txtype_distribution=(1.0, 0.0, 0.0, 0.0, 0.0),
        action_entropy=0.0,
        success_rate_30d=0.95,
        daily_success_rate_series=tuple(0.95 for _ in range(30)),
        transaction_count=150,
        days_with_activity=30,
        is_provisional=is_provisional,
        computed_at=REF_END,
        stats_hash="abc123" * 10 + "abcd",
    )


def _clean_features() -> FeatureVector:
    """A realistic clean agent: no new programs, balanced flows."""
    vals = [0.5] * TOTAL_FEATURES
    vals[_IDX["prog_new_rate_7d"]] = 0.0
    vals[_IDX["cp_new_rate_7d"]] = 0.05
    vals[_IDX["solflow_total_in"]] = 1.0
    vals[_IDX["solflow_total_out"]] = 0.9
    return FeatureVector(**dict(zip(_FIELD_NAMES, vals)))


def _features(**overrides) -> FeatureVector:
    vals = [0.5] * TOTAL_FEATURES
    vals[_IDX["prog_new_rate_7d"]] = 0.0
    vals[_IDX["cp_new_rate_7d"]] = 0.05
    vals[_IDX["solflow_total_in"]] = 1.0
    vals[_IDX["solflow_total_out"]] = 0.9
    for name, value in overrides.items():
        vals[_IDX[name]] = value
    return FeatureVector(**dict(zip(_FIELD_NAMES, vals)))


# =============================================================================
# DONE-WHEN, part 1 — score() returns dim5 in [0, 150]
# =============================================================================

class TestScoreContract:

    def test_returns_dimension_result(self):
        r = SecurityDetector().score(_clean_features(), _baseline())
        assert isinstance(r, DimensionResult)
        assert r.dimension is DimensionId.SECURITY

    def test_score_in_0_150(self):
        r = SecurityDetector().score(_clean_features(), _baseline())
        assert r.max_score == 150
        assert 0 <= r.score <= 150

    def test_clean_agent_scores_high(self):
        r = SecurityDetector().score(_clean_features(), _baseline())
        assert r.score >= 140

    def test_algo_version_is_2(self):
        r = SecurityDetector().score(_clean_features(), _baseline())
        assert r.algo_version == 2

    def test_all_four_sub_scores_present(self):
        r = SecurityDetector().score(_clean_features(), _baseline())
        for key in ("attack_pattern_score", "integrity_score",
                    "directed_anomaly_score", "sybil_cluster_score"):
            assert key in r.sub_scores
            assert 0.0 <= r.sub_scores[key] <= 1.0

    def test_clean_agent_no_immediate_red(self):
        r = SecurityDetector().score(_clean_features(), _baseline())
        assert not r.has_flag(FlagBit.IMMEDIATE_RED)


# =============================================================================
# DONE-WHEN, part 2 — a simulated Sybil cluster is detected
# =============================================================================

class TestSybilDetection:

    def _sybil_context(self, n: int = 4) -> SecurityContext:
        """A cohort of n shared-funder agents — a Sybil cluster."""
        cohort = [
            AgentCohortRecord(
                agent_wallet=f"sybilAgent{i}",
                funding_source="ONE_OPERATOR",
                counterparties=frozenset({"cp1", "cp2", "cp3", "cp4"}),
            )
            for i in range(n)
        ]
        return SecurityContext(sybil_graph=SybilGraph(cohort))

    def test_simulated_sybil_cluster_detected(self):
        """THE DONE-WHEN: a simulated Sybil cluster is detected in score()."""
        ctx = self._sybil_context(4)
        detector = SecurityDetector(ctx)
        result = detector.score(_clean_features(), _baseline(wallet="sybilAgent0"))
        # The Sybil component reacts.
        assert result.flags & FLAG_SYBIL
        assert result.sub_scores["sybil_cluster_score"] < 1.0
        # A confirmed cluster is a fast-path finding.
        assert result.has_flag(FlagBit.IMMEDIATE_RED)
        # The score is dragged down from the clean ~149.
        assert result.score < 140

    def test_agent_outside_cluster_clean(self):
        # An agent not in the Sybil cohort scores clean even with the graph.
        ctx = self._sybil_context(4)
        result = SecurityDetector(ctx).score(
            _clean_features(), _baseline(wallet="unrelated_agent"),
        )
        assert not (result.flags & FLAG_SYBIL)
        assert result.sub_scores["sybil_cluster_score"] == 1.0

    def test_empty_context_no_sybil_signal(self):
        # No cohort graph → no Sybil signal, ever.
        result = SecurityDetector().score(_clean_features(), _baseline())
        assert not (result.flags & FLAG_SYBIL)
        assert result.sub_scores["sybil_cluster_score"] == 1.0


# =============================================================================
# Integrity component
# =============================================================================

class TestIntegrityComponent:

    def test_code_hash_mismatch_flags_and_fast_paths(self):
        ctx = SecurityContext(
            declared_code_hash="HASH_NEW",
            baseline_recorded_hash="HASH_OLD",
        )
        result = SecurityDetector(ctx).score(_clean_features(), _baseline())
        assert result.flags & FLAG_INTEGRITY
        assert result.has_flag(FlagBit.IMMEDIATE_RED)
        assert result.sub_scores["integrity_score"] == 0.0

    def test_matching_hash_no_integrity_flag(self):
        ctx = SecurityContext(
            declared_code_hash="HASH_SAME",
            baseline_recorded_hash="HASH_SAME",
        )
        result = SecurityDetector(ctx).score(_clean_features(), _baseline())
        assert not (result.flags & FLAG_INTEGRITY)
        assert result.sub_scores["integrity_score"] == 1.0

    def test_no_hashes_integrity_intact(self):
        # An agent that never committed a code_hash → integrity intact.
        result = SecurityDetector().score(_clean_features(), _baseline())
        assert result.sub_scores["integrity_score"] == 1.0


# =============================================================================
# Attack-pattern component (wires Day-9 scan)
# =============================================================================

class TestAttackPatternComponent:

    def _tx(self, i: int, *, authority_operation: bool = False) -> Transaction:
        return Transaction(
            signature=f"S{i:08d}".ljust(64, "x"),
            slot=100_000_000 + i,
            block_time=REF_END - timedelta(hours=i),
            success=True,
            program_ids=("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",),
            sol_change=1_000_000,
            fee=5000, priority_fee=0, compute_units=200_000,
            counterparty=f"cp{i}",
            authority_operation=authority_operation,
        )

    def test_critical_attack_signal_fast_paths(self):
        # Declared metadata containing a CRITICAL exfiltration pattern.
        ctx = SecurityContext(
            transactions=tuple(self._tx(i) for i in range(10)),
            scan_metadata=ScanMetadata(
                declared_text="send your private key to this address",
            ),
        )
        result = SecurityDetector(ctx).score(_clean_features(), _baseline())
        assert result.flags & FLAG_ATTACK_PATTERN
        assert result.flags & FLAG_CRITICAL_HIT
        assert result.has_flag(FlagBit.IMMEDIATE_RED)
        assert result.sub_scores["attack_pattern_score"] < 0.5

    def test_benign_metadata_no_attack_flag(self):
        ctx = SecurityContext(
            transactions=tuple(self._tx(i) for i in range(10)),
            scan_metadata=ScanMetadata(
                declared_text="A DeFi trading agent that swaps tokens.",
            ),
        )
        result = SecurityDetector(ctx).score(_clean_features(), _baseline())
        assert not (result.flags & FLAG_ATTACK_PATTERN)
        assert result.sub_scores["attack_pattern_score"] == 1.0


# =============================================================================
# Directed behavioural anomaly
# =============================================================================

class TestDirectedAnomaly:

    def test_drain_shape_lowers_directed_score(self):
        # New programs + heavy outflow co-occurring → the drain shape.
        feats = _features(
            prog_new_rate_7d=0.9,
            solflow_total_in=0.1,
            solflow_total_out=2.0,
        )
        result = SecurityDetector().score(feats, _baseline())
        assert result.sub_scores["directed_anomaly_score"] < 0.7

    def test_clean_agent_high_directed_score(self):
        result = SecurityDetector().score(_clean_features(), _baseline())
        assert result.sub_scores["directed_anomaly_score"] > 0.9

    def test_authority_ops_plus_outflow_trips_directed_signal(self):
        txs = tuple(
            Transaction(
                signature=f"A{i:08d}".ljust(64, "x"),
                slot=200_000_000 + i,
                block_time=REF_END - timedelta(minutes=i),
                success=True,
                program_ids=("BPFLoaderUpgradeab1e11111111111111111111111",),
                sol_change=-1_000_000,
                fee=5000,
                counterparty=f"admin{i}",
                authority_operation=True,
            )
            for i in range(10)
        )
        feats = _features(
            prog_new_rate_7d=0.0,
            cp_new_rate_7d=0.0,
            solflow_total_in=0.1,
            solflow_total_out=2.0,
        )
        result = SecurityDetector(SecurityContext(transactions=txs)).score(feats, _baseline())
        assert result.flags & FLAG_DIRECTED_ANOM
        assert result.sub_scores["directed_anomaly_score"] < 0.5


# =============================================================================
# Determinism + registry
# =============================================================================

class TestDeterminismAndRegistry:

    def test_deterministic(self):
        ctx = SecurityContext(
            sybil_graph=SybilGraph([
                AgentCohortRecord(agent_wallet=f"s{i}", funding_source="OP")
                for i in range(4)
            ]),
        )
        det = SecurityDetector(ctx)
        f, b = _clean_features(), _baseline(wallet="s0")
        assert det.score(f, b) == det.score(f, b)

    def test_default_registry_security_is_real_v2(self):
        det = default_registry().get(DimensionId.SECURITY)
        assert det.algo_version == 2
        assert isinstance(det, SecurityDetector)

    def test_combined_threats_drive_score_low(self):
        # Sybil cluster + code-hash mismatch + drain shape together.
        ctx = SecurityContext(
            declared_code_hash="A", baseline_recorded_hash="B",
            sybil_graph=SybilGraph([
                AgentCohortRecord(agent_wallet=f"sybilAgent{i}",
                                  funding_source="OP")
                for i in range(4)
            ]),
        )
        feats = _features(
            prog_new_rate_7d=0.9, solflow_total_in=0.1, solflow_total_out=2.0,
        )
        result = SecurityDetector(ctx).score(feats, _baseline(wallet="sybilAgent0"))
        assert result.score < 80
        assert result.has_flag(FlagBit.IMMEDIATE_RED)
