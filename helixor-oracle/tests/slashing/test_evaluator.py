"""
tests/slashing/test_evaluator.py — the tiered slash decision.

Pins the core Day-22 rule: a merely-degrading agent is NOT slashed; only a
security-dimension IMMEDIATE_RED confirmed by the oracle cluster triggers a
slash. Also pins compute_slash_amount as byte-identical to the on-chain math.
"""

from __future__ import annotations

import pytest

from detection.types import DimensionId, DimensionResult, FlagBit
from scoring import AlertTier, ScoreResult
from scoring.composite import SCORING_ALGO_VERSION

from slashing.consensus import ConsensusResult
from slashing.evaluator import (
    OffenseTier,
    compute_slash_amount,
    evaluate_slash,
    verdict_from_score,
)


# =============================================================================
# Helpers — build a minimal valid ScoreResult
# =============================================================================

def _dimension(dim: DimensionId, score: int, flags: int = 0) -> DimensionResult:
    from detection.types import DIMENSION_MAX_SCORES
    return DimensionResult(
        dimension=dim,
        score=score,
        max_score=DIMENSION_MAX_SCORES[dim],
        flags=flags,
        sub_scores={},
        algo_version=1,
    )


def _score_result(
    *,
    score: int,
    alert: AlertTier,
    security_flags: int = 0,
    immediate_red: bool = False,
) -> ScoreResult:
    """A minimal valid ScoreResult with a controllable security dimension."""
    from datetime import datetime, timezone

    dims = {
        DimensionId.DRIFT:       _dimension(DimensionId.DRIFT, 180),
        DimensionId.ANOMALY:     _dimension(DimensionId.ANOMALY, 180),
        DimensionId.PERFORMANCE: _dimension(DimensionId.PERFORMANCE, 180),
        DimensionId.CONSISTENCY: _dimension(DimensionId.CONSISTENCY, 180),
        DimensionId.SECURITY:    _dimension(
            DimensionId.SECURITY, 140, flags=security_flags),
    }
    # weighted_contributions must sum to score — split it across dims.
    each = score // 5
    contributions = {d: each for d in DimensionId.ordered()}
    contributions[DimensionId.DRIFT] += score - each * 5

    return ScoreResult(
        score=score,
        alert=alert,
        confidence=1000,
        gaming_detected=False,
        gaming_drop_fraction=0.0,
        delta_clamped=False,
        dimension_results=dims,
        weighted_contributions=contributions,
        weight_vector={d: 0.2 for d in DimensionId.ordered()},
        aggregated_flags=security_flags,
        immediate_red=immediate_red,
        scoring_algo_version=SCORING_ALGO_VERSION,
        scoring_weights_version=1,
        scoring_schema_fingerprint="0" * 64,
        feature_schema_fingerprint="0" * 64,
        baseline_stats_hash="0" * 64,
        detector_algo_versions={d: 1 for d in DimensionId.ordered()},
        computed_at=datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc),
    )


def _consensus(confirmed: bool, votes: int = 1, total: int = 1) -> ConsensusResult:
    return ConsensusResult(
        confirmed=confirmed, confirming_votes=votes,
        total_nodes=total, policy="test",
    )


WALLET = "agentxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
IR = int(FlagBit.IMMEDIATE_RED)


# =============================================================================
# The core rule — degradation is not a slashable offense
# =============================================================================

class TestNoSlashForDegradation:

    def test_low_score_without_security_flag_is_not_slashed(self):
        # A RED agent — but RED from drift/anomaly, NOT a security
        # compromise. The security dimension did not flag. No slash.
        sr = _score_result(score=120, alert=AlertTier.RED, security_flags=0)
        decision = evaluate_slash(sr, _consensus(False), agent_wallet=WALLET)
        assert decision.should_slash is False
        assert decision.tier is None
        assert "degradation is not a slashable offense" in decision.reason

    def test_green_agent_not_slashed(self):
        sr = _score_result(score=900, alert=AlertTier.GREEN)
        decision = evaluate_slash(sr, _consensus(False), agent_wallet=WALLET)
        assert decision.should_slash is False

    def test_yellow_agent_not_slashed(self):
        sr = _score_result(score=550, alert=AlertTier.YELLOW)
        decision = evaluate_slash(sr, _consensus(False), agent_wallet=WALLET)
        assert decision.should_slash is False


# =============================================================================
# The core rule — security flag alone is NOT enough; needs consensus
# =============================================================================

class TestSecurityFlagNeedsConsensus:

    def test_security_immediate_red_without_consensus_is_not_slashed(self):
        # The security dimension flagged a compromise — but the oracle
        # cluster did NOT confirm it. Treated as a low score, not a slash.
        sr = _score_result(
            score=120, alert=AlertTier.RED, security_flags=IR,
            immediate_red=True,
        )
        decision = evaluate_slash(sr, _consensus(False), agent_wallet=WALLET)
        assert decision.should_slash is False
        assert decision.security_immediate_red is True
        assert decision.consensus_confirmed is False
        assert "did not confirm" in decision.reason

    def test_security_immediate_red_with_consensus_is_slashed(self):
        # Security flagged AND the cluster confirmed -> a confirmed
        # compromise -> SLASH at the COMPROMISE tier.
        sr = _score_result(
            score=120, alert=AlertTier.RED, security_flags=IR,
            immediate_red=True,
        )
        decision = evaluate_slash(sr, _consensus(True), agent_wallet=WALLET)
        assert decision.should_slash is True
        assert decision.tier is OffenseTier.COMPROMISE
        assert decision.tier.is_terminal is True


# =============================================================================
# verdict_from_score — the per-node bridge
# =============================================================================

class TestVerdictFromScore:

    def test_security_flag_makes_a_confirming_verdict(self):
        sr = _score_result(
            score=120, alert=AlertTier.RED, security_flags=IR,
            immediate_red=True,
        )
        verdict = verdict_from_score("node-0", sr)
        assert verdict.confirms_compromise is True
        assert verdict.node_id == "node-0"

    def test_no_security_flag_makes_a_non_confirming_verdict(self):
        sr = _score_result(score=900, alert=AlertTier.GREEN)
        verdict = verdict_from_score("node-0", sr)
        assert verdict.confirms_compromise is False


# =============================================================================
# compute_slash_amount — byte-identical to the on-chain Rust
# =============================================================================

class TestComputeSlashAmount:

    def test_minor_takes_five_percent(self):
        assert compute_slash_amount(1_000_000_000, OffenseTier.MINOR) == 50_000_000

    def test_major_takes_fifty_percent(self):
        assert compute_slash_amount(1_000_000_000, OffenseTier.MAJOR) == 500_000_000

    def test_compromise_takes_the_whole_stake(self):
        assert compute_slash_amount(
            1_000_000_000, OffenseTier.COMPROMISE) == 1_000_000_000

    def test_compromise_takes_everything_on_odd_amounts(self):
        # The on-chain code's terminal guard — no dust left behind.
        for stake in [1, 7, 999, 12_345_678, 33_333_333]:
            assert compute_slash_amount(stake, OffenseTier.COMPROMISE) == stake

    def test_never_exceeds_the_stake(self):
        for stake in [0, 1, 100, 10_000_000, 2**63]:
            for tier in OffenseTier:
                assert compute_slash_amount(stake, tier) <= stake

    def test_zero_stake_slashes_zero(self):
        for tier in OffenseTier:
            assert compute_slash_amount(0, tier) == 0

    def test_large_stake_does_not_lose_precision(self):
        # The u128-intermediate path: a near-u64::MAX stake, 50% slash.
        big = 2**63
        amount = compute_slash_amount(big, OffenseTier.MAJOR)
        # Mirrors the Rust: (big * 5000) // 10000.
        assert amount == (big * 5_000) // 10_000

    def test_negative_stake_rejected(self):
        with pytest.raises(ValueError):
            compute_slash_amount(-1, OffenseTier.MINOR)

    def test_offense_tier_codes_match_onchain(self):
        # The wire codes MUST match the on-chain OffenseTier enum.
        assert OffenseTier.MINOR == 0
        assert OffenseTier.MAJOR == 1
        assert OffenseTier.COMPROMISE == 2


# =============================================================================
# Determinism
# =============================================================================

class TestDeterminism:

    def test_decision_is_deterministic(self):
        sr = _score_result(
            score=120, alert=AlertTier.RED, security_flags=IR,
            immediate_red=True,
        )
        first = evaluate_slash(sr, _consensus(True), agent_wallet=WALLET)
        for _ in range(20):
            d = evaluate_slash(sr, _consensus(True), agent_wallet=WALLET)
            assert d.should_slash == first.should_slash
            assert d.tier == first.tier
