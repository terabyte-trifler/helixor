"""
tests/slashing/test_consensus.py — the oracle-consensus policies.

A slash moves real SOL, so a single node must not trigger one alone. These
tests pin the consensus policies: SingleNodeConsensus (today) and
ThresholdConsensus (the Phase-4 BFT policy).
"""

from __future__ import annotations

import pytest

from slashing.consensus import (
    ConsensusPolicy,
    NodeVerdict,
    SingleNodeConsensus,
    ThresholdConsensus,
)


def _verdict(node_id: str, confirms: bool, score: int = 100) -> NodeVerdict:
    return NodeVerdict(
        node_id=node_id, confirms_compromise=confirms,
        score=score, immediate_red=confirms,
    )


# =============================================================================
# NodeVerdict
# =============================================================================

class TestNodeVerdict:

    def test_valid_verdict(self):
        v = _verdict("n0", True)
        assert v.node_id == "n0"
        assert v.confirms_compromise is True

    def test_empty_node_id_rejected(self):
        with pytest.raises(ValueError):
            NodeVerdict(node_id="", confirms_compromise=True,
                        score=100, immediate_red=True)

    def test_out_of_range_score_rejected(self):
        with pytest.raises(ValueError):
            NodeVerdict(node_id="n0", confirms_compromise=True,
                        score=1001, immediate_red=True)


# =============================================================================
# SingleNodeConsensus
# =============================================================================

class TestSingleNodeConsensus:

    def test_satisfies_protocol(self):
        assert isinstance(SingleNodeConsensus(), ConsensusPolicy)

    def test_lone_confirming_verdict_confirms(self):
        result = SingleNodeConsensus().evaluate([_verdict("n0", True)])
        assert result.confirmed is True
        assert result.vote_summary == "1/1"

    def test_lone_non_confirming_verdict_does_not_confirm(self):
        result = SingleNodeConsensus().evaluate([_verdict("n0", False)])
        assert result.confirmed is False
        assert result.vote_summary == "0/1"

    def test_rejects_multiple_verdicts(self):
        # SingleNodeConsensus is for one node — a cluster needs Threshold.
        with pytest.raises(ValueError):
            SingleNodeConsensus().evaluate([
                _verdict("n0", True), _verdict("n1", True),
            ])

    def test_rejects_zero_verdicts(self):
        with pytest.raises(ValueError):
            SingleNodeConsensus().evaluate([])

    def test_policy_name_is_honest(self):
        # The policy name says "single-node" — not pretending to be a cluster.
        assert SingleNodeConsensus().name == "single-node"


# =============================================================================
# ThresholdConsensus — the Phase-4 BFT policy
# =============================================================================

class TestThresholdConsensus:

    def test_satisfies_protocol(self):
        assert isinstance(
            ThresholdConsensus(cluster_size=3, threshold=2), ConsensusPolicy
        )

    def test_two_of_three_confirms(self):
        policy = ThresholdConsensus(cluster_size=3, threshold=2)
        result = policy.evaluate([
            _verdict("n0", True), _verdict("n1", True), _verdict("n2", False),
        ])
        assert result.confirmed is True
        assert result.vote_summary == "2/3"

    def test_one_of_three_does_not_confirm(self):
        policy = ThresholdConsensus(cluster_size=3, threshold=2)
        result = policy.evaluate([
            _verdict("n0", True), _verdict("n1", False), _verdict("n2", False),
        ])
        assert result.confirmed is False
        assert result.vote_summary == "1/3"

    def test_unanimous_confirms(self):
        policy = ThresholdConsensus(cluster_size=3, threshold=2)
        result = policy.evaluate([
            _verdict("n0", True), _verdict("n1", True), _verdict("n2", True),
        ])
        assert result.confirmed is True
        assert result.vote_summary == "3/3"

    def test_exactly_threshold_confirms(self):
        # Exactly `threshold` confirming votes is enough — boundary.
        policy = ThresholdConsensus(cluster_size=5, threshold=3)
        verdicts = [_verdict(f"n{i}", i < 3) for i in range(5)]
        assert policy.evaluate(verdicts).confirmed is True

    def test_one_below_threshold_does_not(self):
        policy = ThresholdConsensus(cluster_size=5, threshold=3)
        verdicts = [_verdict(f"n{i}", i < 2) for i in range(5)]
        assert policy.evaluate(verdicts).confirmed is False

    def test_tolerates_one_malicious_node(self):
        # 2-of-3: one node lying (False when it should confirm) still lets
        # the honest majority confirm — BFT tolerance.
        policy = ThresholdConsensus(cluster_size=3, threshold=2)
        result = policy.evaluate([
            _verdict("honest0", True),
            _verdict("honest1", True),
            _verdict("malicious", False),
        ])
        assert result.confirmed is True

    def test_rejects_duplicate_node(self):
        policy = ThresholdConsensus(cluster_size=3, threshold=2)
        with pytest.raises(ValueError, match="duplicate"):
            policy.evaluate([_verdict("n0", True), _verdict("n0", True)])

    def test_rejects_oversized_verdict_set(self):
        policy = ThresholdConsensus(cluster_size=3, threshold=2)
        with pytest.raises(ValueError):
            policy.evaluate([_verdict(f"n{i}", True) for i in range(4)])

    def test_invalid_threshold_rejected(self):
        with pytest.raises(ValueError):
            ThresholdConsensus(cluster_size=3, threshold=0)
        with pytest.raises(ValueError):
            ThresholdConsensus(cluster_size=3, threshold=4)

    def test_invalid_cluster_size_rejected(self):
        with pytest.raises(ValueError):
            ThresholdConsensus(cluster_size=0, threshold=1)

    def test_policy_name_describes_the_threshold(self):
        policy = ThresholdConsensus(cluster_size=3, threshold=2)
        assert policy.name == "threshold-2-of-3"

    def test_deterministic(self):
        # Same verdict set -> same result, every time (cluster nodes must
        # all reach the identical conclusion).
        policy = ThresholdConsensus(cluster_size=3, threshold=2)
        verdicts = [_verdict("n0", True), _verdict("n1", True),
                    _verdict("n2", False)]
        first = policy.evaluate(verdicts)
        for _ in range(20):
            r = policy.evaluate(verdicts)
            assert r.confirmed == first.confirmed
            assert r.confirming_votes == first.confirming_votes
