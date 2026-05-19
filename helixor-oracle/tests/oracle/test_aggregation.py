"""
tests/oracle/test_aggregation.py — BFT median aggregation.

The cluster's robustness lives here: the median ignores a single outlier,
whether faulty, malicious, or absent. These tests pin that property and
the quorum rule.
"""

from __future__ import annotations

import pytest

from oracle.cluster.aggregation import (
    AggregatedScore,
    NodeScore,
    QuorumNotMet,
    aggregate_scores,
    quorum_for,
)
from oracle.cluster.messages import AgentScore


WALLET = "agentxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


def _score(score: int, *, alert: int = 0, flags: int = 0,
           ir: bool = False, conf: int = 900) -> AgentScore:
    return AgentScore(
        agent_wallet=WALLET, score=score, alert_tier=alert,
        flags=flags, immediate_red=ir, confidence=conf,
    )


def _nodes(*scores: AgentScore) -> list[NodeScore]:
    return [NodeScore(node_id=f"node-{i}", score=s)
            for i, s in enumerate(scores)]


# =============================================================================
# Quorum
# =============================================================================

class TestQuorum:

    def test_quorum_is_strict_majority(self):
        assert quorum_for(1) == 1
        assert quorum_for(3) == 2
        assert quorum_for(5) == 3

    def test_quorum_rejects_invalid_size(self):
        with pytest.raises(ValueError):
            quorum_for(0)

    def test_below_quorum_raises(self):
        # 1 of 3 — below the 2-node quorum.
        with pytest.raises(QuorumNotMet) as exc:
            aggregate_scores(WALLET, _nodes(_score(851)), cluster_size=3)
        assert exc.value.got == 1
        assert exc.value.needed == 2

    def test_exactly_quorum_aggregates(self):
        # 2 of 3 — exactly quorum, must succeed.
        result = aggregate_scores(
            WALLET, _nodes(_score(851), _score(851)), cluster_size=3,
        )
        assert result.score == 851

    def test_empty_submissions_raise_quorum(self):
        with pytest.raises(QuorumNotMet):
            aggregate_scores(WALLET, [], cluster_size=3)


# =============================================================================
# The median — the BFT core
# =============================================================================

class TestMedian:

    def test_three_identical_scores(self):
        result = aggregate_scores(
            WALLET, _nodes(_score(851), _score(851), _score(851)),
            cluster_size=3,
        )
        assert result.score == 851
        assert result.unanimous is True
        assert result.score_spread == 0

    def test_a_single_liar_cannot_move_the_median(self):
        # Two honest nodes at 851, one malicious at 12. Median = 851.
        result = aggregate_scores(
            WALLET, _nodes(_score(851), _score(851), _score(12)),
            cluster_size=3,
        )
        assert result.score == 851
        assert result.unanimous is False
        assert result.score_spread == 839

    def test_a_single_high_liar_cannot_move_the_median(self):
        # Malicious node inflating to 1000 — still ignored.
        result = aggregate_scores(
            WALLET, _nodes(_score(400), _score(400), _score(1000)),
            cluster_size=3,
        )
        assert result.score == 400

    def test_median_is_a_real_submitted_value(self):
        # Three different scores -> the median is the MIDDLE one, an
        # actual node's value, never an invented average.
        result = aggregate_scores(
            WALLET, _nodes(_score(300), _score(700), _score(900)),
            cluster_size=3,
        )
        assert result.score == 700

    def test_five_node_median_tolerates_two_faults(self):
        # 5 nodes, two faulty (0 and 1000). Median of the 3 honest = 851.
        result = aggregate_scores(
            WALLET,
            _nodes(_score(851), _score(851), _score(851),
                   _score(0), _score(1000)),
            cluster_size=5,
        )
        assert result.score == 851

    def test_even_count_takes_lower_middle(self):
        # 2 surviving nodes (3-node cluster, one offline). The median of an
        # even count is the LOWER middle — deterministic, conservative,
        # never an average.
        result = aggregate_scores(
            WALLET, _nodes(_score(400), _score(800)), cluster_size=3,
        )
        assert result.score == 400


# =============================================================================
# Non-numeric fields — flags by majority bit, immediate_red by majority
# =============================================================================

class TestFieldAggregation:

    def test_immediate_red_majority(self):
        # 2 of 3 say immediate_red -> True.
        result = aggregate_scores(
            WALLET,
            _nodes(_score(100, ir=True), _score(100, ir=True),
                   _score(900, ir=False)),
            cluster_size=3,
        )
        assert result.immediate_red is True

    def test_immediate_red_minority_is_false(self):
        # Only 1 of 3 says immediate_red -> False. A lone node cannot
        # force a compromise flag.
        result = aggregate_scores(
            WALLET,
            _nodes(_score(900, ir=False), _score(900, ir=False),
                   _score(100, ir=True)),
            cluster_size=3,
        )
        assert result.immediate_red is False

    def test_flags_aggregated_by_majority_bit(self):
        # Bit 3 (0x08) set by 2 of 3 -> kept. Bit 0 (0x01) set by 1 -> dropped.
        result = aggregate_scores(
            WALLET,
            _nodes(_score(100, flags=0x08), _score(100, flags=0x09),
                   _score(100, flags=0x00)),
            cluster_size=3,
        )
        # 0x08: nodes 0,1 set it -> majority -> kept.
        # 0x01: only node 1 set it -> minority -> dropped.
        assert result.flags == 0x08

    def test_a_lone_node_cannot_inject_a_flag(self):
        result = aggregate_scores(
            WALLET,
            _nodes(_score(100, flags=0), _score(100, flags=0),
                   _score(100, flags=0xFFFFFFFF)),
            cluster_size=3,
        )
        assert result.flags == 0


# =============================================================================
# Validation
# =============================================================================

class TestValidation:

    def test_mismatched_agent_rejected(self):
        other = AgentScore(
            agent_wallet="otherxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            score=100, alert_tier=0, flags=0, immediate_red=False,
            confidence=900,
        )
        with pytest.raises(ValueError, match="expected"):
            aggregate_scores(
                WALLET,
                [NodeScore("n0", _score(851)), NodeScore("n1", other)],
                cluster_size=3,
            )

    def test_duplicate_node_rejected(self):
        with pytest.raises(ValueError, match="duplicate"):
            aggregate_scores(
                WALLET,
                [NodeScore("n0", _score(851)), NodeScore("n0", _score(851))],
                cluster_size=3,
            )


# =============================================================================
# Determinism
# =============================================================================

class TestDeterminism:

    def test_aggregation_is_deterministic(self):
        nodes = _nodes(_score(851), _score(840), _score(12))
        first = aggregate_scores(WALLET, nodes, cluster_size=3)
        for _ in range(20):
            r = aggregate_scores(WALLET, nodes, cluster_size=3)
            assert r.score == first.score
            assert r.flags == first.flags
            assert r.immediate_red == first.immediate_red

    def test_node_order_does_not_matter(self):
        # The median is order-independent — submissions in any order
        # produce the identical result.
        a = aggregate_scores(
            WALLET, _nodes(_score(300), _score(700), _score(900)),
            cluster_size=3,
        )
        b = aggregate_scores(
            WALLET, _nodes(_score(900), _score(300), _score(700)),
            cluster_size=3,
        )
        assert a.score == b.score
