"""
tests/oracle/test_byzantine_cluster.py — the Day-26 done-when.

"A deliberately-Byzantine node (returns a wildly wrong score) is detected,
 excluded from aggregation, and challenged."

These tests run the full commit-reveal + Byzantine-detection epoch across a
3-node cluster with a node made deliberately Byzantine, and prove
detection, exclusion, and (after repeated offence) escalation to an
on-chain challenge.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from oracle.cluster import (
    ByzantineWatchdog,
    InProcessRegistry,
    InProcessTransport,
    NodeKeypair,
    run_byzantine_epoch,
)
from oracle.cluster.messages import AgentScore
from oracle.node import ClusterMembership, OracleNode
from tests.oracle.agent_profiles import profile_adversarial, profile_stable_a


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


def _submit():
    calls: list[dict] = []

    def _s(wallet, aggregated):
        calls.append({"wallet": wallet, "score": aggregated.score})
        return calls[-1]

    return _s, calls


def _build_cluster(n: int = 3):
    registry = InProcessRegistry()
    kps = [NodeKeypair.from_seed(f"oracle-node-{i}", f"seed{i}".encode())
           for i in range(n)]
    nodes = []
    for i, kp in enumerate(kps):
        peers = tuple(kps[j].identity for j in range(n) if j != i)
        node = OracleNode(
            kp, ClusterMembership(kp.identity, peers),
            transport=InProcessTransport(registry),
        )
        registry.register(node.node_id, node)
        nodes.append(node)
    return registry, nodes


def _reset(nodes):
    """Clear per-epoch round state so the cluster can run the next epoch."""
    for n in nodes:
        n._rounds.clear()
        n._epoch_scores.clear()
        n._epoch_nonces.clear()


def _wildly_wrong(score: int = 40):
    """A corruptor that drives every score to a wildly wrong fixed value."""
    def _corrupt(scores: dict) -> dict:
        return {
            w: AgentScore(w, score, 0, 0, False, score)
            for w in scores
        }
    return _corrupt


# =============================================================================
# DONE-WHEN — Byzantine node detected, excluded, challenged
# =============================================================================

class TestByzantineNodeDetectedAndExcluded:

    def test_byzantine_node_is_detected(self):
        """A node returning a wildly wrong score is flagged Byzantine."""
        registry, nodes = _build_cluster(3)
        nodes[2].make_byzantine(_wildly_wrong(40))
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()

        report = run_byzantine_epoch(
            nodes, 26, [profile_adversarial()],
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
        )
        assert "oracle-node-2" in report.byzantine_nodes

    def test_byzantine_node_is_excluded_from_aggregation(self):
        """The Byzantine node's score is left out of the median."""
        registry, nodes = _build_cluster(3)
        nodes[2].make_byzantine(_wildly_wrong(40))
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()

        report = run_byzantine_epoch(
            nodes, 26, [profile_adversarial()],
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
        )
        result = report.results[0]
        assert "oracle-node-2" in result.excluded_nodes
        # The aggregated score is the HONEST median — not corrupted toward 40.
        assert result.aggregated is not None
        assert result.aggregated.score > 400      # the real adversarial score
        assert result.aggregated.score != 40

    def test_cluster_continues_with_the_honest_majority(self):
        """The 2 honest nodes still form a quorum and produce a score."""
        registry, nodes = _build_cluster(3)
        nodes[2].make_byzantine(_wildly_wrong(40))
        submit, calls = _submit()
        watchdog = ByzantineWatchdog()

        report = run_byzantine_epoch(
            nodes, 26, [profile_adversarial(), profile_stable_a()],
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
        )
        # Both agents scored + submitted from the honest majority.
        assert report.submitted_count == 2
        assert report.quorum_failure_count == 0
        assert len(calls) == 2

    def test_byzantine_node_is_challenged_after_repeated_offence(self):
        """
        THE DONE-WHEN: a node Byzantine across multiple epochs triggers a
        challenge_oracle.
        """
        registry, nodes = _build_cluster(3)
        nodes[2].make_byzantine(_wildly_wrong(40))
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()
        filed = []

        # Three epochs of Byzantine behaviour -> three strikes -> challenge.
        for epoch in (26, 27, 28):
            run_byzantine_epoch(
                nodes, epoch, [profile_adversarial()],
                submit_fn=submit, watchdog=watchdog,
                challenge_fn=filed.append, computed_at=REF_END,
            )
            _reset(nodes)

        assert len(filed) == 1
        assert filed[0].accused_node == "oracle-node-2"
        assert filed[0].strikes == 3
        assert watchdog.is_challenged("oracle-node-2") is True

    def test_challenge_carries_the_conflict_evidence(self):
        registry, nodes = _build_cluster(3)
        nodes[2].make_byzantine(_wildly_wrong(40))
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()
        filed = []

        for epoch in (26, 27, 28):
            run_byzantine_epoch(
                nodes, epoch, [profile_adversarial()],
                submit_fn=submit, watchdog=watchdog,
                challenge_fn=filed.append, computed_at=REF_END,
            )
            _reset(nodes)

        challenge = filed[0]
        # The challenge cites the node's deviating score vs the median —
        # conflicting-score evidence (ProofType.ConflictingScores = 0).
        assert challenge.proof_type == 0
        assert challenge.accused_score == 40
        assert challenge.cluster_median != 40
        assert len(challenge.flagged_epochs) == 3


# =============================================================================
# A single bad epoch does NOT trigger a challenge
# =============================================================================

class TestSingleEpochDoesNotChallenge:

    def test_one_bad_epoch_is_not_enough_to_challenge(self):
        # A transient one-off deviation must not slash a node.
        registry, nodes = _build_cluster(3)
        nodes[2].make_byzantine(_wildly_wrong(40))
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()
        filed = []

        report = run_byzantine_epoch(
            nodes, 26, [profile_adversarial()],
            submit_fn=submit, watchdog=watchdog,
            challenge_fn=filed.append, computed_at=REF_END,
        )
        # Detected and excluded — but only one strike, no challenge.
        assert "oracle-node-2" in report.byzantine_nodes
        assert filed == []
        assert watchdog.strikes_for("oracle-node-2") == 1
        assert watchdog.is_challenged("oracle-node-2") is False

    def test_a_node_that_recovers_is_not_challenged(self):
        # Byzantine for 2 epochs, then honest — never reaches 3 strikes.
        registry, nodes = _build_cluster(3)
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()
        filed = []

        nodes[2].make_byzantine(_wildly_wrong(40))
        for epoch in (26, 27):
            run_byzantine_epoch(
                nodes, epoch, [profile_adversarial()],
                submit_fn=submit, watchdog=watchdog,
                challenge_fn=filed.append, computed_at=REF_END,
            )
            _reset(nodes)

        # Node recovers — honest again.
        nodes[2].make_honest()
        for epoch in (28, 29, 30):
            run_byzantine_epoch(
                nodes, epoch, [profile_adversarial()],
                submit_fn=submit, watchdog=watchdog,
                challenge_fn=filed.append, computed_at=REF_END,
            )
            _reset(nodes)

        # 2 strikes, never reached 3 -> no challenge.
        assert watchdog.strikes_for("oracle-node-2") == 2
        assert filed == []


# =============================================================================
# An honest cluster flags nobody
# =============================================================================

class TestHonestCluster:

    def test_honest_cluster_flags_no_byzantine_nodes(self):
        registry, nodes = _build_cluster(3)
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()

        report = run_byzantine_epoch(
            nodes, 26, [profile_adversarial(), profile_stable_a()],
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
        )
        assert report.byzantine_nodes == ()
        assert report.challenges_filed == ()
        for result in report.results:
            assert result.excluded_nodes == ()

    def test_honest_cluster_over_many_epochs_challenges_nobody(self):
        registry, nodes = _build_cluster(3)
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()
        filed = []

        for epoch in range(26, 32):
            run_byzantine_epoch(
                nodes, epoch, [profile_adversarial()],
                submit_fn=submit, watchdog=watchdog,
                challenge_fn=filed.append, computed_at=REF_END,
            )
            _reset(nodes)
        assert filed == []
        assert watchdog.challenged_nodes() == frozenset()


# =============================================================================
# Determinism
# =============================================================================

class TestDeterminism:

    def test_byzantine_epoch_is_deterministic(self):
        def _run():
            _, nodes = _build_cluster(3)
            nodes[2].make_byzantine(_wildly_wrong(40))
            submit, _ = _submit()
            watchdog = ByzantineWatchdog()
            report = run_byzantine_epoch(
                nodes, 26, [profile_adversarial(), profile_stable_a()],
                submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
            )
            return (
                report.byzantine_nodes,
                tuple(r.aggregated.score for r in report.results),
            )

        first = _run()
        for _ in range(5):
            assert _run() == first
