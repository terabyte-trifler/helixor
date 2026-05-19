"""
tests/oracle/test_cluster_runner.py — the Day-24 done-when.

"3 nodes score the same agent; the median is submitted; killing 1 node
 still produces a correct score from the remaining 2."

These tests run the real cluster epoch across a 3-node in-process cluster
(InProcessTransport is a faithful model of the network — it routes to the
peer's real handler), and prove the BFT property end to end.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from oracle.cluster import (
    ClusterEpochRunner,
    InProcessRegistry,
    InProcessTransport,
    NodeKeypair,
    simulate_cluster_epoch,
)
from oracle.node import ClusterMembership, OracleNode
from tests.oracle.agent_profiles import (
    profile_adversarial,
    profile_degrading,
    profile_stable_a,
)


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


def _submit():
    calls: list[dict] = []

    def _s(wallet, aggregated):
        record = {"wallet": wallet, "score": aggregated.score}
        calls.append(record)
        return record

    return _s, calls


def _build_cluster(n: int = 3):
    """Build an n-node in-process cluster. Returns (registry, nodes)."""
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


# =============================================================================
# DONE-WHEN 1 — 3 nodes score the same agent, the median is submitted
# =============================================================================

class TestThreeNodesMedianSubmitted:

    def test_three_nodes_score_and_submit_the_median(self):
        registry, nodes = _build_cluster(3)
        profiles = [profile_adversarial(), profile_stable_a()]
        submit, calls = _submit()

        report = simulate_cluster_epoch(
            nodes, 24, profiles, submit_fn=submit, computed_at=REF_END,
        )["oracle-node-0"]

        # All 3 nodes contributed.
        assert len(report.contributing_nodes) == 3
        assert report.agent_count == 2
        assert report.submitted_count == 2
        assert report.quorum_failure_count == 0

        # Each agent has an aggregated median score.
        for result in report.results:
            assert result.aggregated is not None
            assert result.aggregated.node_count == 3
            assert result.submitted is True

    def test_every_node_aggregates_the_identical_median(self):
        # No central coordinator — every node aggregates from its own
        # perspective. Because scoring + median are deterministic, all
        # nodes' reports carry the IDENTICAL aggregated scores.
        registry, nodes = _build_cluster(3)
        profiles = [profile_adversarial(), profile_stable_a()]
        submit, _ = _submit()

        reports = simulate_cluster_epoch(
            nodes, 24, profiles, submit_fn=submit, computed_at=REF_END,
        )

        per_node_medians = [
            tuple(r.aggregated.score for r in rep.results)
            for rep in reports.values()
        ]
        assert len(set(per_node_medians)) == 1, \
            "every node must aggregate the identical cluster median"

    def test_honest_cluster_is_unanimous(self):
        # Three honest nodes run the deterministic engine on identical
        # inputs -> identical scores -> the median has zero spread.
        registry, nodes = _build_cluster(3)
        submit, _ = _submit()
        report = simulate_cluster_epoch(
            nodes, 24, [profile_adversarial()],
            submit_fn=submit, computed_at=REF_END,
        )["oracle-node-0"]
        assert report.results[0].aggregated.unanimous is True


# =============================================================================
# DONE-WHEN 2 — killing 1 node still produces a correct score from 2
# =============================================================================

class TestKillOneNode:

    def test_cluster_survives_one_node_offline(self):
        """Killing 1 of 3 nodes — the remaining 2 still produce a score."""
        registry, nodes = _build_cluster(3)
        profiles = [profile_adversarial(), profile_stable_a()]
        submit, _ = _submit()

        # All three score the epoch...
        for node in nodes:
            node.score_epoch(24, profiles, computed_at=REF_END)

        # ...then node-2 goes offline (unregister = the process died).
        registry.unregister("oracle-node-2")

        # node-0 aggregates — it can reach node-1 but not node-2.
        report = ClusterEpochRunner(nodes[0]).run_epoch(
            24, profiles, submit_fn=submit, computed_at=REF_END,
        )

        # Quorum (2 of 3) still met — every agent gets a score.
        assert report.quorum_failure_count == 0
        assert report.submitted_count == 2
        assert set(report.contributing_nodes) == {
            "oracle-node-0", "oracle-node-1",
        }
        for result in report.results:
            assert result.aggregated is not None
            assert result.aggregated.node_count == 2

    def test_score_is_still_correct_with_one_node_down(self):
        # The 2-node median must equal the 3-node median when the two
        # survivors are honest (and the killed node was honest too).
        profiles = [profile_adversarial()]
        submit, _ = _submit()

        # 3-node baseline.
        _, nodes3 = _build_cluster(3)
        full = simulate_cluster_epoch(
            nodes3, 24, profiles, submit_fn=submit, computed_at=REF_END,
        )["oracle-node-0"]
        full_score = full.results[0].aggregated.score

        # Same cluster, node-2 killed.
        registry, nodes = _build_cluster(3)
        for node in nodes:
            node.score_epoch(24, profiles, computed_at=REF_END)
        registry.unregister("oracle-node-2")
        degraded = ClusterEpochRunner(nodes[0]).run_epoch(
            24, profiles, submit_fn=submit, computed_at=REF_END,
        )
        degraded_score = degraded.results[0].aggregated.score

        # The cluster still produces the CORRECT score from 2 nodes.
        assert degraded_score == full_score

    def test_two_nodes_offline_fails_quorum(self):
        # Killing 2 of 3 drops below the 2-node quorum — the cluster
        # correctly REFUSES to produce a score rather than trust one node.
        registry, nodes = _build_cluster(3)
        profiles = [profile_adversarial()]
        submit, _ = _submit()

        for node in nodes:
            node.score_epoch(24, profiles, computed_at=REF_END)
        registry.unregister("oracle-node-1")
        registry.unregister("oracle-node-2")

        report = ClusterEpochRunner(nodes[0]).run_epoch(
            24, profiles, submit_fn=submit, computed_at=REF_END,
        )
        assert report.quorum_failure_count == 1
        assert report.submitted_count == 0
        assert report.results[0].aggregated is None
        assert "quorum not met" in report.results[0].error

    def test_one_node_down_survivor_disagreement_refuses(self):
        # One offline node leaves bare quorum (2 of 3). If the two
        # survivors disagree, the cluster must refuse rather than submit a
        # lower-middle "median" that neither Byzantine theory nor the
        # deterministic-engine contract can justify.
        registry, nodes = _build_cluster(3)
        profiles = [profile_adversarial()]
        submit, _ = _submit()

        for node in nodes:
            node.score_epoch(24, profiles, computed_at=REF_END)

        wallet = profiles[0].agent_wallet
        honest = nodes[0].scores_for_epoch(24)[wallet]
        from oracle.cluster.messages import AgentScore
        nodes[1]._epoch_scores[24] = {
            wallet: AgentScore(
                agent_wallet=wallet,
                score=max(0, honest.score - 100),
                alert_tier=honest.alert_tier,
                flags=honest.flags,
                immediate_red=honest.immediate_red,
                confidence=honest.confidence,
            )
        }
        registry.unregister("oracle-node-2")

        report = ClusterEpochRunner(nodes[0]).run_epoch(
            24, profiles, submit_fn=submit, computed_at=REF_END,
        )

        assert report.quorum_failure_count == 1
        assert report.submitted_count == 0
        assert report.results[0].aggregated is None
        assert "consensus not met" in report.results[0].error


# =============================================================================
# A faulty (lying) node, not just an offline one
# =============================================================================

class TestFaultyNode:

    def test_a_lying_node_cannot_corrupt_the_cluster_score(self):
        # node-2 is reachable but FAULTY — it returns a wrong score.
        # The median of the 2 honest nodes + 1 liar still equals the
        # honest score.
        registry, nodes = _build_cluster(3)
        profiles = [profile_adversarial()]
        submit, _ = _submit()

        # Honest nodes score normally.
        nodes[0].score_epoch(24, profiles, computed_at=REF_END)
        nodes[1].score_epoch(24, profiles, computed_at=REF_END)

        # node-2 is faulty — inject a corrupted score directly.
        from oracle.cluster.messages import AgentScore
        wallet = profiles[0].agent_wallet
        nodes[2]._epoch_scores[24] = {
            wallet: AgentScore(
                agent_wallet=wallet, score=12, alert_tier=0,
                flags=0, immediate_red=False, confidence=10,
            )
        }

        report = ClusterEpochRunner(nodes[0]).run_epoch(
            24, profiles, submit_fn=submit, computed_at=REF_END,
        )
        # All 3 contributed, but the median ignores the liar.
        result = report.results[0]
        assert result.aggregated.node_count == 3
        # The honest score (851) is the median, not the lie (12).
        honest_score = nodes[0].scores_for_epoch(24)[wallet].score
        assert result.aggregated.score == honest_score
        assert result.aggregated.score != 12


# =============================================================================
# Cluster sizes
# =============================================================================

class TestClusterSizes:

    def test_five_node_cluster_tolerates_two_failures(self):
        registry, nodes = _build_cluster(5)
        profiles = [profile_adversarial()]
        submit, _ = _submit()

        for node in nodes:
            node.score_epoch(24, profiles, computed_at=REF_END)
        # Kill two nodes — 3 of 5 remain, which is quorum.
        registry.unregister("oracle-node-3")
        registry.unregister("oracle-node-4")

        report = ClusterEpochRunner(nodes[0]).run_epoch(
            24, profiles, submit_fn=submit, computed_at=REF_END,
        )
        assert report.quorum_failure_count == 0
        assert report.results[0].aggregated.node_count == 3

    def test_single_node_cluster_still_works(self):
        # A 1-node cluster — the degenerate case — still produces a score.
        kp = NodeKeypair.from_seed("oracle-node-0", b"seed")
        node = OracleNode.single(kp)
        submit, _ = _submit()
        report = ClusterEpochRunner(node).run_epoch(
            24, [profile_adversarial()], submit_fn=submit, computed_at=REF_END,
        )
        assert report.submitted_count == 1
        assert report.results[0].aggregated.node_count == 1


# =============================================================================
# Determinism
# =============================================================================

class TestDeterminism:

    def test_cluster_epoch_is_deterministic(self):
        profiles = [profile_stable_a(), profile_adversarial(),
                    profile_degrading()]

        def _run():
            _, nodes = _build_cluster(3)
            submit, _ = _submit()
            reports = simulate_cluster_epoch(
                nodes, 24, profiles, submit_fn=submit, computed_at=REF_END,
            )
            report = reports["oracle-node-0"]
            return tuple(r.aggregated.score for r in report.results)

        first = _run()
        for _ in range(5):
            assert _run() == first
