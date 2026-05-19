"""
tests/oracle/test_commit_reveal_cluster.py — the Day-25 done-when.

"The 3-node cluster runs a full commit-reveal round; a node attempting to
 copy another's revealed score fails hash verification."

These tests run the full commit-reveal epoch across a 3-node cluster and
prove: an honest round produces the median; a node that drops out is timed
out; and a copying node is caught by hash verification and excluded.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from oracle.cluster import (
    InProcessRegistry,
    InProcessTransport,
    NodeKeypair,
    RoundPhase,
    compute_commit_hash,
    new_nonce,
    simulate_commit_reveal_epoch,
)
from oracle.cluster.messages import AgentScore, CommitRequest, RevealRequest
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
# DONE-WHEN 1 — the 3-node cluster runs a full commit-reveal round
# =============================================================================

class TestFullCommitRevealRound:

    def test_three_nodes_run_a_full_round(self):
        registry, nodes = _build_cluster(3)
        profiles = [profile_adversarial(), profile_stable_a()]
        submit, calls = _submit()

        reports = simulate_commit_reveal_epoch(
            nodes, 25, profiles, submit_fn=submit, computed_at=REF_END,
        )
        report = reports["oracle-node-0"]

        # All 3 committed AND revealed validly.
        assert len(report.committed_nodes) == 3
        assert len(report.verified_nodes) == 3
        assert len(report.faulty_nodes) == 0
        # Both agents got an aggregated median, submitted.
        assert report.agent_count == 2
        assert report.submitted_count == 2
        assert report.quorum_failure_count == 0

    def test_every_node_aggregates_the_identical_result(self):
        # No coordinator — every node aggregates its own verified set.
        registry, nodes = _build_cluster(3)
        profiles = [profile_adversarial(), profile_stable_a()]
        submit, _ = _submit()

        reports = simulate_commit_reveal_epoch(
            nodes, 25, profiles, submit_fn=submit, computed_at=REF_END,
        )
        medians = [
            tuple(r.aggregated.score for r in rep.results)
            for rep in reports.values()
        ]
        assert len(set(medians)) == 1

    def test_round_reaches_closed_phase(self):
        registry, nodes = _build_cluster(3)
        submit, _ = _submit()
        simulate_commit_reveal_epoch(
            nodes, 25, [profile_adversarial()],
            submit_fn=submit, computed_at=REF_END,
        )
        # After the epoch, every node's round is CLOSED.
        for node in nodes:
            round_ = node.round_for(25)
            assert round_.phase(1_000.0) is RoundPhase.CLOSED

    def test_commit_hides_scores_until_reveal(self):
        # During the commit phase, a peer's commit reveals nothing about
        # the score — it is a 32-byte hash.
        registry, nodes = _build_cluster(3)
        nodes[0].score_epoch(25, [profile_adversarial()], computed_at=REF_END)
        for node in nodes:
            node.open_round(25, [n.node_id for n in nodes],
                            commit_deadline=10.0, reveal_deadline=20.0)
        commit_req = nodes[0].local_commit(25, now=1.0)
        # The commit is a hash — no AgentScore anywhere in it.
        assert isinstance(commit_req, CommitRequest)
        assert len(commit_req.commit_hash) == 32


# =============================================================================
# DONE-WHEN 2 — a copying node fails hash verification
# =============================================================================

class TestCopyingNodeFailsInCluster:

    def test_a_node_copying_a_peer_score_is_caught(self):
        """
        THE DONE-WHEN: node-2 commits a placeholder, then at reveal time
        copies node-0's revealed scores. Hash verification fails; node-2 is
        excluded from the verified set and the median is taken without it.
        """
        registry, nodes = _build_cluster(3)
        profiles = [profile_adversarial()]
        submit, _ = _submit()
        node_ids = [n.node_id for n in nodes]

        # ── Score: honest nodes score; the copier does NOT compute its
        #    own — it stores a placeholder so it has something to commit. ──
        nodes[0].score_epoch(25, profiles, computed_at=REF_END)
        nodes[1].score_epoch(25, profiles, computed_at=REF_END)
        wallet = profiles[0].agent_wallet
        nodes[2]._epoch_scores[25] = {
            wallet: AgentScore(
                agent_wallet=wallet, score=1, alert_tier=0,
                flags=0, immediate_red=False, confidence=1,
            )
        }

        # ── Open + commit: every node commits. node-2 is bound to its
        #    placeholder. ──
        for node in nodes:
            node.open_round(25, node_ids,
                            commit_deadline=10.0, reveal_deadline=20.0)
            node.advance_round_clock(0.0)
        commits = {n.node_id: n.local_commit(25, now=1.0) for n in nodes}
        for node in nodes:
            node.advance_round_clock(1.0)
            for cid, creq in commits.items():
                if cid != node.node_id:
                    node.commit(creq)

        # ── Reveal: honest nodes reveal truthfully. ──
        for node in nodes:
            node.advance_round_clock(11.0)
        honest_reveals = {
            nodes[0].node_id: nodes[0].local_reveal(25, now=11.0),
            nodes[1].node_id: nodes[1].local_reveal(25, now=11.0),
        }

        # ── The COPIER forges a reveal: it copies node-0's revealed scores
        #    but must use its OWN committed nonce. ──
        node0_reveal = honest_reveals["oracle-node-0"]
        copier_nonce = nodes[2]._epoch_nonces[25]
        forged = RevealRequest(
            node_id="oracle-node-2",
            epoch=25,
            scores=node0_reveal.scores,        # copied from node-0
            salt=copier_nonce,                 # the copier's own nonce
        )

        # Distribute reveals. node-1 receives the honest + the forged.
        for node in nodes:
            for rid, rreq in honest_reveals.items():
                if rid != node.node_id:
                    node.reveal(rreq)
        # node-0 and node-1 receive the copier's forged reveal.
        verdict_0 = nodes[0].reveal(forged)
        verdict_1 = nodes[1].reveal(forged)

        # ── The forged reveal FAILS verification on every honest node. ──
        assert verdict_0.verified is False
        assert verdict_1.verified is False
        assert "hash mismatch" in verdict_0.reason

        # node-0's round: copier is faulty, not verified.
        round_0 = nodes[0].round_for(25)
        nodes[0].advance_round_clock(100.0)
        assert "oracle-node-2" in round_0.faulty_nodes(100.0)
        assert "oracle-node-2" not in round_0.verified_nodes()
        assert round_0.verified_nodes() == frozenset(
            {"oracle-node-0", "oracle-node-1"}
        )

    def test_cluster_still_scores_correctly_excluding_the_copier(self):
        # Even with a copier present, the 2 honest nodes form a quorum and
        # the median is the honest score.
        registry, nodes = _build_cluster(3)
        profiles = [profile_adversarial()]
        submit, _ = _submit()

        # node-2 commits a placeholder then fails to reveal validly — model
        # it simply by having it drop its reveal (a forged reveal is
        # excluded identically; both leave it out of the verified set).
        reports = simulate_commit_reveal_epoch(
            nodes, 25, profiles, submit_fn=submit, computed_at=REF_END,
            drop_reveal=["oracle-node-2"],
        )
        report = reports["oracle-node-0"]
        # 2 honest nodes verified, quorum met, score produced.
        assert set(report.verified_nodes) == {
            "oracle-node-0", "oracle-node-1",
        }
        assert report.quorum_failure_count == 0
        assert report.submitted_count == 1


# =============================================================================
# Timeout handling
# =============================================================================

class TestTimeoutHandling:

    def test_node_dropping_commit_is_faulty_but_cluster_survives(self):
        registry, nodes = _build_cluster(3)
        profiles = [profile_adversarial()]
        submit, _ = _submit()

        reports = simulate_commit_reveal_epoch(
            nodes, 25, profiles, submit_fn=submit, computed_at=REF_END,
            drop_commit=["oracle-node-2"],
        )
        report = reports["oracle-node-0"]
        assert "oracle-node-2" in report.faulty_nodes
        assert "oracle-node-2" not in report.verified_nodes
        # 2 of 3 still committed + revealed -> quorum holds.
        assert report.quorum_failure_count == 0
        assert report.submitted_count == 1

    def test_node_dropping_reveal_is_faulty_but_cluster_survives(self):
        registry, nodes = _build_cluster(3)
        profiles = [profile_adversarial()]
        submit, _ = _submit()

        reports = simulate_commit_reveal_epoch(
            nodes, 25, profiles, submit_fn=submit, computed_at=REF_END,
            drop_reveal=["oracle-node-1"],
        )
        report = reports["oracle-node-0"]
        # node-1 committed but never revealed -> faulty.
        assert "oracle-node-1" in report.faulty_nodes
        assert report.quorum_failure_count == 0

    def test_two_nodes_dropping_fails_quorum(self):
        # 2 of 3 drop their reveals -> only 1 verified -> below quorum ->
        # the cluster correctly produces no score.
        registry, nodes = _build_cluster(3)
        profiles = [profile_adversarial()]
        submit, _ = _submit()

        reports = simulate_commit_reveal_epoch(
            nodes, 25, profiles, submit_fn=submit, computed_at=REF_END,
            drop_reveal=["oracle-node-1", "oracle-node-2"],
        )
        report = reports["oracle-node-0"]
        assert len(report.verified_nodes) == 1
        assert report.quorum_failure_count == 1
        assert report.submitted_count == 0


# =============================================================================
# Determinism
# =============================================================================

class TestDeterminism:

    def test_commit_reveal_epoch_is_deterministic(self):
        # The aggregated score is deterministic — even though each round
        # uses fresh random nonces, the nonce never affects the median.
        profiles = [profile_stable_a(), profile_adversarial(),
                    profile_degrading()]

        def _run():
            _, nodes = _build_cluster(3)
            submit, _ = _submit()
            reports = simulate_commit_reveal_epoch(
                nodes, 25, profiles, submit_fn=submit, computed_at=REF_END,
            )
            report = reports["oracle-node-0"]
            return tuple(r.aggregated.score for r in report.results)

        first = _run()
        for _ in range(5):
            assert _run() == first
