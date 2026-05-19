"""
tests/oracle/test_cluster.py — the Day-23 oracle-cluster refactor.

THE DAY-23 DONE-WHEN
--------------------
"The existing single oracle node runs through the new cluster-ready code
 path with zero behaviour change."

This suite proves:
  - identity (Ed25519 keypair) round-trips and signs/verifies,
  - the transport abstraction routes RPCs (in-process),
  - a single OracleNode runs an epoch IDENTICALLY to the pre-Day-23
    `run_epoch` path — the zero-behaviour-change guarantee,
  - a 3-node cluster forms, pings, and reports the right BFT threshold.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from oracle.cluster import (
    InProcessRegistry,
    InProcessTransport,
    NodeIdentity,
    NodeKeypair,
    PeerUnreachable,
    PingRequest,
)
from oracle.cluster.messages import AgentScore, CommitRequest, RevealRequest
from oracle.epoch_runner import run_epoch
from oracle.node import ClusterMembership, OracleNode
from slashing import SingleNodeConsensus
from tests.oracle.agent_profiles import (
    profile_adversarial,
    profile_degrading,
    profile_stable_a,
)


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


def _submit():
    calls: list[str] = []

    def _s(wallet, score_result):
        calls.append(wallet)
        return {"wallet": wallet}

    return _s, calls


def _keypairs(n: int) -> list[NodeKeypair]:
    return [NodeKeypair.from_seed(f"oracle-node-{i}", f"seed{i}".encode())
            for i in range(n)]


# =============================================================================
# Identity — Ed25519 keypair
# =============================================================================

class TestNodeIdentity:

    def test_keypair_has_a_32_byte_public_key(self):
        kp = NodeKeypair.from_seed("node-0", b"seed")
        assert len(kp.public_key) == 32

    def test_from_seed_is_deterministic(self):
        a = NodeKeypair.from_seed("node-0", b"seed")
        b = NodeKeypair.from_seed("node-0", b"seed")
        assert a.public_key == b.public_key

    def test_different_seeds_give_different_keys(self):
        a = NodeKeypair.from_seed("node-0", b"seed-a")
        b = NodeKeypair.from_seed("node-0", b"seed-b")
        assert a.public_key != b.public_key

    def test_generate_gives_distinct_keys(self):
        a = NodeKeypair.generate("node-0")
        b = NodeKeypair.generate("node-0")
        assert a.public_key != b.public_key

    def test_sign_and_verify_round_trip(self):
        kp = NodeKeypair.from_seed("node-0", b"seed")
        message = b"epoch-23 commit hash"
        signature = kp.sign(message)
        assert kp.identity.verify(message, signature) is True

    def test_verify_rejects_a_tampered_message(self):
        kp = NodeKeypair.from_seed("node-0", b"seed")
        signature = kp.sign(b"original")
        assert kp.identity.verify(b"tampered", signature) is False

    def test_verify_rejects_a_wrong_key(self):
        signer = NodeKeypair.from_seed("node-0", b"seed-a")
        other = NodeKeypair.from_seed("node-1", b"seed-b")
        signature = signer.sign(b"message")
        assert other.identity.verify(b"message", signature) is False

    def test_identity_carries_no_secret(self):
        # The repr must never leak secret material.
        kp = NodeKeypair.from_seed("node-0", b"seed")
        assert "seed" not in repr(kp)
        assert b"seed" not in repr(kp).encode()

    def test_identity_rejects_bad_public_key_length(self):
        with pytest.raises(ValueError):
            NodeIdentity(node_id="node-0", public_key=b"too-short")


# =============================================================================
# Transport — in-process
# =============================================================================

class TestInProcessTransport:

    def test_ping_routes_to_the_peer(self):
        registry = InProcessRegistry()
        kps = _keypairs(2)
        nodes = []
        for i, kp in enumerate(kps):
            peers = tuple(k.identity for j, k in enumerate(kps) if j != i)
            node = OracleNode(
                kp, ClusterMembership(kp.identity, peers),
                transport=InProcessTransport(registry),
            )
            registry.register(node.node_id, node)
            nodes.append(node)

        response = nodes[0].ping_peer("oracle-node-1")
        assert response.node_id == "oracle-node-1"

    def test_unreachable_peer_raises(self):
        registry = InProcessRegistry()
        transport = InProcessTransport(registry)
        with pytest.raises(PeerUnreachable):
            transport.ping("ghost", PingRequest(node_id="caller", nonce=1))

    def test_offline_peer_is_unreachable(self):
        # A node that unregisters (goes offline) becomes unreachable.
        registry = InProcessRegistry()
        kps = _keypairs(2)
        nodes = []
        for i, kp in enumerate(kps):
            peers = tuple(k.identity for j, k in enumerate(kps) if j != i)
            node = OracleNode(
                kp, ClusterMembership(kp.identity, peers),
                transport=InProcessTransport(registry),
            )
            registry.register(node.node_id, node)
            nodes.append(node)

        registry.unregister("oracle-node-1")
        # ping_all_peers reports the offline peer as None, never raises.
        results = nodes[0].ping_all_peers()
        assert results["oracle-node-1"] is None

    def test_registry_rejects_duplicate_registration(self):
        registry = InProcessRegistry()
        kp = NodeKeypair.from_seed("node-0", b"seed")
        node = OracleNode.single(kp)
        registry.register("node-0", node)
        with pytest.raises(ValueError):
            registry.register("node-0", node)


# =============================================================================
# ClusterMembership
# =============================================================================

class TestClusterMembership:

    def test_single_node_membership(self):
        kp = NodeKeypair.from_seed("node-0", b"seed")
        m = ClusterMembership(self_identity=kp.identity)
        assert m.size == 1
        assert m.is_single_node is True
        assert m.consensus_threshold == 1

    def test_three_node_threshold_is_two(self):
        kps = _keypairs(3)
        m = ClusterMembership(
            self_identity=kps[0].identity,
            peers=(kps[1].identity, kps[2].identity),
        )
        assert m.size == 3
        assert m.consensus_threshold == 2

    def test_five_node_threshold_is_three(self):
        kps = _keypairs(5)
        m = ClusterMembership(
            self_identity=kps[0].identity,
            peers=tuple(k.identity for k in kps[1:]),
        )
        assert m.size == 5
        assert m.consensus_threshold == 3

    def test_duplicate_node_id_rejected(self):
        a = NodeKeypair.from_seed("dup", b"seed-a")
        b = NodeKeypair.from_seed("dup", b"seed-b")
        with pytest.raises(ValueError, match="duplicate node_id"):
            ClusterMembership(self_identity=a.identity, peers=(b.identity,))

    def test_peer_ids(self):
        kps = _keypairs(3)
        m = ClusterMembership(
            self_identity=kps[0].identity,
            peers=(kps[1].identity, kps[2].identity),
        )
        assert set(m.peer_ids()) == {"oracle-node-1", "oracle-node-2"}


# =============================================================================
# THE DONE-WHEN — zero behaviour change for a single node
# =============================================================================

class TestSingleNodeZeroBehaviourChange:

    def _profiles(self):
        return [profile_stable_a(), profile_degrading(), profile_adversarial()]

    def test_single_node_runs_an_epoch(self):
        kp = NodeKeypair.from_seed("oracle-node-0", b"seed")
        node = OracleNode.single(kp)
        submit, calls = _submit()
        report = node.run_epoch(
            23, self._profiles(), submit_fn=submit, computed_at=REF_END,
        )
        assert report.agent_count == 3
        assert report.submitted_count == 3

    def test_node_path_is_byte_identical_to_direct_run_epoch(self):
        """
        THE DONE-WHEN: the OracleNode wrapper changes nothing about scoring.
        A single node's EpochReport must equal the pre-Day-23 `run_epoch`
        path exactly.
        """
        profiles = self._profiles()

        # ── via the new OracleNode path ─────────────────────────────────────
        kp = NodeKeypair.from_seed("oracle-node-0", b"seed")
        node = OracleNode.single(kp)
        submit_n, _ = _submit()
        via_node = node.run_epoch(
            23, profiles, submit_fn=submit_n, computed_at=REF_END,
        )

        # ── via the direct pre-Day-23 path ──────────────────────────────────
        submit_d, _ = _submit()
        via_direct = run_epoch(
            epoch_id=23, agent_inputs=profiles, submit_fn=submit_d,
            consensus=SingleNodeConsensus(), node_id="oracle-node-0",
            computed_at=REF_END,
        )

        # Every score, alert, and slash decision must match exactly.
        assert len(via_node.results) == len(via_direct.results)
        for rn, rd in zip(via_node.results, via_direct.results):
            assert rn.agent_wallet == rd.agent_wallet
            assert rn.score_result.score == rd.score_result.score
            assert rn.score_result.alert == rd.score_result.alert
            assert rn.score_result.aggregated_flags == rd.score_result.aggregated_flags
            assert rn.slashed == rd.slashed
            assert (rn.slash_decision.should_slash
                    == rd.slash_decision.should_slash)

    def test_single_node_is_deterministic_across_runs(self):
        kp = NodeKeypair.from_seed("oracle-node-0", b"seed")
        profiles = self._profiles()

        def _run():
            node = OracleNode.single(kp)
            submit, _ = _submit()
            report = node.run_epoch(
                23, profiles, submit_fn=submit, computed_at=REF_END,
            )
            return tuple(r.score_result.score for r in report.results)

        first = _run()
        for _ in range(5):
            assert _run() == first

    def test_lone_node_has_no_transport(self):
        # A single node talks to nobody — pinging a peer is a usage error.
        node = OracleNode.single(NodeKeypair.from_seed("node-0", b"seed"))
        with pytest.raises(RuntimeError, match="no transport"):
            node.ping_peer("anyone")


# =============================================================================
# The serving surface — Ping works, commit/reveal are honest stubs
# =============================================================================

class TestServingSurface:

    def test_ping_handler_echoes_nonce_and_reports_epoch(self):
        node = OracleNode.single(NodeKeypair.from_seed("node-0", b"seed"))
        node.set_epoch(7)
        response = node.ping(PingRequest(node_id="caller", nonce=42))
        assert response.node_id == "node-0"
        assert response.nonce == 42
        assert response.current_epoch == 7

    def test_commit_handler_is_an_honest_stub(self):
        # Day 23 exposes the handler but not the protocol — it must REJECT
        # honestly, not silently accept a commit it cannot process.
        node = OracleNode.single(NodeKeypair.from_seed("node-0", b"seed"))
        response = node.commit(CommitRequest(
            node_id="peer", epoch=1, commit_hash=b"\x00" * 32,
        ))
        assert response.accepted is False
        assert "Days 24-28" in response.reason

    def test_reveal_handler_is_an_honest_stub(self):
        node = OracleNode.single(NodeKeypair.from_seed("node-0", b"seed"))
        response = node.reveal(RevealRequest(
            node_id="peer", epoch=1, scores=(), salt=b"salt",
        ))
        assert response.verified is False
        assert "Days 24-28" in response.reason

    def test_ping_nonce_mismatch_is_caught(self):
        # A peer that echoes the wrong nonce (stale/replayed) is rejected.
        registry = InProcessRegistry()

        class _BadNoncePeer:
            def ping(self, request):
                from oracle.cluster.messages import PingResponse
                return PingResponse(node_id="bad", nonce=999,
                                    current_epoch=1)
            def commit(self, request): ...
            def reveal(self, request): ...

        registry.register("bad", _BadNoncePeer())
        kp = NodeKeypair.from_seed("node-0", b"seed")
        bad_id = NodeIdentity(node_id="bad", public_key=b"\x01" * 32)
        node = OracleNode(
            kp, ClusterMembership(kp.identity, (bad_id,)),
            transport=InProcessTransport(registry),
        )
        with pytest.raises(RuntimeError, match="nonce"):
            node.ping_peer("bad")


# =============================================================================
# A 3-node cluster
# =============================================================================

class TestThreeNodeCluster:

    def _cluster(self, n: int = 3):
        registry = InProcessRegistry()
        kps = _keypairs(n)
        nodes = []
        for i, kp in enumerate(kps):
            peers = tuple(k.identity for j, k in enumerate(kps) if j != i)
            node = OracleNode(
                kp, ClusterMembership(kp.identity, peers),
                transport=InProcessTransport(registry),
            )
            registry.register(node.node_id, node)
            nodes.append(node)
        return nodes

    def test_cluster_forms_with_correct_threshold(self):
        nodes = self._cluster(3)
        for node in nodes:
            assert node.membership.size == 3
            assert node.membership.consensus_threshold == 2

    def test_every_node_can_ping_every_peer(self):
        nodes = self._cluster(3)
        for node in nodes:
            pings = node.ping_all_peers()
            assert len(pings) == 2
            assert all(r is not None for r in pings.values())

    def test_each_node_runs_its_own_pipeline(self):
        # Each node scores independently — and, being deterministic, the
        # three reach the IDENTICAL score for the same agent.
        nodes = self._cluster(3)
        profiles = [profile_adversarial()]
        scores = []
        for node in nodes:
            submit, _ = _submit()
            report = node.run_epoch(
                23, profiles, submit_fn=submit, computed_at=REF_END,
            )
            scores.append(report.results[0].score_result.score)
        # All three nodes independently computed the same score.
        assert len(set(scores)) == 1
