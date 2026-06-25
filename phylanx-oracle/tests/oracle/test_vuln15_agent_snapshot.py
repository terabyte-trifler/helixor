"""
tests/oracle/test_vuln15_agent_snapshot.py — VULN-15 agent-set drift attack.

Pins the audit-mandated mitigations:

  1. **Snapshot semantics — fix the agent set at the start of each epoch.**
     `EpochAgentSnapshot` is an immutable, hash-pinned record of the
     in-scope agent set for ONE commit-reveal round. The hash is
     canonical (sorted, de-duplicated, length-prefixed, domain-separated),
     so two honest nodes reach byte-identical hashes from the same set.

  2. **Snapshot folds into commit + reveal verification.** A node whose
     in-scope set drifts between commit and reveal computes a different
     `snapshot_hash` than honest verifiers — its reveal then fails
     verification at every honest peer. The attacker who race-registers
     an agent between commit and reveal cannot grief the round into
     producing no result without their drift being LOCALLY detectable.

  3. **Boundary semantics — registrations / deregistrations apply at
     epoch boundary, not mid-epoch.** `AgentSetBuffer` queues changes
     during an epoch and atomically folds them in at the next boundary,
     so the snapshot a new epoch captures has the SAME view of the
     agent set on every node regardless of the exact moment a
     registration event landed.

  4. **Full integration — runner builds the snapshot from agent_inputs
     and binds it on every node; the cluster end-to-end produces a
     successful commit-reveal round with the snapshot folded in.**
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from oracle.cluster import (
    AgentSetBuffer,
    AppliedSnapshot,
    EpochAgentSnapshot,
    InProcessRegistry,
    InProcessTransport,
    NodeKeypair,
    PendingChangeKind,
    SnapshotMismatch,
    canonical_snapshot_bytes,
    compute_snapshot,
    compute_snapshot_hash,
    compute_commit_hash,
    new_nonce,
    quorum_for,
    simulate_commit_reveal_epoch,
    verify_reveal,
)
from oracle.cluster.messages import AgentScore
from oracle.node import ClusterMembership, OracleNode
from tests.oracle.agent_profiles import ALL_PROFILES


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# 1. Canonical encoding — determinism + ordering + domain separation
# =============================================================================

class TestCanonicalSnapshotEncoding:

    def test_same_set_same_hash(self):
        h1 = compute_snapshot_hash(7, ["alice", "bob", "carol"])
        h2 = compute_snapshot_hash(7, ["alice", "bob", "carol"])
        assert h1 == h2
        assert len(h1) == 32

    def test_ordering_is_irrelevant(self):
        # Two nodes that happened to see the agent list in different
        # orders MUST still hash to the same value.
        h1 = compute_snapshot_hash(7, ["bob", "alice", "carol"])
        h2 = compute_snapshot_hash(7, ["carol", "bob", "alice"])
        assert h1 == h2

    def test_duplicates_are_collapsed(self):
        # A node that double-counts an agent in its list must not differ
        # from a node that listed it once.
        h_single = compute_snapshot_hash(7, ["alice", "bob"])
        h_dupe = compute_snapshot_hash(7, ["alice", "alice", "bob", "bob"])
        assert h_single == h_dupe

    def test_different_set_different_hash(self):
        h_three = compute_snapshot_hash(7, ["alice", "bob", "carol"])
        h_two = compute_snapshot_hash(7, ["alice", "bob"])
        assert h_three != h_two

    def test_different_epoch_different_hash(self):
        h_epoch_7 = compute_snapshot_hash(7, ["alice", "bob"])
        h_epoch_8 = compute_snapshot_hash(8, ["alice", "bob"])
        assert h_epoch_7 != h_epoch_8

    def test_domain_prefix_is_present(self):
        # The "HXR-EPOCH-SNAPSHOT\0" prefix is the front of the canonical
        # bytes — pinned so a snapshot hash is never collidable with any
        # other sha256 on the protocol surface.
        raw = canonical_snapshot_bytes(0, [])
        assert raw.startswith(b"HXR-EPOCH-SNAPSHOT\x00")

    def test_negative_epoch_rejected(self):
        with pytest.raises(ValueError):
            compute_snapshot_hash(-1, [])

    def test_empty_set_is_valid(self):
        # A bootstrapping cluster with no agents yet still needs a stable
        # snapshot hash.
        h = compute_snapshot_hash(0, [])
        assert len(h) == 32


# =============================================================================
# 2. EpochAgentSnapshot — construction invariants
# =============================================================================

class TestEpochAgentSnapshot:

    def test_compute_snapshot_round_trips(self):
        snap = compute_snapshot(5, ["alice", "bob"], now=1234.0)
        assert snap.epoch_id == 5
        assert snap.agent_count == 2
        assert snap.agent_wallets == ("alice", "bob")
        assert snap.snapshot_hash == compute_snapshot_hash(5, ["alice", "bob"])
        assert snap.captured_at == 1234.0

    def test_wallets_are_sorted_in_memory(self):
        # The wire shape and the in-memory shape match — the cluster never
        # has to re-sort to compare.
        snap = compute_snapshot(5, ["carol", "alice", "bob"])
        assert snap.agent_wallets == ("alice", "bob", "carol")

    def test_construction_rejects_inconsistent_hash(self):
        # A hand-built snapshot in tests cannot smuggle a wrong hash —
        # __post_init__ recomputes and compares.
        bad_hash = b"\xff" * 32
        with pytest.raises(ValueError):
            EpochAgentSnapshot(
                epoch_id=1, agent_wallets=("alice",),
                snapshot_hash=bad_hash, captured_at=0.0,
            )

    def test_construction_rejects_wrong_hash_length(self):
        # The hash must be 32 bytes — the round's snapshot_hash check
        # depends on this.
        with pytest.raises(ValueError):
            EpochAgentSnapshot(
                epoch_id=1, agent_wallets=(),
                snapshot_hash=b"\x00" * 31, captured_at=0.0,
            )

    def test_matches_returns_true_for_identical_snapshots(self):
        s1 = compute_snapshot(5, ["alice", "bob"])
        s2 = compute_snapshot(5, ["bob", "alice"])
        assert s1.matches(s2) is True

    def test_matches_returns_false_for_set_drift(self):
        s1 = compute_snapshot(5, ["alice", "bob"])
        s2 = compute_snapshot(5, ["alice", "bob", "carol"])
        assert s1.matches(s2) is False

    def test_matches_returns_false_for_epoch_mismatch(self):
        s1 = compute_snapshot(5, ["alice"])
        s2 = compute_snapshot(6, ["alice"])
        assert s1.matches(s2) is False

    def test_assert_matches_raises_on_drift(self):
        s1 = compute_snapshot(5, ["alice", "bob"])
        s2 = compute_snapshot(5, ["alice", "bob", "carol"])
        with pytest.raises(SnapshotMismatch) as excinfo:
            s1.assert_matches(s2, context="commit-reveal phase 2")
        assert excinfo.value.epoch_id == 5
        assert "VULN-15" in str(excinfo.value)
        assert "commit-reveal phase 2" in str(excinfo.value)


# =============================================================================
# 3. Commit-hash binding — VULN-15 attack surface
# =============================================================================

class TestCommitHashSnapshotBinding:

    def _score(self, wallet: str) -> AgentScore:
        return AgentScore(
            agent_wallet=wallet, score=700, alert_tier=0,
            flags=0, immediate_red=False, confidence=900,
        )

    def test_back_compat_no_snapshot_kwarg(self):
        # Pre-VULN-15 callers (the 1k+ legacy round suite) pass no
        # snapshot — hashing must still match the legacy wire format.
        nonce = b"\x00" * 32
        scores = (self._score("alice"),)
        h_legacy = compute_commit_hash(scores, nonce)
        # Explicitly passing None yields the same bytes.
        h_none = compute_commit_hash(scores, nonce, snapshot_hash=None)
        assert h_legacy == h_none

    def test_different_snapshot_yields_different_commit(self):
        nonce = b"\x00" * 32
        scores = (self._score("alice"),)
        snap_a = compute_snapshot(1, ["alice"])
        snap_b = compute_snapshot(1, ["alice", "bob"])
        h_a = compute_commit_hash(scores, nonce, snapshot_hash=snap_a.snapshot_hash)
        h_b = compute_commit_hash(scores, nonce, snapshot_hash=snap_b.snapshot_hash)
        assert h_a != h_b

    def test_verify_reveal_succeeds_with_matching_snapshot(self):
        # Honest path: committer and verifier hold the same snapshot.
        nonce = new_nonce()
        scores = (self._score("alice"),)
        snap = compute_snapshot(1, ["alice"])
        commit = compute_commit_hash(scores, nonce, snapshot_hash=snap.snapshot_hash)
        assert verify_reveal(
            commit, scores, nonce, snapshot_hash=snap.snapshot_hash,
        ) is True

    def test_verify_reveal_fails_on_set_drift(self):
        # The VULN-15 attack: committer used snapshot_hash_A; verifier's
        # set drifted, so verifier holds snapshot_hash_B. The reveal
        # MUST fail verification.
        nonce = new_nonce()
        scores = (self._score("alice"),)
        snap_committer = compute_snapshot(1, ["alice"])
        snap_verifier_after_drift = compute_snapshot(1, ["alice", "bob"])
        commit = compute_commit_hash(
            scores, nonce, snapshot_hash=snap_committer.snapshot_hash,
        )
        assert verify_reveal(
            commit, scores, nonce,
            snapshot_hash=snap_verifier_after_drift.snapshot_hash,
        ) is False

    def test_verify_reveal_fails_when_one_side_omits_snapshot(self):
        # Mixed back-compat / VULN-15 nodes do not interop — that's the
        # design: the snapshot binding is part of the protocol surface.
        nonce = new_nonce()
        scores = (self._score("alice"),)
        snap = compute_snapshot(1, ["alice"])
        commit = compute_commit_hash(scores, nonce, snapshot_hash=snap.snapshot_hash)
        assert verify_reveal(commit, scores, nonce, snapshot_hash=None) is False


# =============================================================================
# 4. OracleNode — bind_snapshot wiring
# =============================================================================

class TestOracleNodeBindSnapshot:

    def _node(self, node_id: str = "n1") -> OracleNode:
        kp = NodeKeypair.from_seed(node_id, f"{node_id}-seed".encode())
        membership = ClusterMembership(self_identity=kp.identity)
        return OracleNode(kp, membership)

    def test_bind_then_open_propagates_snapshot_to_round(self):
        node = self._node()
        snap = compute_snapshot(epoch_id=1, wallets=["a"])
        node.bind_snapshot(1, snap)
        round_ = node.open_round(
            1, [node.node_id],
            commit_deadline=5.0, reveal_deadline=10.0,
        )
        assert round_.snapshot_hash == snap.snapshot_hash

    def test_open_without_bind_keeps_legacy_behaviour(self):
        # No snapshot bound → round.snapshot_hash is None → commits/reveals
        # use the legacy wire format. Critical for back-compat.
        node = self._node()
        round_ = node.open_round(
            1, [node.node_id],
            commit_deadline=5.0, reveal_deadline=10.0,
        )
        assert round_.snapshot_hash is None

    def test_bind_rejects_epoch_id_mismatch(self):
        node = self._node()
        snap = compute_snapshot(epoch_id=2, wallets=["a"])
        with pytest.raises(ValueError):
            node.bind_snapshot(1, snap)

    def test_bind_idempotent_for_same_hash(self):
        node = self._node()
        snap = compute_snapshot(epoch_id=1, wallets=["a", "b"])
        node.bind_snapshot(1, snap)
        node.bind_snapshot(1, snap)               # same hash → no-op
        assert node.snapshot_for(1) is snap

    def test_bind_rejects_rebind_to_different_hash(self):
        node = self._node()
        snap_a = compute_snapshot(epoch_id=1, wallets=["a"])
        snap_b = compute_snapshot(epoch_id=1, wallets=["a", "b"])
        node.bind_snapshot(1, snap_a)
        with pytest.raises(RuntimeError):
            node.bind_snapshot(1, snap_b)

    def test_snapshot_for_returns_none_when_unbound(self):
        node = self._node()
        assert node.snapshot_for(42) is None


# =============================================================================
# 5. AgentSetBuffer — atomic boundary semantics
# =============================================================================

class TestAgentSetBuffer:

    def test_initial_set_is_active(self):
        buf = AgentSetBuffer(initial=["alice", "bob"])
        assert buf.current_set == frozenset({"alice", "bob"})
        assert buf.pending_count == 0
        assert buf.applied_epochs == 0

    def test_enqueue_does_not_mutate_current_set(self):
        # The core invariant: the active set DOES NOT CHANGE until
        # apply_pending is called at an epoch boundary.
        buf = AgentSetBuffer(initial=["alice"])
        buf.enqueue_register("bob")
        buf.enqueue_deregister("alice")
        assert buf.current_set == frozenset({"alice"})       # unchanged
        assert buf.pending_count == 2

    def test_apply_pending_folds_in_atomically(self):
        buf = AgentSetBuffer(initial=["alice"])
        buf.enqueue_register("bob")
        buf.enqueue_deregister("alice")
        applied = buf.apply_pending(next_epoch_id=2)

        assert isinstance(applied, AppliedSnapshot)
        assert applied.new_set == frozenset({"bob"})
        assert applied.registered == ("bob",)
        assert applied.deregistered == ("alice",)
        assert buf.current_set == frozenset({"bob"})
        assert buf.pending_count == 0
        assert buf.applied_epochs == 1

    def test_register_already_present_is_noop_at_apply(self):
        buf = AgentSetBuffer(initial=["alice"])
        buf.enqueue_register("alice")
        applied = buf.apply_pending(next_epoch_id=1)
        assert applied.registered == ()
        assert applied.deregistered == ()
        assert buf.current_set == frozenset({"alice"})

    def test_deregister_absent_is_noop_at_apply(self):
        buf = AgentSetBuffer(initial=["alice"])
        buf.enqueue_deregister("bob")
        applied = buf.apply_pending(next_epoch_id=1)
        assert applied.deregistered == ()
        assert buf.current_set == frozenset({"alice"})

    def test_last_enqueue_wins(self):
        # The buffer is a state machine, not an event log — multiple
        # changes on the same wallet collapse to the LATEST.
        buf = AgentSetBuffer(initial=["alice"])
        buf.enqueue_deregister("alice")
        buf.enqueue_register("alice")
        # "Last wins" → alice should still be registered.
        applied = buf.apply_pending(next_epoch_id=1)
        assert applied.registered == ()                  # no change
        assert buf.current_set == frozenset({"alice"})

    def test_diff_is_sorted_for_determinism(self):
        # Two nodes producing the same diff must produce the byte-
        # identical tuple ordering — sorted-by-wallet pins that.
        buf = AgentSetBuffer()
        buf.enqueue_register("carol")
        buf.enqueue_register("alice")
        buf.enqueue_register("bob")
        applied = buf.apply_pending(next_epoch_id=1)
        assert applied.registered == ("alice", "bob", "carol")

    def test_pending_kind_introspection(self):
        buf = AgentSetBuffer()
        buf.enqueue_register("alice")
        assert buf.has_pending("alice") is True
        assert buf.pending_kind("alice") is PendingChangeKind.REGISTER
        assert buf.pending_kind("bob") is None

    def test_apply_rejects_negative_epoch(self):
        buf = AgentSetBuffer()
        with pytest.raises(ValueError):
            buf.apply_pending(next_epoch_id=-1)

    def test_apply_with_no_pending_changes_is_a_noop_tick(self):
        buf = AgentSetBuffer(initial=["alice"])
        applied = buf.apply_pending(next_epoch_id=5)
        assert applied.change_count == 0
        assert applied.new_set == frozenset({"alice"})
        assert buf.applied_epochs == 1                   # the tick still counted

    def test_two_buffers_with_same_event_stream_converge(self):
        # The cluster-wide property: every node's buffer, fed the same
        # event stream, produces an identical post-boundary set.
        events = [
            ("register", "alice"),
            ("register", "bob"),
            ("deregister", "alice"),
            ("register", "carol"),
        ]
        bufs = [AgentSetBuffer(), AgentSetBuffer()]
        for buf in bufs:
            for kind, w in events:
                if kind == "register":
                    buf.enqueue_register(w)
                else:
                    buf.enqueue_deregister(w)
            buf.apply_pending(next_epoch_id=1)
        assert bufs[0].current_set == bufs[1].current_set
        assert bufs[0].current_set == frozenset({"bob", "carol"})


# =============================================================================
# 6. End-to-end: cluster runner builds + binds snapshot, round completes
# =============================================================================

class TestRunEpochSnapshotBinding:

    def _cluster(self, n: int = 3) -> list[OracleNode]:
        registry = InProcessRegistry()
        kps = [
            NodeKeypair.from_seed(f"vuln15-node-{i}", f"seed{i}".encode())
            for i in range(n)
        ]
        nodes = []
        for i, kp in enumerate(kps):
            peers = tuple(kps[j].identity for j in range(n) if j != i)
            node = OracleNode(
                kp, ClusterMembership(kp.identity, peers),
                transport=InProcessTransport(registry),
            )
            registry.register(node.node_id, node)
            nodes.append(node)
        return nodes

    def test_runner_binds_snapshot_on_every_node(self):
        nodes = self._cluster(3)
        inputs = [gen() for gen, _ in ALL_PROFILES.values()]
        wallets = [ai.agent_wallet for ai in inputs]
        expected_hash = compute_snapshot_hash(epoch_id=15, wallets=wallets)

        def submit(wallet, aggregated):
            return {"wallet": wallet, "score": aggregated.score}

        simulate_commit_reveal_epoch(
            nodes, epoch_id=15, agent_inputs=inputs,
            submit_fn=submit, computed_at=REF_END,
        )

        for node in nodes:
            snap = node.snapshot_for(15)
            assert snap is not None
            assert snap.snapshot_hash == expected_hash
            round_ = node.round_for(15)
            assert round_ is not None
            assert round_.snapshot_hash == expected_hash

    def test_runner_produces_verified_reveals_with_snapshot_bound(self):
        # The whole cluster runs end-to-end with snapshot binding. Every
        # honest node verifies every honest node's reveal — no false
        # rejections from the new hash format.
        nodes = self._cluster(3)
        inputs = [gen() for gen, _ in ALL_PROFILES.values()]

        submissions: list[tuple[str, int]] = []
        def submit(wallet, aggregated):
            submissions.append((wallet, aggregated.score))
            return {"wallet": wallet, "score": aggregated.score}

        reports = simulate_commit_reveal_epoch(
            nodes, epoch_id=16, agent_inputs=inputs,
            submit_fn=submit, computed_at=REF_END,
        )

        for node in nodes:
            report = reports[node.node_id]
            # Every node reveal verified → verified_nodes == cluster_size.
            assert len(report.verified_nodes) == 3
            # Every agent was aggregated and submitted.
            assert report.submitted_count == len(inputs)


# =============================================================================
# 7. Mid-epoch drift detection — the VULN-15 attack scenario
# =============================================================================

class TestMidEpochDriftIsDetected:
    """
    The core audit ask: a node whose agent set drifts between commit
    and reveal must be CAUGHT. Even if scores are honest, the
    snapshot_hash binding makes a divergent reveal fail verification
    against a verifier holding the right snapshot.
    """

    def _score(self, wallet: str) -> AgentScore:
        return AgentScore(
            agent_wallet=wallet, score=500, alert_tier=0,
            flags=0, immediate_red=False, confidence=800,
        )

    def test_round_rejects_reveal_when_committer_used_drifted_snapshot(self):
        # Honest verifier holds snap_honest. Attacker committed against
        # snap_drifted (one extra agent). At reveal, the verifier's
        # round (bound to snap_honest) rejects the attacker's reveal
        # because the snapshot hashes differ.
        from oracle.cluster.commit_reveal_round import CommitRevealRound

        snap_honest = compute_snapshot(1, ["alice", "bob"])
        snap_drifted = compute_snapshot(1, ["alice", "bob", "mallory"])

        scores = (self._score("alice"), self._score("bob"))
        nonce = new_nonce()
        attacker_commit = compute_commit_hash(
            scores, nonce, snapshot_hash=snap_drifted.snapshot_hash,
        )

        # The honest verifier's round is bound to snap_honest.
        round_ = CommitRevealRound(
            epoch=1, node_ids=["attacker"],
            commit_deadline=5.0, reveal_deadline=10.0,
            snapshot_hash=snap_honest.snapshot_hash,
        )
        round_.submit_commit("attacker", attacker_commit, now=1.0)
        record = round_.submit_reveal("attacker", scores, nonce, now=6.0)

        # The reveal is recorded but NOT verified — exactly the VULN-15
        # detection surface.
        assert record.verified is False
        assert "hash mismatch" in record.reason

    def test_honest_round_with_matching_snapshot_verifies(self):
        # Control: same scenario but committer and round share the
        # honest snapshot → reveal verifies.
        from oracle.cluster.commit_reveal_round import CommitRevealRound

        snap_honest = compute_snapshot(1, ["alice", "bob"])
        scores = (self._score("alice"), self._score("bob"))
        nonce = new_nonce()
        commit = compute_commit_hash(
            scores, nonce, snapshot_hash=snap_honest.snapshot_hash,
        )
        round_ = CommitRevealRound(
            epoch=1, node_ids=["honest"],
            commit_deadline=5.0, reveal_deadline=10.0,
            snapshot_hash=snap_honest.snapshot_hash,
        )
        round_.submit_commit("honest", commit, now=1.0)
        record = round_.submit_reveal("honest", scores, nonce, now=6.0)
        assert record.verified is True
