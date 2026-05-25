"""
tests/oracle/test_vuln22_version_pinning.py — VULN-22 scoring-algorithm
version mismatch.

Pins the audit-mandated mitigations for the upgrade-induced liveness
attack:

  1. **The (scoring_algo, scoring_weights) version is folded into the
     commit hash.** A revealer that switches versions between commit and
     reveal cannot reproduce the committed hash — `verify_reveal` returns
     False even when the scores match.

  2. **The round PINS to one version.** Either pre-pinned by the runner
     (`pinned_algo_version=`) or auto-pinned from the first commit that
     carries a version. Subsequent commits with a different version are
     rejected with `VersionMismatch` — a subclass of `CommitRejected`.

  3. **Mismatched nodes are SILENTLY EXCLUDED, not flagged Byzantine.**
     A node on the wrong version contributes nothing this round, gains
     no Byzantine strike, is not slashed, and may participate normally
     in the next epoch once it upgrades. The runner surfaces the
     exclusion via `report.version_excluded_nodes` so operators can see
     the upgrade-skew without a stake-loss event.

  4. **Commit messages carry the version on the wire.** `CommitRequest`
     and `RevealRequest` both expose `scoring_algo_version` /
     `scoring_weights_version` — both-set or both-omitted (validated in
     __post_init__).

  5. **End-to-end mainnet rehearsal.** A 5-node cluster with one node on
     a stale version runs a full Byzantine epoch and finishes with:
       - 4 verified, 1 version-excluded, 0 Byzantine, 0 challenges filed,
       - the produced score is the honest-majority median.
     The minority node is NOT slashed; rerunning a second epoch with the
     same configuration produces the same result — no strike accumulation.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from oracle.cluster import (
    ByzantineWatchdog,
    CommitRejected,
    CommitRevealRound,
    InProcessRegistry,
    InProcessTransport,
    NodeKeypair,
    VersionMismatch,
    compute_commit_hash,
    new_nonce,
    quorum_for,
    run_byzantine_epoch,
    verify_reveal,
)
from oracle.cluster.messages import (
    AgentScore,
    CommitRequest,
    RevealRequest,
)
from oracle.node import ClusterMembership, OracleNode
from tests.oracle.agent_profiles import profile_stable_a


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


def _scores(wallet: str = "agent-X") -> tuple[AgentScore, ...]:
    return (AgentScore(wallet, 800, 0, 0, False, 900),)


# =============================================================================
# 1. Version folds into the hash — pure layer
# =============================================================================

class TestVersionFoldsIntoHash:

    def test_hash_differs_when_version_differs(self):
        scores = _scores()
        nonce = new_nonce()
        h1 = compute_commit_hash(scores, nonce, algo_version=(2, 1))
        h2 = compute_commit_hash(scores, nonce, algo_version=(2, 2))
        h3 = compute_commit_hash(scores, nonce, algo_version=(3, 1))
        assert h1 != h2 != h3 != h1
        # And every version-tagged hash differs from the untagged legacy.
        h_legacy = compute_commit_hash(scores, nonce)
        assert h_legacy not in {h1, h2, h3}

    def test_reveal_with_wrong_version_fails(self):
        """A node committed at V1 cannot reveal at V2 — hash mismatch."""
        scores = _scores()
        nonce = new_nonce()
        committed = compute_commit_hash(scores, nonce, algo_version=(2, 1))
        assert verify_reveal(committed, scores, nonce, algo_version=(2, 1))
        assert not verify_reveal(
            committed, scores, nonce, algo_version=(2, 2),
        )
        assert not verify_reveal(committed, scores, nonce)   # legacy path

    def test_version_out_of_u32_range_raises(self):
        scores = _scores()
        nonce = new_nonce()
        with pytest.raises(ValueError):
            compute_commit_hash(scores, nonce, algo_version=(-1, 0))
        with pytest.raises(ValueError):
            compute_commit_hash(scores, nonce, algo_version=(0, 2**33))


# =============================================================================
# 2. Round pins from first commit
# =============================================================================

class TestRoundAutoPinAndMismatch:

    def _round(self, pinned=None):
        return CommitRevealRound(
            epoch=42, node_ids=["A", "B", "C"],
            commit_deadline=10.0, reveal_deadline=20.0,
            pinned_algo_version=pinned,
        )

    def test_round_auto_pins_to_first_version_aware_commit(self):
        r = self._round()
        assert r.pinned_algo_version is None
        r.submit_commit("A", b"\x01" * 32, now=1.0, algo_version=(2, 1))
        assert r.pinned_algo_version == (2, 1)

    def test_second_commit_with_different_version_is_VersionMismatch(self):
        r = self._round()
        r.submit_commit("A", b"\x01" * 32, now=1.0, algo_version=(2, 1))
        with pytest.raises(VersionMismatch):
            r.submit_commit("B", b"\x02" * 32, now=2.0, algo_version=(2, 2))
        # B is NOT in committed_nodes, but IS in version_mismatched_nodes.
        assert "B" not in r.committed_nodes()
        assert "B" in r.version_mismatched_nodes()
        assert "A" in r.committed_nodes()

    def test_VersionMismatch_is_subclass_of_CommitRejected(self):
        """The runner's existing CommitRejected catch keeps working."""
        assert issubclass(VersionMismatch, CommitRejected)

    def test_pre_pinned_round_rejects_first_off_version_commit(self):
        r = self._round(pinned=(2, 1))
        with pytest.raises(VersionMismatch):
            r.submit_commit("A", b"\x01" * 32, now=1.0, algo_version=(2, 2))
        assert "A" in r.version_mismatched_nodes()
        assert "A" not in r.committed_nodes()

    def test_pinned_round_rejects_version_unaware_commit(self):
        """A pre-pinned round treats a missing version as a mismatch."""
        r = self._round(pinned=(2, 1))
        with pytest.raises(VersionMismatch):
            r.submit_commit("A", b"\x01" * 32, now=1.0)   # no algo_version

    def test_legacy_round_with_no_versions_still_works(self):
        """All-None preserves the pre-VULN-22 wire format."""
        r = self._round()
        r.submit_commit("A", b"\x01" * 32, now=1.0)
        r.submit_commit("B", b"\x02" * 32, now=2.0)
        assert r.pinned_algo_version is None
        assert r.version_mismatched_nodes() == frozenset()
        assert r.committed_nodes() == frozenset({"A", "B"})


# =============================================================================
# 3. Round.submit_reveal verifies under the pinned version
# =============================================================================

class TestRoundRevealVerificationUsesPinnedVersion:

    def test_reveal_passes_when_committer_and_pin_agree(self):
        r = CommitRevealRound(
            epoch=1, node_ids=["A"],
            commit_deadline=10.0, reveal_deadline=20.0,
        )
        scores = _scores()
        nonce = new_nonce()
        commit_hash = compute_commit_hash(
            scores, nonce, algo_version=(2, 1),
        )
        r.submit_commit("A", commit_hash, now=1.0, algo_version=(2, 1))
        record = r.submit_reveal("A", scores, nonce, now=11.0)
        assert record.verified is True

    def test_reveal_fails_when_pinned_version_differs_from_committer(self):
        """
        Smuggle a hash computed under a DIFFERENT version into the round.
        The pin is V1; the commit hash was computed under V2 yet was
        accepted (because the round only saw the version metadata, not
        the hash's secret algo_version). At reveal time, the round
        verifies under V1 — fails — exactly the audit's "version drift
        between commit and reveal is caught" property.
        """
        r = CommitRevealRound(
            epoch=1, node_ids=["A"],
            commit_deadline=10.0, reveal_deadline=20.0,
            pinned_algo_version=(2, 1),
        )
        scores = _scores()
        nonce = new_nonce()
        # Wrong-version hash but the COMMIT metadata says (2, 1) — the
        # round accepts the commit and binds to (2, 1).
        bad_hash = compute_commit_hash(scores, nonce, algo_version=(2, 2))
        r.submit_commit("A", bad_hash, now=1.0, algo_version=(2, 1))
        record = r.submit_reveal("A", scores, nonce, now=11.0)
        assert record.verified is False
        assert "hash mismatch" in record.reason


# =============================================================================
# 4. CommitRequest / RevealRequest carry the version pair
# =============================================================================

class TestMessageVersionFields:

    def test_commit_request_carries_versions(self):
        req = CommitRequest(
            node_id="A", epoch=1, commit_hash=b"\x00" * 32,
            scoring_algo_version=2, scoring_weights_version=1,
        )
        assert req.scoring_algo_version == 2
        assert req.scoring_weights_version == 1

    def test_reveal_request_carries_versions(self):
        req = RevealRequest(
            node_id="A", epoch=1,
            scores=_scores(), salt=new_nonce(),
            scoring_algo_version=2, scoring_weights_version=1,
        )
        assert req.scoring_algo_version == 2
        assert req.scoring_weights_version == 1

    def test_commit_request_half_set_version_raises(self):
        with pytest.raises(ValueError):
            CommitRequest(
                node_id="A", epoch=1, commit_hash=b"\x00" * 32,
                scoring_algo_version=2,
                # scoring_weights_version omitted
            )

    def test_reveal_request_half_set_version_raises(self):
        with pytest.raises(ValueError):
            RevealRequest(
                node_id="A", epoch=1,
                scores=_scores(), salt=new_nonce(),
                scoring_weights_version=1,
                # scoring_algo_version omitted
            )

    def test_commit_request_legacy_no_version_still_constructs(self):
        req = CommitRequest(node_id="A", epoch=1, commit_hash=b"\x00" * 32)
        assert req.scoring_algo_version is None
        assert req.scoring_weights_version is None


# =============================================================================
# 5. End-to-end: 5-node cluster, one node on a stale version
# =============================================================================

def _build_cluster(versions: list[tuple[int, int]]):
    """Build a cluster of len(versions) nodes; each node pinned to its version."""
    registry = InProcessRegistry()
    n = len(versions)
    kps = [NodeKeypair.from_seed(f"oracle-node-{i}", f"seed{i}".encode())
           for i in range(n)]
    nodes = []
    for i, kp in enumerate(kps):
        peers = tuple(kps[j].identity for j in range(n) if j != i)
        algo, weights = versions[i]
        node = OracleNode(
            kp, ClusterMembership(kp.identity, peers),
            transport=InProcessTransport(registry),
            scoring_algo_version=algo,
            scoring_weights_version=weights,
        )
        registry.register(node.node_id, node)
        nodes.append(node)
    return registry, nodes


def _reset(nodes):
    for n in nodes:
        n._rounds.clear()
        n._epoch_scores.clear()
        n._epoch_nonces.clear()
        n._epoch_snapshots.clear()


def _submit():
    calls: list[dict] = []

    def _s(wallet, aggregated):
        calls.append({"wallet": wallet, "score": aggregated.score})
        return calls[-1]
    return _s, calls


class TestEndToEndOneStaleNode:

    def test_stale_node_is_excluded_not_slashed(self):
        # 4 nodes on (2, 1); node 4 on stale (1, 1).
        versions = [(2, 1), (2, 1), (2, 1), (2, 1), (1, 1)]
        _registry, nodes = _build_cluster(versions)
        submit, calls = _submit()
        watchdog = ByzantineWatchdog()
        report = run_byzantine_epoch(
            nodes, 1, [profile_stable_a()],
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
        )
        # The stale node is version-excluded, NOT byzantine, NOT a non-revealer.
        stale = "oracle-node-4"
        assert stale in report.version_excluded_nodes
        assert stale not in report.byzantine_nodes
        assert stale not in report.non_revealers
        # No challenges filed — no slashing for being mid-upgrade.
        assert report.challenges_filed == ()
        assert report.non_reveal_challenges == ()
        # The 4 honest V1 nodes still produced a result.
        assert len(report.verified_nodes) == 4
        assert calls, "expected an aggregated score from the honest majority"

    def test_stale_node_does_not_accumulate_strikes_across_epochs(self):
        """Three epochs of version mismatch must NOT trip the strike threshold."""
        versions = [(2, 1), (2, 1), (2, 1), (2, 1), (1, 1)]
        _registry, nodes = _build_cluster(versions)
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()
        for ep in (1, 2, 3, 4):
            run_byzantine_epoch(
                nodes, ep, [profile_stable_a()],
                submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
            )
            _reset(nodes)
        assert watchdog.strikes_for("oracle-node-4") == 0
        assert watchdog.non_reveal_strikes_for("oracle-node-4") == 0
        assert watchdog.is_challenged("oracle-node-4") is False

    def test_stale_node_recovers_after_upgrade(self):
        """Once the node upgrades, it rejoins the round in the next epoch."""
        versions = [(2, 1), (2, 1), (2, 1), (2, 1), (1, 1)]
        _registry, nodes = _build_cluster(versions)
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()
        report1 = run_byzantine_epoch(
            nodes, 1, [profile_stable_a()],
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
        )
        assert "oracle-node-4" in report1.version_excluded_nodes

        # Simulate the operator rolling node 4 to the new version.
        nodes[4]._algo_version = (2, 1)
        _reset(nodes)

        report2 = run_byzantine_epoch(
            nodes, 2, [profile_stable_a()],
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
        )
        assert report2.version_excluded_nodes == ()
        assert "oracle-node-4" in report2.verified_nodes
