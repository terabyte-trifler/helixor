"""
tests/oracle/test_commit_reveal.py — the commit-reveal protocol.

Pins the cryptographic core: the commit hash hides scores, a reveal
verifies against its commit, and the round state machine enforces the two
phases and their deadlines.
"""

from __future__ import annotations

import pytest

from oracle.cluster.commit_reveal import (
    NONCE_BYTES,
    canonical_scores,
    compute_commit_hash,
    new_nonce,
    verify_reveal,
)
from oracle.cluster.commit_reveal_round import (
    CommitRejected,
    CommitRevealRound,
    RevealRejected,
    RoundPhase,
)
from oracle.cluster.messages import AgentScore


def _score(wallet: str, score: int, **kw) -> AgentScore:
    return AgentScore(
        agent_wallet=wallet, score=score,
        alert_tier=kw.get("alert", 0), flags=kw.get("flags", 0),
        immediate_red=kw.get("ir", False), confidence=kw.get("conf", 900),
    )


SCORES = (_score("agentA", 851, ir=True), _score("agentB", 420))


# =============================================================================
# Nonce
# =============================================================================

class TestNonce:

    def test_nonce_is_32_bytes(self):
        assert len(new_nonce()) == NONCE_BYTES == 32

    def test_nonces_are_unique(self):
        # 1000 nonces, all distinct — they must be unpredictable.
        nonces = {new_nonce() for _ in range(1000)}
        assert len(nonces) == 1000


# =============================================================================
# Canonical serialisation
# =============================================================================

class TestCanonicalScores:

    def test_serialisation_is_deterministic(self):
        assert canonical_scores(SCORES) == canonical_scores(SCORES)

    def test_order_independent(self):
        # A score set has no inherent order — canonical form sorts.
        forward = canonical_scores(SCORES)
        reversed_ = canonical_scores(tuple(reversed(SCORES)))
        assert forward == reversed_

    def test_different_scores_serialise_differently(self):
        a = canonical_scores((_score("agentA", 851),))
        b = canonical_scores((_score("agentA", 852),))
        assert a != b

    def test_agent_count_is_bound(self):
        # [A] and [A, B] must not collide — the length prefix prevents it.
        one = canonical_scores((_score("agentA", 100),))
        two = canonical_scores((_score("agentA", 100), _score("agentB", 0)))
        assert one != two


# =============================================================================
# Commit hash + verification
# =============================================================================

class TestCommitHash:

    def test_commit_hash_is_32_bytes(self):
        assert len(compute_commit_hash(SCORES, new_nonce())) == 32

    def test_same_inputs_same_hash(self):
        nonce = new_nonce()
        assert compute_commit_hash(SCORES, nonce) == compute_commit_hash(SCORES, nonce)

    def test_different_nonce_different_hash(self):
        # The nonce is what hides the score — different nonce, different hash.
        assert compute_commit_hash(SCORES, new_nonce()) != \
               compute_commit_hash(SCORES, new_nonce())

    def test_bad_nonce_length_rejected(self):
        with pytest.raises(ValueError):
            compute_commit_hash(SCORES, b"too-short")

    def test_verify_accepts_the_right_reveal(self):
        nonce = new_nonce()
        commit = compute_commit_hash(SCORES, nonce)
        assert verify_reveal(commit, SCORES, nonce) is True

    def test_verify_rejects_tampered_scores(self):
        # THE DONE-WHEN CORE: a copier reveals different scores than it
        # committed -> verification fails.
        nonce = new_nonce()
        commit = compute_commit_hash(SCORES, nonce)
        copied = (_score("agentA", 999), _score("agentB", 420))
        assert verify_reveal(commit, copied, nonce) is False

    def test_verify_rejects_wrong_nonce(self):
        commit = compute_commit_hash(SCORES, new_nonce())
        assert verify_reveal(commit, SCORES, new_nonce()) is False

    def test_verify_rejects_bad_nonce_length(self):
        commit = compute_commit_hash(SCORES, new_nonce())
        assert verify_reveal(commit, SCORES, b"short") is False


# =============================================================================
# The round state machine — phases
# =============================================================================

class TestRoundPhases:

    def _round(self):
        return CommitRevealRound(
            epoch=25, node_ids=["n0", "n1", "n2"],
            commit_deadline=10.0, reveal_deadline=20.0,
        )

    def test_starts_in_commit_phase(self):
        assert self._round().phase(0.0) is RoundPhase.OPEN_COMMIT

    def test_commit_phase_closes_when_all_commit(self):
        r = self._round()
        for nid in ["n0", "n1", "n2"]:
            r.submit_commit(nid, compute_commit_hash(SCORES, new_nonce()), now=1.0)
        assert r.phase(1.0) is RoundPhase.OPEN_REVEAL

    def test_commit_phase_closes_at_deadline(self):
        r = self._round()
        r.submit_commit("n0", compute_commit_hash(SCORES, new_nonce()), now=1.0)
        # Only 1 of 3 committed, but the deadline passes -> phase advances.
        assert r.phase(10.0) is RoundPhase.OPEN_REVEAL

    def test_round_closes_when_all_reveal(self):
        r = self._round()
        nonces = {nid: new_nonce() for nid in ["n0", "n1", "n2"]}
        for nid in ["n0", "n1", "n2"]:
            r.submit_commit(nid, compute_commit_hash(SCORES, nonces[nid]), now=1.0)
        for nid in ["n0", "n1", "n2"]:
            r.submit_reveal(nid, SCORES, nonces[nid], now=11.0)
        assert r.phase(11.0) is RoundPhase.CLOSED

    def test_round_closes_at_reveal_deadline(self):
        r = self._round()
        n0 = new_nonce()
        r.submit_commit("n0", compute_commit_hash(SCORES, n0), now=1.0)
        # commit phase closes at 10; reveal deadline 20 passes -> closed.
        assert r.phase(20.0) is RoundPhase.CLOSED


# =============================================================================
# The round — commit rules
# =============================================================================

class TestRoundCommit:

    def _round(self):
        return CommitRevealRound(
            epoch=25, node_ids=["n0", "n1", "n2"],
            commit_deadline=10.0, reveal_deadline=20.0,
        )

    def test_unknown_node_rejected(self):
        r = self._round()
        with pytest.raises(CommitRejected, match="not a member"):
            r.submit_commit("ghost", compute_commit_hash(SCORES, new_nonce()),
                            now=1.0)

    def test_double_commit_rejected(self):
        # The first commit BINDS — it cannot be replaced.
        r = self._round()
        r.submit_commit("n0", compute_commit_hash(SCORES, new_nonce()), now=1.0)
        with pytest.raises(CommitRejected, match="already committed"):
            r.submit_commit("n0", compute_commit_hash(SCORES, new_nonce()),
                            now=1.0)

    def test_late_commit_rejected(self):
        r = self._round()
        with pytest.raises(CommitRejected, match="too late"):
            r.submit_commit("n0", compute_commit_hash(SCORES, new_nonce()),
                            now=11.0)

    def test_bad_hash_length_rejected(self):
        r = self._round()
        with pytest.raises(CommitRejected, match="32-byte"):
            r.submit_commit("n0", b"short", now=1.0)


# =============================================================================
# The round — reveal rules
# =============================================================================

class TestRoundReveal:

    def _committed_round(self):
        r = CommitRevealRound(
            epoch=25, node_ids=["n0", "n1", "n2"],
            commit_deadline=10.0, reveal_deadline=20.0,
        )
        nonces = {nid: new_nonce() for nid in ["n0", "n1", "n2"]}
        for nid in ["n0", "n1", "n2"]:
            r.submit_commit(nid, compute_commit_hash(SCORES, nonces[nid]), now=1.0)
        return r, nonces

    def test_reveal_before_commit_phase_closes_rejected(self):
        # No peeking: a reveal during the commit phase is rejected.
        r = CommitRevealRound(
            epoch=25, node_ids=["n0", "n1", "n2"],
            commit_deadline=10.0, reveal_deadline=20.0,
        )
        n0 = new_nonce()
        r.submit_commit("n0", compute_commit_hash(SCORES, n0), now=1.0)
        # n1, n2 have not committed -> still in commit phase.
        with pytest.raises(RevealRejected, match="commit phase"):
            r.submit_reveal("n0", SCORES, n0, now=2.0)

    def test_reveal_without_commit_rejected(self):
        r, nonces = self._committed_round()
        # A node with no commit cannot reveal.
        r2 = CommitRevealRound(
            epoch=25, node_ids=["n0", "n1"],
            commit_deadline=10.0, reveal_deadline=20.0,
        )
        r2.submit_commit("n0", compute_commit_hash(SCORES, nonces["n0"]), now=1.0)
        # n1 never committed; force into reveal phase by deadline.
        with pytest.raises(RevealRejected, match="no commit"):
            r2.submit_reveal("n1", SCORES, new_nonce(), now=11.0)

    def test_valid_reveal_verifies(self):
        r, nonces = self._committed_round()
        rec = r.submit_reveal("n0", SCORES, nonces["n0"], now=11.0)
        assert rec.verified is True

    def test_double_reveal_rejected(self):
        r, nonces = self._committed_round()
        r.submit_reveal("n0", SCORES, nonces["n0"], now=11.0)
        with pytest.raises(RevealRejected, match="already revealed"):
            r.submit_reveal("n0", SCORES, nonces["n0"], now=11.0)

    def test_late_reveal_rejected(self):
        r, nonces = self._committed_round()
        with pytest.raises(RevealRejected, match="too late"):
            r.submit_reveal("n0", SCORES, nonces["n0"], now=21.0)


# =============================================================================
# THE DONE-WHEN — a copying node fails verification
# =============================================================================

class TestCopyingNodeFails:

    def test_a_node_copying_a_revealed_score_fails_verification(self):
        """
        THE DONE-WHEN: a node that did not score independently commits a
        placeholder, then tries to reveal a score it copied from a peer.
        Its commit does not match the copied score -> verification fails.
        """
        r = CommitRevealRound(
            epoch=25, node_ids=["honest", "copier"],
            commit_deadline=10.0, reveal_deadline=20.0,
        )
        honest_scores = (_score("agentA", 851, ir=True),)
        honest_nonce = new_nonce()

        # The copier has NOT computed independently — it commits a guess.
        copier_placeholder = (_score("agentA", 500),)
        copier_nonce = new_nonce()

        # Phase 1 — both commit. The copier is now BOUND to its placeholder.
        r.submit_commit("honest",
                        compute_commit_hash(honest_scores, honest_nonce), now=1.0)
        r.submit_commit("copier",
                        compute_commit_hash(copier_placeholder, copier_nonce),
                        now=1.0)

        # Phase 2 — honest reveals truthfully.
        honest_rec = r.submit_reveal("honest", honest_scores, honest_nonce,
                                     now=11.0)
        assert honest_rec.verified is True

        # The copier sees honest's 851 and tries to reveal it as its own.
        copier_rec = r.submit_reveal("copier", honest_scores, copier_nonce,
                                     now=11.0)
        # FAILS — the copied score does not hash to the copier's commit.
        assert copier_rec.verified is False
        assert "hash mismatch" in copier_rec.reason

        # The copier is excluded from the verified set.
        assert r.verified_nodes() == frozenset({"honest"})
        assert "copier" in r.faulty_nodes(21.0)

    def test_copier_cannot_replace_its_commit(self):
        # The copier cannot go back and commit the real score after seeing
        # it — the commit phase is closed by reveal time.
        r = CommitRevealRound(
            epoch=25, node_ids=["honest", "copier"],
            commit_deadline=10.0, reveal_deadline=20.0,
        )
        honest_nonce = new_nonce()
        r.submit_commit("honest",
                        compute_commit_hash(SCORES, honest_nonce), now=1.0)
        r.submit_commit("copier",
                        compute_commit_hash((_score("agentA", 0),), new_nonce()),
                        now=1.0)
        # Reveal phase is open now. The copier tries to slip in a NEW commit.
        with pytest.raises(CommitRejected):
            r.submit_commit("copier",
                            compute_commit_hash(SCORES, new_nonce()), now=11.0)


# =============================================================================
# Timeout = fault
# =============================================================================

class TestTimeoutHandling:

    def test_node_that_never_commits_is_faulty(self):
        r = CommitRevealRound(
            epoch=25, node_ids=["n0", "n1", "n2"],
            commit_deadline=10.0, reveal_deadline=20.0,
        )
        nonces = {nid: new_nonce() for nid in ["n0", "n1"]}
        for nid in ["n0", "n1"]:
            r.submit_commit(nid, compute_commit_hash(SCORES, nonces[nid]), now=1.0)
        for nid in ["n0", "n1"]:
            r.submit_reveal(nid, SCORES, nonces[nid], now=11.0)
        # n2 never committed -> faulty.
        assert "n2" in r.faulty_nodes(21.0)
        assert r.verified_nodes() == frozenset({"n0", "n1"})

    def test_node_that_commits_but_never_reveals_is_faulty(self):
        r = CommitRevealRound(
            epoch=25, node_ids=["n0", "n1", "n2"],
            commit_deadline=10.0, reveal_deadline=20.0,
        )
        nonces = {nid: new_nonce() for nid in ["n0", "n1", "n2"]}
        for nid in ["n0", "n1", "n2"]:
            r.submit_commit(nid, compute_commit_hash(SCORES, nonces[nid]), now=1.0)
        # Only n0, n1 reveal.
        for nid in ["n0", "n1"]:
            r.submit_reveal(nid, SCORES, nonces[nid], now=11.0)
        # n2 committed but did not reveal -> still faulty.
        assert "n2" in r.faulty_nodes(21.0)
        assert "n2" not in r.verified_nodes()
