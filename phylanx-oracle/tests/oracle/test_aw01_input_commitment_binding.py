"""
tests/oracle/test_aw01_input_commitment_binding.py — AW-01, layer 2.

Layer 1 (test_input_commitment.py) pinned the pure SHA-256 primitive.
This layer pins the commit-reveal BINDING — a revealing node cannot swap
inputs after seeing peers' commits, because its committed input_commitments
are bound by the hash.
"""

from __future__ import annotations

import pytest

from oracle.cluster.commit_reveal import (
    compute_commit_hash,
    new_nonce,
    verify_reveal,
)
from oracle.cluster.commit_reveal_round import (
    CommitRevealRound,
    RoundPhase,
)
from oracle.cluster.messages import AgentScore, RevealRequest


def _score(wallet: str, score: int) -> AgentScore:
    return AgentScore(
        agent_wallet=wallet, score=score,
        alert_tier=0, flags=0, immediate_red=False, confidence=900,
    )


SCORES = (_score("agentA", 851), _score("agentB", 420))
COMMITMENTS_A = (("agentA", b"\xaa" * 32), ("agentB", b"\xbb" * 32))
COMMITMENTS_B = (("agentA", b"\xcc" * 32), ("agentB", b"\xdd" * 32))


# =============================================================================
# compute_commit_hash + verify_reveal — binding the input commitments
# =============================================================================

class TestCommitVerifyWithInputCommitments:

    def test_round_trip_with_input_commitments_verifies(self):
        nonce = b"\x42" * 32
        h = compute_commit_hash(SCORES, nonce, input_commitments=COMMITMENTS_A)
        assert verify_reveal(h, SCORES, nonce, input_commitments=COMMITMENTS_A)

    def test_changed_input_commitment_fails_verification(self):
        # Committed under A, tries to reveal under B — the attacker
        # changed the input commitments after seeing peers' commits.
        nonce = b"\x42" * 32
        h = compute_commit_hash(SCORES, nonce, input_commitments=COMMITMENTS_A)
        assert not verify_reveal(
            h, SCORES, nonce, input_commitments=COMMITMENTS_B,
        )

    def test_revealing_without_commitments_after_committing_with_them_fails(self):
        # Strip the input_commitments at reveal time — must fail.
        nonce = b"\x42" * 32
        h = compute_commit_hash(SCORES, nonce, input_commitments=COMMITMENTS_A)
        assert not verify_reveal(h, SCORES, nonce, input_commitments=None)

    def test_committing_without_commitments_then_adding_them_fails(self):
        # Opposite direction — committed with no commitments, reveals
        # with commitments. Both directions must break.
        nonce = b"\x42" * 32
        h = compute_commit_hash(SCORES, nonce, input_commitments=None)
        assert not verify_reveal(
            h, SCORES, nonce, input_commitments=COMMITMENTS_A,
        )

    def test_legacy_path_without_commitments_still_works(self):
        # Back-compat: a caller that never passes input_commitments gets
        # the pre-AW-01 wire format.
        nonce = b"\x42" * 32
        h = compute_commit_hash(SCORES, nonce)
        assert verify_reveal(h, SCORES, nonce)

    def test_commitment_order_does_not_affect_hash(self):
        # The tag is sorted by agent_wallet internally — reversing the
        # caller's pair order must NOT change the commit hash.
        nonce = b"\x42" * 32
        h_a = compute_commit_hash(
            SCORES, nonce, input_commitments=COMMITMENTS_A,
        )
        h_a_rev = compute_commit_hash(
            SCORES, nonce, input_commitments=tuple(reversed(COMMITMENTS_A)),
        )
        assert h_a == h_a_rev

    def test_wrong_commitment_length_raises(self):
        nonce = b"\x42" * 32
        with pytest.raises(ValueError, match="32 bytes"):
            compute_commit_hash(
                SCORES, nonce,
                input_commitments=(("agentA", b"too-short"),),
            )

    def test_input_commitments_compose_with_snapshot_and_algo_version(self):
        # All three optional bindings should be foldable together.
        nonce = b"\x42" * 32
        snap = b"\x99" * 32
        algo = (2, 7)
        h = compute_commit_hash(
            SCORES, nonce,
            snapshot_hash=snap, algo_version=algo,
            input_commitments=COMMITMENTS_A,
        )
        assert verify_reveal(
            h, SCORES, nonce,
            snapshot_hash=snap, algo_version=algo,
            input_commitments=COMMITMENTS_A,
        )
        # Drop any ONE of the three bindings -> verify fails.
        assert not verify_reveal(
            h, SCORES, nonce, algo_version=algo,
            input_commitments=COMMITMENTS_A,
        )
        assert not verify_reveal(
            h, SCORES, nonce, snapshot_hash=snap,
            input_commitments=COMMITMENTS_A,
        )
        assert not verify_reveal(
            h, SCORES, nonce, snapshot_hash=snap, algo_version=algo,
        )


# =============================================================================
# Round state machine — submitting a reveal with the wrong commitments fails
# =============================================================================

class TestRoundBinding:

    def _round(self, node_ids):
        return CommitRevealRound(
            epoch=1, node_ids=node_ids,
            commit_deadline=10.0, reveal_deadline=20.0, opened_at=0.0,
        )

    def test_honest_commit_and_reveal_with_commitments_round_trips(self):
        nonce = new_nonce()
        h = compute_commit_hash(
            SCORES, nonce, input_commitments=COMMITMENTS_A,
        )
        r = self._round(["nodeA", "nodeB"])
        r.submit_commit("nodeA", h, now=1.0)
        r.submit_commit("nodeB", b"\x00" * 32, now=1.0)
        rec = r.submit_reveal(
            "nodeA", SCORES, nonce, now=11.0,
            input_commitments=COMMITMENTS_A,
        )
        assert rec.verified
        assert rec.input_commitments == COMMITMENTS_A

    def test_revealing_swapped_commitments_fails_verification(self):
        # The attacker committed honestly (binding COMMITMENTS_A) but
        # tries to reveal under COMMITMENTS_B (perhaps to fake the
        # cross-node agreement on B's hash).
        nonce = new_nonce()
        h = compute_commit_hash(
            SCORES, nonce, input_commitments=COMMITMENTS_A,
        )
        r = self._round(["nodeA", "nodeB"])
        r.submit_commit("nodeA", h, now=1.0)
        r.submit_commit("nodeB", b"\x00" * 32, now=1.0)
        rec = r.submit_reveal(
            "nodeA", SCORES, nonce, now=11.0,
            input_commitments=COMMITMENTS_B,
        )
        assert not rec.verified
        # The unverified reveal is still recorded for the audit trail.
        assert rec.input_commitments == COMMITMENTS_B
        assert "hash mismatch" in rec.reason


# =============================================================================
# RevealRequest message validation
# =============================================================================

class TestRevealRequestMessage:

    def test_valid_input_commitments_accepted(self):
        req = RevealRequest(
            node_id="n1", epoch=1,
            scores=SCORES, salt=b"\x00" * 32,
            input_commitments=COMMITMENTS_A,
        )
        assert req.input_commitments == COMMITMENTS_A

    def test_short_commitment_rejected(self):
        with pytest.raises(ValueError, match="32 bytes"):
            RevealRequest(
                node_id="n1", epoch=1,
                scores=SCORES, salt=b"\x00" * 32,
                input_commitments=(("agentA", b"short"),),
            )

    def test_empty_wallet_rejected(self):
        with pytest.raises(ValueError, match="empty wallet"):
            RevealRequest(
                node_id="n1", epoch=1,
                scores=SCORES, salt=b"\x00" * 32,
                input_commitments=(("", b"\xaa" * 32),),
            )

    def test_omitted_commitments_default_to_none(self):
        req = RevealRequest(
            node_id="n1", epoch=1,
            scores=SCORES, salt=b"\x00" * 32,
        )
        assert req.input_commitments is None
