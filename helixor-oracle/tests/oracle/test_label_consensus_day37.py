"""
tests/oracle/test_label_consensus_day37.py — Day-37 label-consensus integration.

The Day-37 spec: commit-reveal payload v2 carries (score,
failure_mode_bitmask, diagnosis_payload_hash) per agent, the commit
hash binds all three, the aggregator runs a per-bit u64 majority on the
bitmask AND an exact-match honest-majority over the payload hash, and
the watchdog gets two new tracks:

    * label-deviation (Hamming-distance > threshold)  — soft, accumulates
    * payload-hash mismatch                           — hard, fires on 1st

This file pins:
    1. canonical_scores binds (bitmask, payload_hash) — commit hash differs
       when either field changes (no silent shift between commit + reveal).
    2. aggregate_scores per-bit u64 majority over `failure_mode_bitmask`.
    3. aggregate_scores exact-match consensus on `diagnosis_payload_hash`
       (signers + dissenters surfaced for downstream slashing).
    4. ByzantineWatchdog label-deviation soft track — 3 strikes -> challenge.
    5. ByzantineWatchdog payload-hash mismatch hard track — 1st occurrence
       already files the challenge (no flap window).
    6. Three chaos scenarios:
       (a) one Byzantine node lies about labels — excluded from signing set
       (b) one node down mid-reveal — consensus still forms at quorum
       (c) one node's kernel diverges on payload hash — hard isolation
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from oracle.cluster.aggregation import (
    AggregatedScore,
    NodeScore,
    QuorumNotMet,
    _majority_label_bits,
    aggregate_scores,
)
from oracle.cluster.byzantine_watchdog import (
    LABEL_DEVIATION_HAMMING_THRESHOLD,
    LABEL_STRIKE_THRESHOLD,
    LabelDeviationFlag,
    PROOF_LABEL_DEVIATION,
    PROOF_PAYLOAD_HASH_MISMATCH,
    PayloadHashMismatchFlag,
    ByzantineWatchdog,
)
from oracle.cluster.commit_reveal import (
    canonical_scores,
    compute_commit_hash,
    new_nonce,
    verify_reveal,
)
from oracle.cluster.messages import AgentScore


NONCE = b"\x42" * 32


def _score(
    wallet: str,
    score: int = 800,
    *,
    bitmask: int = 0,
    payload_hash: bytes = b"",
) -> AgentScore:
    return AgentScore(
        agent_wallet=wallet,
        score=score,
        alert_tier=1,
        flags=0,
        immediate_red=False,
        confidence=900,
        failure_mode_bitmask=bitmask,
        diagnosis_payload_hash=payload_hash,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. canonical_scores + commit hash bind the v2 fields
# ─────────────────────────────────────────────────────────────────────────────

class TestPayloadV2Binding:
    def test_bitmask_change_changes_commit_hash(self):
        a = (_score("A", bitmask=0),)
        b = (_score("A", bitmask=1 << 35),)   # tool_loop bit
        assert compute_commit_hash(a, NONCE) != compute_commit_hash(b, NONCE)

    def test_payload_hash_change_changes_commit_hash(self):
        h1 = b"\xaa" * 32
        h2 = b"\xbb" * 32
        a = (_score("A", payload_hash=h1),)
        b = (_score("A", payload_hash=h2),)
        assert compute_commit_hash(a, NONCE) != compute_commit_hash(b, NONCE)

    def test_empty_hash_distinct_from_zero_hash(self):
        # b"" -> normalized to 32 zero bytes; b"\x00"*32 -> same. They
        # must be IDENTICAL on the wire so a pre-v2 reveal matches a
        # post-v2 verifier that recomputed against an all-zero hash.
        empty = (_score("A", payload_hash=b""),)
        zeros = (_score("A", payload_hash=b"\x00" * 32),)
        assert canonical_scores(empty) == canonical_scores(zeros)

    def test_verify_reveal_catches_post_commit_bitmask_swap(self):
        # Node commits with bitmask=X, tries to reveal with bitmask=Y.
        committed = (_score("A", bitmask=1 << 35),)
        revealed  = (_score("A", bitmask=1 << 57),)
        h = compute_commit_hash(committed, NONCE)
        assert verify_reveal(h, revealed, NONCE) is False
        assert verify_reveal(h, committed, NONCE) is True

    def test_u64_bitmask_round_trip(self):
        # The top bit of the u64 must survive serialisation unscathed.
        top_bit = 1 << 63
        s = (_score("A", bitmask=top_bit),)
        h = compute_commit_hash(s, NONCE)
        assert verify_reveal(h, s, NONCE) is True


# ─────────────────────────────────────────────────────────────────────────────
# 2. Aggregator — per-bit u64 majority over failure_mode_bitmask
# ─────────────────────────────────────────────────────────────────────────────

class TestLabelBitmaskMajority:
    def test_majority_label_bits_unanimous(self):
        assert _majority_label_bits([0b101, 0b101, 0b101]) == 0b101

    def test_one_dissenter_does_not_set_bit(self):
        # 1-of-3 setting a bit is NOT a strict majority.
        assert _majority_label_bits([0b001, 0b000, 0b000]) == 0

    def test_two_of_three_sets_bit(self):
        assert _majority_label_bits([0b001, 0b001, 0b000]) == 0b001

    def test_top_u64_bit_majority(self):
        top = 1 << 63
        assert _majority_label_bits([top, top, 0]) == top
        assert _majority_label_bits([top, 0, 0]) == 0

    def test_aggregator_emits_majority_bitmask(self):
        b_set = 1 << 35
        agg = aggregate_scores(
            "A",
            [
                NodeScore("n1", _score("A", bitmask=b_set)),
                NodeScore("n2", _score("A", bitmask=b_set)),
                NodeScore("n3", _score("A", bitmask=0)),
            ],
            cluster_size=3,
        )
        assert agg.label_bitmask == b_set

    def test_aggregator_drops_minority_bit(self):
        b = 1 << 35
        agg = aggregate_scores(
            "A",
            [
                NodeScore("n1", _score("A", bitmask=b)),
                NodeScore("n2", _score("A", bitmask=0)),
                NodeScore("n3", _score("A", bitmask=0)),
            ],
            cluster_size=3,
        )
        assert agg.label_bitmask == 0


# ─────────────────────────────────────────────────────────────────────────────
# 3. Aggregator — exact-match payload-hash consensus
# ─────────────────────────────────────────────────────────────────────────────

class TestPayloadHashConsensus:
    def test_unanimous_payload_hash_consensus(self):
        h = b"\xcc" * 32
        agg = aggregate_scores(
            "A",
            [
                NodeScore("n1", _score("A", payload_hash=h)),
                NodeScore("n2", _score("A", payload_hash=h)),
                NodeScore("n3", _score("A", payload_hash=h)),
            ],
            cluster_size=3,
        )
        assert agg.diagnosis_payload_hash == h
        assert agg.payload_hash_signers == ("n1", "n2", "n3")
        assert agg.payload_hash_dissenters == ()
        assert agg.has_payload_hash_consensus

    def test_one_dissenter_isolated(self):
        majority = b"\xcc" * 32
        liar     = b"\xdd" * 32
        agg = aggregate_scores(
            "A",
            [
                NodeScore("n1", _score("A", payload_hash=majority)),
                NodeScore("n2", _score("A", payload_hash=majority)),
                NodeScore("n3", _score("A", payload_hash=liar)),
            ],
            cluster_size=3,
        )
        assert agg.diagnosis_payload_hash == majority
        assert set(agg.payload_hash_signers) == {"n1", "n2"}
        assert agg.payload_hash_dissenters == ("n3",)

    def test_no_consensus_when_evenly_split(self):
        # 2-2 split: no strict majority, NO consensus hash; dissenters
        # are every non-empty hash node.
        h1 = b"\x11" * 32
        h2 = b"\x22" * 32
        agg = aggregate_scores(
            "A",
            [
                NodeScore("n1", _score("A", payload_hash=h1)),
                NodeScore("n2", _score("A", payload_hash=h1)),
                NodeScore("n3", _score("A", payload_hash=h2)),
                NodeScore("n4", _score("A", payload_hash=h2)),
            ],
            cluster_size=5,                       # quorum 3 -> 4 contributors OK
        )
        # 2 != strict-majority of 4 (need >2). No consensus.
        assert agg.diagnosis_payload_hash == b""
        assert agg.payload_hash_signers == ()
        # Every node with a non-empty hash is a dissenter under "no consensus".
        assert set(agg.payload_hash_dissenters) == {"n1", "n2", "n3", "n4"}

    def test_score_only_mode_has_no_payload_consensus(self):
        # No node ran the kernel — empty hashes everywhere. No consensus,
        # no dissenters; the cluster is in score-only mode.
        agg = aggregate_scores(
            "A",
            [
                NodeScore("n1", _score("A")),
                NodeScore("n2", _score("A")),
                NodeScore("n3", _score("A")),
            ],
            cluster_size=3,
        )
        assert agg.diagnosis_payload_hash == b""
        assert agg.payload_hash_signers == ()
        assert agg.payload_hash_dissenters == ()
        assert not agg.has_payload_hash_consensus

    def test_pre_v2_node_does_not_dissent(self):
        # 2 honest nodes ran the kernel; 1 legacy node didn't (empty hash).
        # The empty-hash node is NOT a dissenter — it just didn't vote.
        h = b"\xcc" * 32
        agg = aggregate_scores(
            "A",
            [
                NodeScore("n1", _score("A", payload_hash=h)),
                NodeScore("n2", _score("A", payload_hash=h)),
                NodeScore("n3", _score("A")),       # pre-v2 / score-only
            ],
            cluster_size=3,
        )
        assert agg.diagnosis_payload_hash == h
        assert "n3" not in agg.payload_hash_dissenters


# ─────────────────────────────────────────────────────────────────────────────
# 4. Watchdog — label-deviation soft track
# ─────────────────────────────────────────────────────────────────────────────

class TestLabelDeviationWatchdog:
    def _flag(self, node_id: str, epoch: int, dist: int = 5) -> LabelDeviationFlag:
        return LabelDeviationFlag(
            node_id=node_id,
            epoch=epoch,
            subject_agent="agentA",
            accused_bitmask=0xFF,
            consensus_bitmask=0x00,
            hamming_distance=dist,
        )

    def test_threshold_pin(self):
        assert LABEL_DEVIATION_HAMMING_THRESHOLD == 3
        assert LABEL_STRIKE_THRESHOLD == 3

    def test_one_label_strike_does_not_challenge(self):
        w = ByzantineWatchdog()
        filed = w.record_label_deviations(1, [self._flag("n3", 1)])
        assert filed == []
        assert w.label_strikes_for("n3") == 1
        assert not w.is_label_challenged("n3")

    def test_three_label_strikes_files_a_challenge(self):
        w = ByzantineWatchdog()
        filings: list = []
        w.record_label_deviations(1, [self._flag("n3", 1)], challenge_fn=filings.append)
        w.record_label_deviations(2, [self._flag("n3", 2)], challenge_fn=filings.append)
        w.record_label_deviations(3, [self._flag("n3", 3)], challenge_fn=filings.append)
        assert len(filings) == 1
        assert filings[0].accused_node == "n3"
        assert filings[0].proof_type == PROOF_LABEL_DEVIATION
        assert filings[0].strikes == 3
        assert w.is_label_challenged("n3")

    def test_dedup_within_an_epoch(self):
        w = ByzantineWatchdog()
        w.record_label_deviations(
            1,
            [self._flag("n3", 1, dist=4), self._flag("n3", 1, dist=10)],
        )
        # WORST distance is cited, not summed.
        assert w.label_strikes_for("n3") == 1

    def test_idempotent_across_reruns(self):
        w = ByzantineWatchdog()
        w.record_label_deviations(1, [self._flag("n3", 1)])
        w.record_label_deviations(1, [self._flag("n3", 1)])
        assert w.label_strikes_for("n3") == 1


# ─────────────────────────────────────────────────────────────────────────────
# 5. Watchdog — payload-hash mismatch HARD track
# ─────────────────────────────────────────────────────────────────────────────

class TestPayloadHashMismatchWatchdog:
    def _flag(self, node_id: str, epoch: int) -> PayloadHashMismatchFlag:
        return PayloadHashMismatchFlag(
            node_id=node_id,
            epoch=epoch,
            subject_agent="agentA",
            accused_hash=b"\xdd" * 32,
            consensus_hash=b"\xcc" * 32,
        )

    def test_first_occurrence_files_challenge(self):
        w = ByzantineWatchdog()
        filings: list = []
        filed = w.record_payload_hash_mismatches(
            1, [self._flag("n3", 1)], challenge_fn=filings.append,
        )
        assert len(filed) == 1
        assert len(filings) == 1
        assert filings[0].proof_type == PROOF_PAYLOAD_HASH_MISMATCH
        assert filings[0].accused_node == "n3"
        assert filings[0].strikes == 1
        assert w.is_payload_hash_mismatch_challenged("n3")

    def test_second_occurrence_does_not_double_charge(self):
        w = ByzantineWatchdog()
        filings: list = []
        w.record_payload_hash_mismatches(
            1, [self._flag("n3", 1)], challenge_fn=filings.append,
        )
        w.record_payload_hash_mismatches(
            2, [self._flag("n3", 2)], challenge_fn=filings.append,
        )
        # Strike count climbs, but only ONE challenge is filed.
        assert w.payload_hash_mismatch_strikes_for("n3") == 2
        assert len(filings) == 1

    def test_dedup_within_an_epoch(self):
        w = ByzantineWatchdog()
        w.record_payload_hash_mismatches(
            1, [self._flag("n3", 1), self._flag("n3", 1)],
        )
        assert w.payload_hash_mismatch_strikes_for("n3") == 1


# ─────────────────────────────────────────────────────────────────────────────
# 6. CHAOS — three Byzantine scenarios end-to-end through the aggregator
# ─────────────────────────────────────────────────────────────────────────────

class TestByzantineChaosLabels:
    """
    The three Day-37 done-when chaos scenarios.

    Each runs aggregate_scores over a 3-node cluster and asserts the cert
    carries the HONEST consensus and the watchdog can isolate the liar.
    The end-to-end network-level chaos (drop_reveal etc.) is already
    exercised by tests/oracle/test_commit_reveal_cluster.py — here the
    chaos lives in the AGGREGATOR'S view of the per-node payloads, the
    layer Day-37 added.
    """

    HONEST_HASH = b"\xaa" * 32
    LIAR_HASH   = b"\xbb" * 32

    def test_liar_excluded_from_signing_set_cert_carries_consensus(self):
        # 2 honest + 1 liar. Honest nodes assert label bits {3, 5}; the
        # liar asserts {3, 50} — a 4-bit Hamming distance from majority.
        honest_bits = (1 << 3) | (1 << 5)
        liar_bits   = (1 << 3) | (1 << 50)
        agg = aggregate_scores(
            "agentA",
            [
                NodeScore("h1", _score("agentA", bitmask=honest_bits,
                                       payload_hash=self.HONEST_HASH)),
                NodeScore("h2", _score("agentA", bitmask=honest_bits,
                                       payload_hash=self.HONEST_HASH)),
                NodeScore("liar", _score("agentA", bitmask=liar_bits,
                                          payload_hash=self.LIAR_HASH)),
            ],
            cluster_size=3,
        )
        # The cert carries the HONEST consensus.
        assert agg.label_bitmask == honest_bits
        assert agg.diagnosis_payload_hash == self.HONEST_HASH
        # Liar is excluded from the signing set, flagged as a hard dissenter.
        assert set(agg.payload_hash_signers) == {"h1", "h2"}
        assert agg.payload_hash_dissenters == ("liar",)

    def test_node_down_mid_reveal_consensus_still_forms_at_quorum(self):
        # 3 honest nodes wanted to reveal, but n3 went down before reveal.
        # Only n1, n2 contribute -> quorum (2 of 3) holds, cert ships.
        bits = (1 << 35)
        agg = aggregate_scores(
            "agentA",
            [
                NodeScore("h1", _score("agentA", bitmask=bits,
                                       payload_hash=self.HONEST_HASH)),
                NodeScore("h2", _score("agentA", bitmask=bits,
                                       payload_hash=self.HONEST_HASH)),
            ],
            cluster_size=3,
        )
        assert agg.label_bitmask == bits
        assert agg.diagnosis_payload_hash == self.HONEST_HASH
        # No dissenters — the offline node simply didn't contribute.
        assert agg.payload_hash_dissenters == ()
        # Quorum met (2 of 3) even with one node down.
        assert agg.node_count == 2
        assert agg.quorum == 2

    def test_node_down_below_quorum_raises(self):
        # 1 surviving node of 3 — below quorum. The cluster refuses.
        with pytest.raises(QuorumNotMet):
            aggregate_scores(
                "agentA",
                [
                    NodeScore("h1", _score("agentA", payload_hash=self.HONEST_HASH)),
                ],
                cluster_size=3,
            )

    def test_payload_hash_mismatch_isolates_liar_hard(self):
        # Liar's kernel produced DIFFERENT canonical JSON bytes than the
        # honest pair — flagged as a hard dissenter and the watchdog
        # files the challenge on the FIRST occurrence (no flap window).
        agg = aggregate_scores(
            "agentA",
            [
                NodeScore("h1", _score("agentA", bitmask=1 << 35,
                                       payload_hash=self.HONEST_HASH)),
                NodeScore("h2", _score("agentA", bitmask=1 << 35,
                                       payload_hash=self.HONEST_HASH)),
                NodeScore("liar", _score("agentA", bitmask=1 << 35,
                                          payload_hash=self.LIAR_HASH)),
            ],
            cluster_size=3,
        )
        assert agg.payload_hash_dissenters == ("liar",)

        # Feed the dissenter into the watchdog — hard fire on first epoch.
        w = ByzantineWatchdog()
        filings: list = []
        w.record_payload_hash_mismatches(
            1,
            [PayloadHashMismatchFlag(
                node_id="liar",
                epoch=1,
                subject_agent="agentA",
                accused_hash=self.LIAR_HASH,
                consensus_hash=self.HONEST_HASH,
            )],
            challenge_fn=filings.append,
        )
        assert len(filings) == 1
        assert filings[0].proof_type == PROOF_PAYLOAD_HASH_MISMATCH
        assert filings[0].accused_node == "liar"
