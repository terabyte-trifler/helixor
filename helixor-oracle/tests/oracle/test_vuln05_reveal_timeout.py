"""
tests/oracle/test_vuln05_reveal_timeout.py — VULN-05 commit-reveal livelock.

Pins the three guarantees the audit asks for:

  1. **Reveal timeout is hard.** A reveal that arrives at-or-after the
     reveal-deadline is rejected, regardless of phase. The committed-but-
     silent node cannot stall the round by holding back its reveal past
     the timeout.
  2. **Partial-reveal early close.** Once a quorum of VERIFIED reveals
     is in, the round closes — the cluster proceeds without waiting on
     stragglers. The "1 of 5 commits but doesn't reveal" attack scenario
     no longer burns the full reveal window per epoch.
  3. **Non-reveal strikes accumulate per epoch.** A node that commits
     and then goes silent earns a strike each epoch it does so; three
     such epochs route to an on-chain challenge_oracle through the
     watchdog (PROOF_NON_REVEAL), the same escalation pattern as
     ConflictingScores and SlowDrift.

Together: the protocol cannot livelock, the cluster cannot be slowed
deterministically, and a node engineered to grief liveness is slashed.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from oracle.cluster import (
    NON_REVEAL_STRIKE_THRESHOLD,
    PROOF_NON_REVEAL,
    ByzantineWatchdog,
    InProcessRegistry,
    InProcessTransport,
    NodeKeypair,
    NonRevealFlag,
    RoundPhase,
    compute_commit_hash,
    new_nonce,
    quorum_for,
    run_byzantine_epoch,
    simulate_commit_reveal_epoch,
)
from oracle.cluster.commit_reveal_round import (
    CommitRevealRound,
    RevealRejected,
)
from oracle.cluster.messages import AgentScore
from oracle.node import ClusterMembership, OracleNode
from tests.oracle.agent_profiles import (
    profile_adversarial,
    profile_stable_a,
)


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# Test helpers
# =============================================================================

def _score(wallet: str, score: int) -> AgentScore:
    return AgentScore(
        agent_wallet=wallet, score=score,
        alert_tier=0, flags=0, immediate_red=False, confidence=900,
    )


SCORES = (_score("agentA", 851), _score("agentB", 420))


def _submit():
    calls: list[dict] = []

    def _s(wallet, aggregated):
        calls.append({"wallet": wallet, "score": aggregated.score})
        return calls[-1]

    return _s, calls


def _build_cluster(n: int = 5):
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
    for n in nodes:
        n._rounds.clear()
        n._epoch_scores.clear()
        n._epoch_nonces.clear()


# =============================================================================
# Guarantee 1 — reveal timeout is hard
# =============================================================================

class TestRevealTimeoutIsHard:

    def _committed_round(self, min_reveals=None):
        r = CommitRevealRound(
            epoch=25, node_ids=["n0", "n1", "n2"],
            commit_deadline=10.0, reveal_deadline=20.0,
            min_reveals=min_reveals,
        )
        nonces = {nid: new_nonce() for nid in ["n0", "n1", "n2"]}
        for nid in ["n0", "n1", "n2"]:
            r.submit_commit(nid, compute_commit_hash(SCORES, nonces[nid]),
                            now=1.0)
        return r, nonces

    def test_reveal_at_deadline_is_rejected(self):
        # The deadline is inclusive: a reveal AT the deadline is too late.
        r, nonces = self._committed_round()
        with pytest.raises(RevealRejected, match="too late"):
            r.submit_reveal("n0", SCORES, nonces["n0"], now=20.0)

    def test_reveal_after_deadline_is_rejected(self):
        r, nonces = self._committed_round()
        with pytest.raises(RevealRejected, match="too late"):
            r.submit_reveal("n0", SCORES, nonces["n0"], now=100.0)

    def test_deadline_rejects_even_when_quorum_already_reached(self):
        # If the round closed early on quorum, a STRAGGLER arriving past
        # the reveal-deadline is still rejected.
        r, nonces = self._committed_round(min_reveals=2)
        r.submit_reveal("n0", SCORES, nonces["n0"], now=11.0)
        r.submit_reveal("n1", SCORES, nonces["n1"], now=11.0)
        # Quorum reached, phase CLOSED. n2 tries to reveal past deadline.
        assert r.phase(11.0) is RoundPhase.CLOSED
        with pytest.raises(RevealRejected, match="too late"):
            r.submit_reveal("n2", SCORES, nonces["n2"], now=25.0)


# =============================================================================
# Guarantee 2 — partial-reveal early close kills the livelock
# =============================================================================

class TestPartialRevealEarlyClose:

    def test_round_closes_early_on_quorum_of_verified_reveals(self):
        # 5-node round; quorum = 3. After 3 verified reveals the round
        # is CLOSED — the cluster does not wait for the other 2.
        r = CommitRevealRound(
            epoch=25, node_ids=[f"n{i}" for i in range(5)],
            commit_deadline=10.0, reveal_deadline=20.0,
            min_reveals=3,
        )
        nonces = {nid: new_nonce() for nid in [f"n{i}" for i in range(5)]}
        for nid in [f"n{i}" for i in range(5)]:
            r.submit_commit(nid, compute_commit_hash(SCORES, nonces[nid]),
                            now=1.0)
        assert r.phase(1.0) is RoundPhase.OPEN_REVEAL

        r.submit_reveal("n0", SCORES, nonces["n0"], now=11.0)
        assert r.phase(11.0) is RoundPhase.OPEN_REVEAL    # 1/3
        r.submit_reveal("n1", SCORES, nonces["n1"], now=11.0)
        assert r.phase(11.0) is RoundPhase.OPEN_REVEAL    # 2/3
        r.submit_reveal("n2", SCORES, nonces["n2"], now=11.0)
        # 3 verified -> CLOSED early.
        assert r.phase(11.0) is RoundPhase.CLOSED
        assert r.closed_by_quorum is True

    def test_unverified_reveals_do_not_count_toward_quorum(self):
        # A copier whose reveal hash-mismatches does NOT trigger the
        # quorum close — only VERIFIED reveals count.
        r = CommitRevealRound(
            epoch=25, node_ids=["honest1", "honest2", "copier"],
            commit_deadline=10.0, reveal_deadline=20.0,
            min_reveals=2,
        )
        h1_nonce = new_nonce()
        h2_nonce = new_nonce()
        cp_nonce = new_nonce()
        # honest1 and honest2 commit to the real scores; copier commits
        # to a placeholder.
        r.submit_commit("honest1", compute_commit_hash(SCORES, h1_nonce),
                        now=1.0)
        r.submit_commit("honest2", compute_commit_hash(SCORES, h2_nonce),
                        now=1.0)
        r.submit_commit(
            "copier",
            compute_commit_hash((_score("agentA", 0),), cp_nonce), now=1.0,
        )
        # honest1 + copier reveal. honest1 verifies, copier doesn't.
        r.submit_reveal("honest1", SCORES, h1_nonce, now=11.0)
        copier_rec = r.submit_reveal(
            "copier", SCORES, cp_nonce, now=11.0,
        )
        assert copier_rec.verified is False
        # Only 1 verified -> quorum (2) NOT reached -> still OPEN_REVEAL.
        assert r.phase(11.0) is RoundPhase.OPEN_REVEAL

    def test_late_but_in_window_reveals_are_still_accepted(self):
        # After early-close on quorum, a stragger that reveals BEFORE the
        # reveal-deadline is still accepted — they're recorded for the
        # audit trail and kept out of the non-revealers set.
        r = CommitRevealRound(
            epoch=25, node_ids=["n0", "n1", "n2"],
            commit_deadline=10.0, reveal_deadline=20.0,
            min_reveals=2,
        )
        nonces = {nid: new_nonce() for nid in ["n0", "n1", "n2"]}
        for nid in ["n0", "n1", "n2"]:
            r.submit_commit(nid, compute_commit_hash(SCORES, nonces[nid]),
                            now=1.0)
        r.submit_reveal("n0", SCORES, nonces["n0"], now=11.0)
        r.submit_reveal("n1", SCORES, nonces["n1"], now=11.0)
        # Round closed on quorum; n2 reveals at now=15 < deadline=20.
        rec = r.submit_reveal("n2", SCORES, nonces["n2"], now=15.0)
        assert rec.verified is True
        # n2 is NOT a non-revealer — they made it before the deadline.
        assert "n2" not in r.non_revealers(25.0)

    def test_min_reveals_none_preserves_legacy_wait_for_all(self):
        # Without min_reveals, the round waits for all committers or the
        # timeout — preserves legacy behaviour the round-state tests pin.
        r = CommitRevealRound(
            epoch=25, node_ids=["n0", "n1", "n2"],
            commit_deadline=10.0, reveal_deadline=20.0,
        )
        nonces = {nid: new_nonce() for nid in ["n0", "n1", "n2"]}
        for nid in ["n0", "n1", "n2"]:
            r.submit_commit(nid, compute_commit_hash(SCORES, nonces[nid]),
                            now=1.0)
        r.submit_reveal("n0", SCORES, nonces["n0"], now=11.0)
        r.submit_reveal("n1", SCORES, nonces["n1"], now=11.0)
        # 2 of 3 revealed, no min_reveals -> still OPEN_REVEAL.
        assert r.phase(11.0) is RoundPhase.OPEN_REVEAL
        assert r.closed_by_quorum is False


# =============================================================================
# Guarantee 3 — non_revealers tracking
# =============================================================================

class TestNonRevealers:

    def test_committed_but_silent_node_is_a_non_revealer(self):
        r = CommitRevealRound(
            epoch=25, node_ids=["n0", "n1", "n2"],
            commit_deadline=10.0, reveal_deadline=20.0,
        )
        nonces = {nid: new_nonce() for nid in ["n0", "n1", "n2"]}
        for nid in ["n0", "n1", "n2"]:
            r.submit_commit(nid, compute_commit_hash(SCORES, nonces[nid]),
                            now=1.0)
        r.submit_reveal("n0", SCORES, nonces["n0"], now=11.0)
        r.submit_reveal("n1", SCORES, nonces["n1"], now=11.0)
        # n2 committed but never revealed.
        assert r.non_revealers(21.0) == frozenset({"n2"})

    def test_uncommitted_node_is_not_a_non_revealer(self):
        # Non-revealers specifically tracks COMMITTED-but-silent. A node
        # that never committed is faulty, but not a non-revealer — its
        # strike track is different (it didn't even start the protocol).
        r = CommitRevealRound(
            epoch=25, node_ids=["n0", "n1", "n2"],
            commit_deadline=10.0, reveal_deadline=20.0,
        )
        nonces = {nid: new_nonce() for nid in ["n0", "n1"]}
        for nid in ["n0", "n1"]:
            r.submit_commit(nid, compute_commit_hash(SCORES, nonces[nid]),
                            now=1.0)
        for nid in ["n0", "n1"]:
            r.submit_reveal(nid, SCORES, nonces[nid], now=11.0)
        # n2 never committed — faulty yes, non-revealer no.
        assert "n2" in r.faulty_nodes(21.0)
        assert "n2" not in r.non_revealers(21.0)

    def test_failed_reveal_is_not_a_non_revealer(self):
        # A copier who submits a reveal that fails verification HAS
        # revealed (in the protocol sense — they sent the message). They
        # are excluded as Byzantine elsewhere, not as a non-revealer.
        r = CommitRevealRound(
            epoch=25, node_ids=["honest", "copier"],
            commit_deadline=10.0, reveal_deadline=20.0,
        )
        h_nonce = new_nonce()
        cp_nonce = new_nonce()
        r.submit_commit("honest", compute_commit_hash(SCORES, h_nonce),
                        now=1.0)
        r.submit_commit(
            "copier",
            compute_commit_hash((_score("agentA", 0),), cp_nonce), now=1.0,
        )
        r.submit_reveal("honest", SCORES, h_nonce, now=11.0)
        # Copier reveals something that fails verification.
        rec = r.submit_reveal("copier", SCORES, cp_nonce, now=11.0)
        assert rec.verified is False
        # The copier is faulty but DID reveal -> not a non-revealer.
        assert "copier" in r.faulty_nodes(21.0)
        assert "copier" not in r.non_revealers(21.0)


# =============================================================================
# Guarantee 3a — watchdog NON_REVEAL strikes
# =============================================================================

class TestWatchdogNonRevealStrikes:

    def test_one_non_reveal_epoch_is_one_strike(self):
        watchdog = ByzantineWatchdog()
        watchdog.record_non_revealers(
            42, [NonRevealFlag(node_id="lazy", epoch=42, reveal_deadline=20.0)],
        )
        assert watchdog.non_reveal_strikes_for("lazy") == 1
        assert watchdog.is_non_reveal_challenged("lazy") is False

    def test_threshold_epochs_of_non_reveal_files_a_challenge(self):
        filed = []
        watchdog = ByzantineWatchdog()
        for epoch in range(NON_REVEAL_STRIKE_THRESHOLD):
            watchdog.record_non_revealers(
                epoch,
                [NonRevealFlag(node_id="lazy", epoch=epoch,
                               reveal_deadline=20.0)],
                challenge_fn=filed.append,
            )
        assert watchdog.non_reveal_strikes_for("lazy") == \
            NON_REVEAL_STRIKE_THRESHOLD
        assert watchdog.is_non_reveal_challenged("lazy") is True
        assert len(filed) == 1
        challenge = filed[0]
        assert challenge.proof_type == PROOF_NON_REVEAL
        assert challenge.accused_node == "lazy"
        assert challenge.strikes == NON_REVEAL_STRIKE_THRESHOLD

    def test_below_threshold_does_not_challenge(self):
        filed = []
        watchdog = ByzantineWatchdog()
        watchdog.record_non_revealers(
            42, [NonRevealFlag(node_id="lazy", epoch=42, reveal_deadline=20.0)],
            challenge_fn=filed.append,
        )
        watchdog.record_non_revealers(
            43, [NonRevealFlag(node_id="lazy", epoch=43, reveal_deadline=20.0)],
            challenge_fn=filed.append,
        )
        assert watchdog.non_reveal_strikes_for("lazy") == 2
        assert filed == []

    def test_non_reveal_strikes_track_separately_from_byzantine_strikes(self):
        # A node can be both non-revealing AND Byzantine; the counters
        # are independent. A non-reveal strike does not bump the
        # Byzantine counter and vice versa.
        from oracle.cluster import EpochByzantineFlag
        watchdog = ByzantineWatchdog()
        watchdog.record_epoch(
            42,
            [EpochByzantineFlag("twofer", 42, "agentA", 100, 500)],
        )
        watchdog.record_non_revealers(
            42, [NonRevealFlag(node_id="twofer", epoch=42,
                               reveal_deadline=20.0)],
        )
        assert watchdog.strikes_for("twofer") == 1
        assert watchdog.non_reveal_strikes_for("twofer") == 1

    def test_double_record_of_same_epoch_is_idempotent(self):
        # Re-feeding the same epoch's non-reveal flags must NOT
        # double-strike — the dedup keys on (node, epoch).
        watchdog = ByzantineWatchdog()
        watchdog.record_non_revealers(
            42, [NonRevealFlag(node_id="lazy", epoch=42, reveal_deadline=20.0)],
        )
        watchdog.record_non_revealers(
            42, [NonRevealFlag(node_id="lazy", epoch=42, reveal_deadline=20.0)],
        )
        assert watchdog.non_reveal_strikes_for("lazy") == 1

    def test_mismatched_epoch_in_flag_is_rejected(self):
        watchdog = ByzantineWatchdog()
        with pytest.raises(ValueError, match="non-reveal flag epoch"):
            watchdog.record_non_revealers(
                42,
                [NonRevealFlag(node_id="lazy", epoch=43,
                               reveal_deadline=20.0)],
            )


# =============================================================================
# The attack scenario — exact audit reproduction
# =============================================================================

class TestAuditAttackScenario:
    """
    The audit's exact attack: a 5-node cluster, 1 node commits but never
    reveals. The cluster MUST still issue a certificate (no livelock) and
    MUST attribute a strike to the silent node so repeat offenders are
    eventually slashed.
    """

    def test_one_silent_node_does_not_stall_the_cluster(self):
        registry, nodes = _build_cluster(5)
        submit, calls = _submit()

        reports = simulate_commit_reveal_epoch(
            nodes, 25, [profile_adversarial()],
            submit_fn=submit, computed_at=REF_END,
            drop_reveal=["oracle-node-4"],         # the bribed node
        )
        # Every honest node still produced an aggregated result.
        for nid, report in reports.items():
            assert report.quorum_failure_count == 0
            assert report.submitted_count == 1
            # The silent node is surfaced as a non-revealer.
            assert "oracle-node-4" in report.non_revealers
            # The honest 4 are the verified set.
            assert set(report.verified_nodes) == {
                "oracle-node-0", "oracle-node-1",
                "oracle-node-2", "oracle-node-3",
            }

    def test_non_reveal_attack_accumulates_strikes_to_a_challenge(self):
        registry, nodes = _build_cluster(5)
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()
        filed = []

        # Three epochs of "commit but stay silent" -> non-reveal threshold.
        for epoch in range(25, 25 + NON_REVEAL_STRIKE_THRESHOLD):
            report = run_byzantine_epoch(
                nodes, epoch, [profile_adversarial()],
                submit_fn=submit, watchdog=watchdog,
                challenge_fn=filed.append, computed_at=REF_END,
                drop_reveal=["oracle-node-4"],
            )
            # Every epoch still produces a result — no livelock.
            assert report.quorum_failure_count == 0
            assert "oracle-node-4" in report.non_revealers
            _reset(nodes)

        # The silent node was challenged once with PROOF_NON_REVEAL.
        non_reveal_challenges = [c for c in filed
                                 if c.proof_type == PROOF_NON_REVEAL]
        assert len(non_reveal_challenges) == 1
        ch = non_reveal_challenges[0]
        assert ch.accused_node == "oracle-node-4"
        assert ch.strikes == NON_REVEAL_STRIKE_THRESHOLD
        assert watchdog.is_non_reveal_challenged("oracle-node-4") is True

    def test_single_silent_epoch_does_not_trigger_a_challenge(self):
        # A transient one-off silence (node crash, network blip) must NOT
        # slash. Only sustained behaviour reaches the threshold.
        registry, nodes = _build_cluster(5)
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()
        filed = []

        run_byzantine_epoch(
            nodes, 25, [profile_adversarial()],
            submit_fn=submit, watchdog=watchdog,
            challenge_fn=filed.append, computed_at=REF_END,
            drop_reveal=["oracle-node-4"],
        )
        assert watchdog.non_reveal_strikes_for("oracle-node-4") == 1
        assert filed == []

    def test_cluster_runner_reports_partial_reveal_close_on_silent_node(self):
        # When a node holds back its reveal, the OTHER nodes still close
        # the round on the partial-reveal quorum (NOT by waiting for the
        # reveal-deadline). The report flags this as closed_by_quorum.
        registry, nodes = _build_cluster(5)
        submit, _ = _submit()

        reports = simulate_commit_reveal_epoch(
            nodes, 25, [profile_adversarial()],
            submit_fn=submit, computed_at=REF_END,
            drop_reveal=["oracle-node-4"],
        )
        for nid, report in reports.items():
            assert report.closed_by_quorum is True


# =============================================================================
# Honest cluster regression
# =============================================================================

class TestHonestClusterUnaffected:

    def test_honest_5_node_cluster_files_no_non_reveal_challenges(self):
        registry, nodes = _build_cluster(5)
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()
        filed = []

        for epoch in range(25, 30):
            report = run_byzantine_epoch(
                nodes, epoch, [profile_adversarial(), profile_stable_a()],
                submit_fn=submit, watchdog=watchdog,
                challenge_fn=filed.append, computed_at=REF_END,
            )
            assert report.non_revealers == ()
            assert report.non_reveal_challenges == ()
            _reset(nodes)
        assert filed == []

    def test_quorum_matches_aggregator_quorum(self):
        # The partial-reveal quorum must match the median aggregator's
        # quorum — otherwise a round could close on partial reveals but
        # still fail aggregation for QuorumNotMet.
        for n in [1, 3, 5, 7]:
            assert quorum_for(n) == n // 2 + 1
