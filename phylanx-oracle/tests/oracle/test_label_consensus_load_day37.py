"""
tests/oracle/test_label_consensus_load_day37.py — 20-epoch load test
with the Day-37 label-consensus payload enabled.

Done-when: the cluster suite runs 20 epochs with labels enabled and:
    * byte-stable label bitmask across the run (each epoch's aggregate
      matches the deterministic input bitmask),
    * payload_hash consensus holds every epoch (no spurious dissenters,
      no degraded certs),
    * the watchdog records ZERO label-deviation strikes and ZERO
      payload-hash mismatch strikes across the run,
    * the per-epoch wall-clock cost is negligible (the load is small
      but the assertion guards against an accidental O(N^2) regression).

Determinism: the test feeds the SAME bitmask + payload hash from every
node on every agent — the aggregator must reach the SAME consensus on
every epoch (byte-stable).
"""

from __future__ import annotations

import time

from oracle.cluster.aggregation import (
    AggregatedScore,
    NodeScore,
    aggregate_scores,
)
from oracle.cluster.byzantine_watchdog import (
    ByzantineWatchdog,
    LabelDeviationFlag,
    PayloadHashMismatchFlag,
)
from oracle.cluster.messages import AgentScore


CLUSTER_SIZE = 3
AGENTS = ("agentA", "agentB", "agentC", "agentD", "agentE")
HONEST_BITMASK = (1 << 3) | (1 << 35) | (1 << 57)
HONEST_HASH = b"\xaa" * 32


def _node_score(wallet: str) -> AgentScore:
    return AgentScore(
        agent_wallet=wallet,
        score=800,
        alert_tier=1,
        flags=0,
        immediate_red=False,
        confidence=900,
        failure_mode_bitmask=HONEST_BITMASK,
        diagnosis_payload_hash=HONEST_HASH,
    )


def test_twenty_epoch_load_with_labels():
    watchdog = ByzantineWatchdog()
    aggregates: list[AggregatedScore] = []
    epoch_durations: list[float] = []

    for epoch in range(1, 21):
        t0 = time.perf_counter()
        per_epoch: list[AggregatedScore] = []
        for wallet in AGENTS:
            node_scores = [
                NodeScore(node_id=f"n{i}", score=_node_score(wallet))
                for i in range(1, CLUSTER_SIZE + 1)
            ]
            agg = aggregate_scores(
                wallet, node_scores, cluster_size=CLUSTER_SIZE,
            )
            per_epoch.append(agg)

        # Byte-stable label bitmask + payload hash every epoch.
        for agg in per_epoch:
            assert agg.label_bitmask == HONEST_BITMASK
            assert agg.diagnosis_payload_hash == HONEST_HASH
            assert set(agg.payload_hash_signers) == {"n1", "n2", "n3"}
            assert agg.payload_hash_dissenters == ()
            assert agg.has_payload_hash_consensus
            # Score-only median path still works.
            assert agg.score == 800
            assert agg.node_count == CLUSTER_SIZE

        # Feed the watchdog — no liars, no flags. Strike counts stay zero.
        watchdog.record_label_deviations(
            epoch, [], challenge_fn=lambda c: None,
        )
        watchdog.record_payload_hash_mismatches(
            epoch, [], challenge_fn=lambda c: None,
        )

        aggregates.extend(per_epoch)
        epoch_durations.append(time.perf_counter() - t0)

    # 20 epochs × 5 agents = 100 aggregates.
    assert len(aggregates) == 20 * len(AGENTS)

    # ZERO watchdog strikes across the whole run.
    for nid in ("n1", "n2", "n3"):
        assert watchdog.label_strikes_for(nid) == 0
        assert watchdog.payload_hash_mismatch_strikes_for(nid) == 0
        assert not watchdog.is_label_challenged(nid)
        assert not watchdog.is_payload_hash_mismatch_challenged(nid)

    # Performance guard — a single epoch of 5 agents over 3 nodes must
    # be well under 100ms. Wide margin so CI noise doesn't trip it; the
    # point is to catch an accidental O(N^2) regression in the new
    # u64-majority / hash-consensus code paths.
    max_epoch = max(epoch_durations)
    assert max_epoch < 0.1, f"slowest epoch was {max_epoch:.3f}s"


def test_byte_stable_aggregate_across_epochs():
    """Two epochs with identical inputs MUST produce byte-identical aggregates."""
    node_scores = [
        NodeScore(node_id=f"n{i}", score=_node_score("agentA"))
        for i in range(1, CLUSTER_SIZE + 1)
    ]
    a = aggregate_scores("agentA", node_scores, cluster_size=CLUSTER_SIZE)
    b = aggregate_scores("agentA", node_scores, cluster_size=CLUSTER_SIZE)
    assert a == b
    assert a.label_bitmask == b.label_bitmask
    assert a.diagnosis_payload_hash == b.diagnosis_payload_hash
    assert a.payload_hash_signers == b.payload_hash_signers


def test_persistent_liar_eventually_challenged_across_load_run():
    """
    A 20-epoch run with one node lying about LABEL BITS every epoch:
        - the cluster bitmask consensus is the honest one every epoch,
        - the liar accumulates label-strikes,
        - after LABEL_STRIKE_THRESHOLD (3) epochs the watchdog files
          its single PROOF_LABEL_DEVIATION challenge.
    """
    from oracle.cluster.byzantine_watchdog import LABEL_STRIKE_THRESHOLD

    LIAR = "liar"
    liar_bitmask = HONEST_BITMASK ^ ((1 << 17) | (1 << 33) | (1 << 41) | (1 << 60))
    filings: list = []

    watchdog = ByzantineWatchdog()
    for epoch in range(1, 21):
        # Build the per-agent aggregates (just one agent for brevity).
        node_scores = [
            NodeScore(node_id="h1", score=_node_score("agentA")),
            NodeScore(node_id="h2", score=_node_score("agentA")),
            NodeScore(
                node_id=LIAR,
                score=AgentScore(
                    agent_wallet="agentA",
                    score=800, alert_tier=1, flags=0,
                    immediate_red=False, confidence=900,
                    failure_mode_bitmask=liar_bitmask,
                    diagnosis_payload_hash=HONEST_HASH,
                ),
            ),
        ]
        agg = aggregate_scores("agentA", node_scores, cluster_size=CLUSTER_SIZE)
        assert agg.label_bitmask == HONEST_BITMASK
        # Compute the liar's Hamming distance and feed the watchdog.
        hamming = bin(liar_bitmask ^ agg.label_bitmask).count("1")
        watchdog.record_label_deviations(
            epoch,
            [LabelDeviationFlag(
                node_id=LIAR,
                epoch=epoch,
                subject_agent="agentA",
                accused_bitmask=liar_bitmask,
                consensus_bitmask=agg.label_bitmask,
                hamming_distance=hamming,
            )],
            challenge_fn=filings.append,
        )

    assert watchdog.label_strikes_for(LIAR) == 20
    # EXACTLY ONE challenge filed across the whole run — first time the
    # liar crossed the strike threshold.
    assert len(filings) == 1
    assert filings[0].strikes == LABEL_STRIKE_THRESHOLD
