"""
tests/oracle/test_aw01_byzantine_runner.py — AW-01, layer 4.

Layers 1-3 (input_commitment.py, commit-reveal binding, cert-payload binding)
proved the per-node and on-chain pieces. This layer pins the CROSS-NODE
AGREEMENT step the aggregator performs in `run_byzantine_epoch`:

  - When every node computes the SAME input commitment, the cluster majority
    flows through to `ByzantineAgentResult.input_commitment` and
    FlagBit.INPUT_DIVERGENCE is NOT set.

  - When a poisoned-pipeline node computes a different commitment (modelled
    via `input_commitment_overrides`), the dissenting node is named in
    `input_divergent_nodes` and the FlagBit.INPUT_DIVERGENCE bit is OR'd
    into the aggregated score's flags.

  - When NO majority can be assembled (the cluster splits below the AW-01
    quorum), `input_commitment is None` — the cert path will refuse to
    issue a cert. This is the architectural fix in action: no input
    majority -> no certificate.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from detection.types import FlagBit
from oracle.cluster import (
    ByzantineWatchdog,
    InProcessRegistry,
    InProcessTransport,
    NodeKeypair,
    run_byzantine_epoch,
)
from oracle.cluster.input_commitment import (
    COMMITMENT_BYTES,
    SlotAnchor,
    compute_input_commitment,
)
from oracle.node import ClusterMembership, OracleNode
from tests.oracle.agent_profiles import profile_stable_a
from baseline import compute_baseline, stats_hash_to_bytes


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


# ── infra ──────────────────────────────────────────────────────────────────────

def _submit():
    calls: list[dict] = []

    def _s(wallet, aggregated):
        calls.append({"wallet": wallet, "score": aggregated.score,
                      "flags": int(aggregated.flags)})
        return calls[-1]

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


def _honest_commitment(agent_input) -> bytes:
    """Compute the honest cluster-wide commitment for a given agent input.

    The runner defaults `slot_anchor` to `SlotAnchor.zero()` when no anchor
    is wired through (`run_byzantine_epoch(slot_anchor=None)`), so this
    test helper mirrors that — using a SlotAnchor.zero() here keeps the
    expected commitment byte-identical to the per-node commitment the
    runner computes inside the cluster.
    """
    baseline = compute_baseline(
        agent_input.agent_wallet,
        list(agent_input.baseline_transactions),
        agent_input.baseline_window,
        computed_at=REF_END,
    )
    return compute_input_commitment(
        agent_wallet=agent_input.agent_wallet,
        baseline_window=agent_input.baseline_window,
        current_window=agent_input.current_window,
        baseline_transactions=agent_input.baseline_transactions,
        current_transactions=agent_input.current_transactions,
        baseline_hash=stats_hash_to_bytes(baseline.stats_hash),
        slot_anchor=SlotAnchor.zero(),
    )


# =============================================================================
# Honest cluster — every node agrees on the input commitment
# =============================================================================

class TestHonestClusterAgreesOnInputCommitment:

    def test_majority_commitment_is_surfaced(self):
        _, nodes = _build_cluster(3)
        agent = profile_stable_a()
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()

        report = run_byzantine_epoch(
            nodes, 26, [agent],
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
        )
        result = report.by_wallet(agent.agent_wallet)
        assert result is not None
        assert result.input_commitment is not None
        assert len(result.input_commitment) == COMMITMENT_BYTES
        assert result.input_commitment == _honest_commitment(agent)
        assert result.input_divergent_nodes == ()

    def test_input_divergence_flag_is_not_set(self):
        _, nodes = _build_cluster(3)
        agent = profile_stable_a()
        submit, calls = _submit()
        watchdog = ByzantineWatchdog()

        run_byzantine_epoch(
            nodes, 26, [agent],
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
        )
        # Submitted -> the aggregated score reached the submit_fn.
        assert len(calls) == 1
        assert calls[0]["flags"] & int(FlagBit.INPUT_DIVERGENCE) == 0


# =============================================================================
# One poisoned node — divergence detected, flag set, majority still wins
# =============================================================================

class TestPoisonedNodeIsDetected:

    def test_dissenting_node_is_named(self):
        """A single node with a different input_commitment is surfaced."""
        _, nodes = _build_cluster(3)
        agent = profile_stable_a()
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()

        poisoned = b"\xde" * COMMITMENT_BYTES
        report = run_byzantine_epoch(
            nodes, 26, [agent],
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
            input_commitment_overrides={
                ("oracle-node-2", agent.agent_wallet): poisoned,
            },
        )
        result = report.by_wallet(agent.agent_wallet)
        assert result is not None
        assert "oracle-node-2" in result.input_divergent_nodes

    def test_majority_commitment_still_wins(self):
        """2-of-3 honest nodes outvote 1 poisoned node — majority emerges."""
        _, nodes = _build_cluster(3)
        agent = profile_stable_a()
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()

        report = run_byzantine_epoch(
            nodes, 26, [agent],
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
            input_commitment_overrides={
                ("oracle-node-1", agent.agent_wallet): b"\xaa" * COMMITMENT_BYTES,
            },
        )
        result = report.by_wallet(agent.agent_wallet)
        assert result is not None
        assert result.input_commitment == _honest_commitment(agent)

    def test_input_divergence_flag_is_set_on_aggregated_score(self):
        """The watchdog needs an on-chain flag to attribute strikes."""
        _, nodes = _build_cluster(3)
        agent = profile_stable_a()
        submit, calls = _submit()
        watchdog = ByzantineWatchdog()

        run_byzantine_epoch(
            nodes, 26, [agent],
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
            input_commitment_overrides={
                ("oracle-node-1", agent.agent_wallet): b"\x11" * COMMITMENT_BYTES,
            },
        )
        assert len(calls) == 1
        assert calls[0]["flags"] & int(FlagBit.INPUT_DIVERGENCE) != 0


# =============================================================================
# No quorum — cluster splits, no commitment, FlagBit set, cert path refuses
# =============================================================================

class TestNoQuorumNoCommitment:

    def test_split_cluster_yields_no_majority(self):
        """3 nodes, 3 different commitments — no AW-01 quorum is reached."""
        _, nodes = _build_cluster(3)
        agent = profile_stable_a()
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()

        report = run_byzantine_epoch(
            nodes, 26, [agent],
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
            input_commitment_overrides={
                ("oracle-node-0", agent.agent_wallet): b"\x01" * COMMITMENT_BYTES,
                ("oracle-node-1", agent.agent_wallet): b"\x02" * COMMITMENT_BYTES,
                ("oracle-node-2", agent.agent_wallet): b"\x03" * COMMITMENT_BYTES,
            },
        )
        result = report.by_wallet(agent.agent_wallet)
        assert result is not None
        # AW-01 architectural gate: NO majority -> NO commitment.
        assert result.input_commitment is None

    def test_split_cluster_sets_divergence_flag(self):
        _, nodes = _build_cluster(3)
        agent = profile_stable_a()
        submit, calls = _submit()
        watchdog = ByzantineWatchdog()

        run_byzantine_epoch(
            nodes, 26, [agent],
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
            input_commitment_overrides={
                ("oracle-node-0", agent.agent_wallet): b"\x01" * COMMITMENT_BYTES,
                ("oracle-node-1", agent.agent_wallet): b"\x02" * COMMITMENT_BYTES,
                ("oracle-node-2", agent.agent_wallet): b"\x03" * COMMITMENT_BYTES,
            },
        )
        assert len(calls) == 1
        assert calls[0]["flags"] & int(FlagBit.INPUT_DIVERGENCE) != 0


# =============================================================================
# Override-shape validation — wrong length is rejected loudly
# =============================================================================

class TestOverrideShape:

    def test_wrong_length_override_is_rejected(self):
        _, nodes = _build_cluster(3)
        agent = profile_stable_a()
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()

        with pytest.raises(ValueError, match="must be"):
            run_byzantine_epoch(
                nodes, 26, [agent],
                submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
                input_commitment_overrides={
                    ("oracle-node-0", agent.agent_wallet): b"\x01" * 7,
                },
            )


# =============================================================================
# Custom quorum threshold
# =============================================================================

class TestCustomQuorumThreshold:

    def test_explicit_unanimous_quorum_fails_with_one_dissenter(self):
        """A unanimous quorum (=N) is broken by a single dissenter."""
        _, nodes = _build_cluster(3)
        agent = profile_stable_a()
        submit, _ = _submit()
        watchdog = ByzantineWatchdog()

        report = run_byzantine_epoch(
            nodes, 26, [agent],
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
            input_commitment_quorum=3,
            input_commitment_overrides={
                ("oracle-node-2", agent.agent_wallet): b"\xde" * COMMITMENT_BYTES,
            },
        )
        result = report.by_wallet(agent.agent_wallet)
        assert result is not None
        assert result.input_commitment is None
        assert "oracle-node-2" in result.input_divergent_nodes


# =============================================================================
# Determinism — AW-01 is a pure function of its inputs
# =============================================================================

class TestDeterminism:

    def test_commitment_outputs_are_deterministic_across_runs(self):
        def _run():
            _, nodes = _build_cluster(3)
            agent = profile_stable_a()
            submit, _ = _submit()
            watchdog = ByzantineWatchdog()
            report = run_byzantine_epoch(
                nodes, 26, [agent],
                submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
                input_commitment_overrides={
                    ("oracle-node-1", agent.agent_wallet): b"\xee" * COMMITMENT_BYTES,
                },
            )
            result = report.by_wallet(agent.agent_wallet)
            return (result.input_commitment, result.input_divergent_nodes)

        first = _run()
        for _ in range(3):
            assert _run() == first
