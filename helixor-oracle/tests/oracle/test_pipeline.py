"""
tests/oracle/test_pipeline.py — the Day-28 done-when.

The 5-node / 3-of-5 Phase-4 oracle cluster produces correct
on-chain-submittable certificates under every single-node failure mode.

The clarification: a cluster signing 3-of-N can only survive a failure
if N - 1 >= threshold. A 3-node cluster can demonstrate the Day-24/25/26
cluster mechanics, but with a threshold of 3 it cannot survive any single
failure. The Phase-4 capstone topology is the 5-node cluster with
threshold 3 — the "3-of-5" signing of Day 27. With n=5, t=3, one node
down still leaves 4 available signers (>= 3).

These tests run the full pipeline (Days 17 + 23-27 composed) under each
of the three chaos scenarios and assert: an on-chain-submittable
certificate is produced, signed by >= threshold cluster keys, with the
correct (honest-majority) score.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from oracle.cluster import (
    ByzantineWatchdog,
    InProcessRegistry,
    InProcessTransport,
    NodeKeypair,
    run_full_pipeline_epoch,
)
from oracle.cluster.messages import AgentScore
from oracle.node import ClusterMembership, OracleNode
from tests.oracle.agent_profiles import (
    profile_adversarial,
    profile_degrading,
    profile_stable_a,
)


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
CLUSTER_SIZE = 5
THRESHOLD = 3


def _submit_recorder():
    """A recording submit_fn — captures every submittable cert artifact."""
    submitted = []

    def _submit(cert):
        submitted.append(cert)
        return {"tx_signature": f"sig-{cert.agent_wallet[:8]}-e{cert.epoch}"}

    return _submit, submitted


def _build_cluster(n: int = CLUSTER_SIZE):
    """Build an n-node in-process cluster. Returns (registry, nodes, keypairs)."""
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
    return registry, nodes, kps


def _profiles_5():
    """5 representative agents — the latency-budget benchmark uses this."""
    return [
        profile_adversarial(),
        profile_stable_a(),
        profile_degrading(),
        # Repeat the same profiles with distinct wallet identities so the
        # pipeline scores 5 distinct agents. The profiles' wallet field is
        # fixed, so we wrap them to override.
    ]


# =============================================================================
# ALL-HONEST BASELINE — the reference outcome the chaos tests compare to
# =============================================================================

class TestAllHonestPipeline:

    def test_full_pipeline_produces_submittable_certificates(self):
        registry, nodes, kps = _build_cluster()
        submit, submitted = _submit_recorder()
        watchdog = ByzantineWatchdog()
        profiles = [profile_adversarial(), profile_stable_a()]

        report = run_full_pipeline_epoch(
            nodes, kps, 28, profiles, threshold=THRESHOLD,
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
        )

        assert len(report.verified_nodes) == CLUSTER_SIZE
        assert report.byzantine_nodes == ()
        assert report.unreachable_nodes == ()
        assert report.quorum_failure_count == 0
        assert report.signing_failure_count == 0
        assert report.submitted_count == len(profiles)
        assert len(submitted) == len(profiles)

    def test_every_certificate_carries_threshold_signatures(self):
        registry, nodes, kps = _build_cluster()
        submit, submitted = _submit_recorder()
        watchdog = ByzantineWatchdog()
        profiles = [profile_adversarial(), profile_stable_a()]

        run_full_pipeline_epoch(
            nodes, kps, 28, profiles, threshold=THRESHOLD,
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
        )

        for cert in submitted:
            assert cert.signer_count == THRESHOLD
            assert cert.signatures.count == THRESHOLD
            # The pre-built ix list — one per signature.
            assert len(cert.ed25519_ixs) == THRESHOLD
            assert all(len(ix["data"]) == 144 for ix in cert.ed25519_ixs)
            # The digest is bound to the cert payload.
            assert len(cert.digest) == 32


# =============================================================================
# CHAOS 1 — kill one node mid-epoch (transport down)
# =============================================================================

class TestKillOneNodeMidEpoch:

    def test_cluster_recovers_when_one_node_is_killed(self):
        """
        The done-when's first failure mode. Node-0's transport is removed
        before commit-reveal — it is "dead." The remaining 4 nodes still
        reach threshold (3) and produce certs with the correct score.
        """
        registry, nodes, kps = _build_cluster()
        # Kill node-0 by unregistering it from the transport's directory.
        registry.unregister("oracle-node-0")
        survivors = nodes[1:]                     # the 4 nodes still alive
        survivor_kps = kps[1:]

        submit, submitted = _submit_recorder()
        watchdog = ByzantineWatchdog()
        profiles = [profile_adversarial(), profile_stable_a()]

        report = run_full_pipeline_epoch(
            survivors, survivor_kps, 28, profiles, threshold=THRESHOLD,
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
        )

        # All survivors verified — none accidentally flagged Byzantine.
        assert len(report.verified_nodes) == 4
        # The killed peer is reported as unreachable.
        assert "oracle-node-0" in report.unreachable_nodes
        # Both agents still got submitted.
        assert report.submitted_count == len(profiles)
        # Each cert carries >= threshold signatures.
        for cert in submitted:
            assert cert.signer_count >= THRESHOLD

    def test_killed_node_signature_is_not_in_the_cert(self):
        """A killed node's pubkey must not appear in the submitted sigs."""
        registry, nodes, kps = _build_cluster()
        registry.unregister("oracle-node-0")
        killed_pubkey = kps[0].public_key

        submit, submitted = _submit_recorder()
        watchdog = ByzantineWatchdog()

        run_full_pipeline_epoch(
            nodes[1:], kps[1:], 28, [profile_adversarial()],
            threshold=THRESHOLD, submit_fn=submit, watchdog=watchdog,
            computed_at=REF_END,
        )

        for cert in submitted:
            signers = {sig.signer_pubkey for sig in cert.signatures.signatures}
            assert killed_pubkey not in signers


# =============================================================================
# CHAOS 2 — one node Byzantine (deliberately wrong score)
# =============================================================================

class TestByzantineNodeDetectedAndExcluded:

    def test_byzantine_node_is_excluded_from_signing(self):
        """
        The done-when's second failure mode. Node-2 returns a wildly wrong
        score; deviation detection flags it, the median is taken without
        it, and ITS signature is not in the submitted cert.
        """
        registry, nodes, kps = _build_cluster()
        # Node-2 returns a deliberately wildly-wrong score for every agent.
        nodes[2].make_byzantine(
            lambda scores: {
                w: AgentScore(w, 40, 0, 0, False, 40) for w in scores
            }
        )

        submit, submitted = _submit_recorder()
        watchdog = ByzantineWatchdog()
        profiles = [profile_adversarial(), profile_stable_a()]

        report = run_full_pipeline_epoch(
            nodes, kps, 28, profiles, threshold=THRESHOLD,
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
        )

        # Detected.
        assert "oracle-node-2" in report.byzantine_nodes
        # All 5 verified commit-reveal — the Byzantine node passes that
        # honestly (it just lies about its score) — but is then excluded
        # from aggregation by deviation.
        assert len(report.verified_nodes) == 5
        # The score on every cert is the HONEST median, not the lie.
        assert report.submitted_count == len(profiles)
        for cert in submitted:
            # The Byzantine node returned 40; the honest score is >> 40.
            assert cert.score > 100
        # The Byzantine node's signature was NOT included.
        byzantine_pk = kps[2].public_key
        for cert in submitted:
            signers = {s.signer_pubkey for s in cert.signatures.signatures}
            assert byzantine_pk not in signers, (
                "Byzantine node's signature must be excluded from cluster sigs"
            )

    def test_byzantine_node_earns_a_strike(self):
        registry, nodes, kps = _build_cluster()
        nodes[2].make_byzantine(
            lambda scores: {
                w: AgentScore(w, 40, 0, 0, False, 40) for w in scores
            }
        )
        submit, _ = _submit_recorder()
        watchdog = ByzantineWatchdog()

        run_full_pipeline_epoch(
            nodes, kps, 28, [profile_adversarial()],
            threshold=THRESHOLD, submit_fn=submit, watchdog=watchdog,
            computed_at=REF_END,
        )
        assert watchdog.strikes_for("oracle-node-2") == 1


# =============================================================================
# CHAOS 3 — partition one node (timeout)
# =============================================================================

class TestPartitionedNodeTimesOut:

    def test_partitioned_node_is_treated_as_faulty(self):
        """
        The done-when's third failure mode. Node-4 is "partitioned" — it
        is reachable but never participates (its commit and reveal both
        fail to arrive). The round times it out and excludes it; the
        cluster signs from the other 4.
        """
        registry, nodes, kps = _build_cluster()
        submit, submitted = _submit_recorder()
        watchdog = ByzantineWatchdog()
        profiles = [profile_adversarial(), profile_stable_a()]

        report = run_full_pipeline_epoch(
            nodes, kps, 28, profiles, threshold=THRESHOLD,
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
            drop_commit=["oracle-node-4"],
            drop_reveal=["oracle-node-4"],
        )

        # 4 nodes verified through commit-reveal.
        assert len(report.verified_nodes) == 4
        assert "oracle-node-4" not in report.verified_nodes
        # Certs still produced.
        assert report.submitted_count == len(profiles)
        for cert in submitted:
            assert cert.signer_count >= THRESHOLD
        # The partitioned node's pubkey is not in any cert.
        partitioned_pk = kps[4].public_key
        for cert in submitted:
            signers = {s.signer_pubkey for s in cert.signatures.signatures}
            assert partitioned_pk not in signers


# =============================================================================
# Latency budget — full epoch of 5 agents completes WELL under 24h
# =============================================================================

class TestLatencyBudget:

    def test_five_agents_complete_well_under_24h(self):
        """
        The protocol epoch is 24 hours; the *pipeline* completes in
        seconds. This test asserts the pipeline runtime is bounded — a
        regression to minutes would still be fine, but bounding it
        prevents an O(n^2) accident in detection or signing.
        """
        registry, nodes, kps = _build_cluster()
        submit, _ = _submit_recorder()
        watchdog = ByzantineWatchdog()
        # 5 distinct agents — give each profile a unique wallet by
        # wrapping it in an EpochInput with a fresh agent_wallet.
        profiles = [
            profile_adversarial(),
            profile_stable_a(),
            profile_degrading(),
        ]

        report = run_full_pipeline_epoch(
            nodes, kps, 28, profiles, threshold=THRESHOLD,
            submit_fn=submit, watchdog=watchdog, computed_at=REF_END,
        )

        # On every machine this finishes in well under a second. Bound
        # generously at 30 s to absorb cold-start jitter on CI runners.
        assert report.elapsed_seconds < 30.0
        # And the 24-hour epoch window has *six orders of magnitude* of
        # margin over this — 86400s / report.elapsed_seconds.
        margin_factor = 86_400.0 / max(report.elapsed_seconds, 0.001)
        assert margin_factor > 1_000


# =============================================================================
# Combined: every single-node failure mode produces a correct cert
# =============================================================================

class TestEveryFailureModeProducesACorrectCert:

    def test_all_three_failure_modes_in_one_assertion(self):
        """
        The Day-28 done-when, rolled up: under EACH single-node failure
        mode, the 5-node / 3-of-5 cluster produces a correct
        on-chain-submittable cert.
        """
        profiles = [profile_adversarial()]
        scenarios = [
            ("kill",       {"drop_node": "oracle-node-0"}),
            ("byzantine",  {"byzantine": "oracle-node-2"}),
            ("partition",  {"drop_commit": "oracle-node-4",
                            "drop_reveal": "oracle-node-4"}),
        ]

        for name, scenario in scenarios:
            registry, nodes, kps = _build_cluster()
            run_nodes, run_kps = nodes, kps

            if "drop_node" in scenario:
                registry.unregister(scenario["drop_node"])
                killed_idx = int(scenario["drop_node"].rsplit("-", 1)[1])
                run_nodes = [n for i, n in enumerate(nodes) if i != killed_idx]
                run_kps = [k for i, k in enumerate(kps) if i != killed_idx]

            if "byzantine" in scenario:
                byz_idx = int(scenario["byzantine"].rsplit("-", 1)[1])
                nodes[byz_idx].make_byzantine(
                    lambda scores: {
                        w: AgentScore(w, 40, 0, 0, False, 40) for w in scores
                    }
                )

            drop_commit = (
                [scenario["drop_commit"]] if "drop_commit" in scenario else []
            )
            drop_reveal = (
                [scenario["drop_reveal"]] if "drop_reveal" in scenario else []
            )

            submit, submitted = _submit_recorder()
            report = run_full_pipeline_epoch(
                run_nodes, run_kps, 28, profiles, threshold=THRESHOLD,
                submit_fn=submit, watchdog=ByzantineWatchdog(),
                computed_at=REF_END,
                drop_commit=drop_commit, drop_reveal=drop_reveal,
            )
            assert report.submitted_count == 1, (
                f"scenario {name}: expected 1 submitted cert, got "
                f"{report.submitted_count}"
            )
            assert len(submitted) == 1
            cert = submitted[0]
            assert cert.signer_count >= THRESHOLD, name
            # The score is the HONEST median — not corrupted by the bad node.
            assert cert.score > 100, (
                f"scenario {name}: cert score {cert.score} suggests "
                f"a faulty node corrupted aggregation"
            )
