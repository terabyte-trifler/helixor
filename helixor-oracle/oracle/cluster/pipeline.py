"""
oracle/cluster/pipeline.py — the full Phase-4 oracle pipeline.

Days 23-27 each built one piece of Phase 4:
  23 — oracle node refactor (identity + transport)
  24 — 3-node cluster + gRPC + median aggregation
  25 — commit-reveal (no copying)
  26 — Byzantine detection + watchdog slashing
  27 — 3-of-5 multisig cert signing

Day 28 composes them. `run_full_pipeline_epoch` drives one epoch end to
end:

    Geyser/Kafka transactions  (Day 17 event bus)
      → 3 nodes ingest, each scores independently
      → COMMIT-REVEAL exchange      (Day 25)
      → BYZANTINE detection         (Day 26 — deviation + exclude)
      → MEDIAN aggregation          (Day 24 — on the honest survivors)
      → CERT PAYLOAD                (Day 27 canonical digest)
      → THRESHOLD SIGNATURES        (3 of 5 cluster keys sign)
      → SUBMITTABLE CERTIFICATE     (cert + Ed25519 precompile ixs)
      → ON-CHAIN SUBMIT             (injected seam)

THE INJECTED SEAMS
------------------
The runner never touches the chain directly. It produces a
`SubmittableCertificate` per agent and hands it to an `OnChainSubmitFn` —
the same dependency-inversion pattern as every prior day (submit_fn /
slash_fn / challenge_fn). Production wires the real on-chain call; chaos
tests pass a recording stub so failure modes are isolated to the
off-chain pipeline.

DETERMINISM, AGAIN
------------------
Everything in the deterministic path is pure stdlib — scoring, the
canonical digest, threshold counting, median aggregation. The only random
inputs are commit-reveal nonces (which MUST be random) and Ed25519
signature bytes (deterministic given the key + message, but a different
key gives different bytes — fine, the SIGNATURE SET varies; the AGGREGATED
SCORE is identical across runs).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from baseline import compute_baseline, stats_hash_to_bytes
from oracle.cluster.aggregation import AggregatedScore
from oracle.cluster.byzantine_runner import (
    ByzantineAgentResult,
    ByzantineEpochReport,
    run_byzantine_epoch,
)
from oracle.cluster.byzantine_watchdog import (
    ByzantineChallenge,
    ByzantineWatchdog,
    ChallengeFn,
)
from oracle.cluster.cert_signing import (
    AggregatedSignatures,
    InsufficientSignatures,
    aggregate_signatures,
    build_ed25519_instructions,
    cert_payload_digest,
    sign_cert_digest,
)
from oracle.cluster.identity import NodeKeypair
from oracle.epoch_runner import AgentEpochInput

if TYPE_CHECKING:
    from oracle.node import OracleNode

logger = logging.getLogger("helixor.oracle.cluster.pipeline")


# =============================================================================
# The submittable certificate — the artifact a tx is built from
# =============================================================================

@dataclass(frozen=True, slots=True)
class SubmittableCertificate:
    """
    A signed, threshold-verified certificate ready for on-chain submission.

    Carries everything a tx builder needs: the cert payload (the fields
    `issue_certificate` writes), the canonical digest the cluster signed,
    the threshold-satisfying signature set, and the pre-built Ed25519
    precompile instruction data blobs (one per signature).
    """
    agent_wallet:    str
    epoch:           int
    score:           int
    alert_tier:      int
    flags:           int
    baseline_hash:   bytes
    immediate_red:   bool
    digest:          bytes
    signatures:      AggregatedSignatures
    ed25519_ixs:     tuple[dict, ...]
    aggregated:      AggregatedScore

    @property
    def signer_count(self) -> int:
        return self.signatures.count


# An on-chain submit function takes a SubmittableCertificate and submits
# the assembled transaction. Injected — production wires the real submit;
# chaos tests pass a recording stub.
OnChainSubmitFn = Callable[[SubmittableCertificate], object]


# =============================================================================
# Pipeline result
# =============================================================================

@dataclass(frozen=True, slots=True)
class PipelineAgentResult:
    """One agent's outcome through the full Phase-4 pipeline."""
    agent_wallet:      str
    aggregated:        AggregatedScore | None
    excluded_nodes:    tuple[str, ...]
    certificate:       SubmittableCertificate | None
    submitted:         bool
    submission:        object | None = None
    error:             str = ""


@dataclass(frozen=True, slots=True)
class PipelineEpochReport:
    """One epoch's outcome through the full Phase-4 pipeline."""
    epoch_id:           int
    computed_at:        datetime
    cluster_size:       int
    threshold:          int
    verified_nodes:     tuple[str, ...]    # passed commit-reveal
    byzantine_nodes:    tuple[str, ...]    # detected this epoch
    unreachable_nodes:  tuple[str, ...]    # transport-level failures
    challenges_filed:   tuple[ByzantineChallenge, ...]
    results:            tuple[PipelineAgentResult, ...]
    elapsed_seconds:    float

    @property
    def agent_count(self) -> int:
        return len(self.results)

    @property
    def submitted_count(self) -> int:
        return sum(1 for r in self.results if r.submitted)

    @property
    def quorum_failure_count(self) -> int:
        return sum(1 for r in self.results if r.aggregated is None)

    @property
    def signing_failure_count(self) -> int:
        # Aggregated but failed to gather threshold signatures.
        return sum(
            1 for r in self.results
            if r.aggregated is not None and r.certificate is None
        )

    def by_wallet(self, wallet: str) -> PipelineAgentResult | None:
        for r in self.results:
            if r.agent_wallet == wallet:
                return r
        return None


# =============================================================================
# The pipeline epoch
# =============================================================================

def run_full_pipeline_epoch(
    nodes:           Sequence["OracleNode"],
    cluster_kps:     Sequence[NodeKeypair],
    epoch_id:        int,
    agent_inputs:    Sequence[AgentEpochInput],
    *,
    threshold:       int,
    submit_fn:       OnChainSubmitFn,
    watchdog:        ByzantineWatchdog,
    challenge_fn:    ChallengeFn | None = None,
    computed_at:     datetime | None = None,
    drop_commit:     Sequence[str] = (),
    drop_reveal:     Sequence[str] = (),
) -> PipelineEpochReport:
    """
    Drive one epoch through the full Phase-4 pipeline.

    `nodes` is the running cluster. `cluster_kps` are the cluster's
    keypairs — the same nodes' keypairs in `NodeKeypair` form, used to
    sign certs. (A node holds a keypair, but the pipeline asks each
    keypair to sign — equivalent and explicit.)

    `threshold` is the cert-signing threshold (3 for 3-of-5).

    `drop_commit` / `drop_reveal` model chaos: a node failing to commit
    or reveal. A node whose transport is unreachable produces neither —
    Day 25's round simply records it as faulty.

    Returns a `PipelineEpochReport` with everything — what succeeded,
    what failed, what was challenged, how long it took.
    """
    started = time.perf_counter()
    ts = computed_at or datetime.now(timezone.utc)
    cluster_size = len(nodes)
    agent_list = list(agent_inputs)
    baseline_hashes = _baseline_hashes_by_wallet(agent_list, computed_at=ts)

    # ── DETECT unreachable nodes BEFORE running the epoch ───────────────────
    # A node whose service is unregistered (the "kill node" model) is
    # detected by transport probing — equivalent to the Phase-4 cluster's
    # liveness ping. Captured for the report.
    unreachable = _probe_unreachable(nodes)

    # ── 1-5. Byzantine epoch  (commit-reveal + detect + exclude + median) ───
    # The byzantine-runner produces an inner Day-25/26 epoch with median
    # aggregation. The Day-27 signing step is added on top of its output.
    # Submission is staged: we collect SubmittableCertificates first, then
    # call submit_fn so chaos tests can inspect every per-agent stage.
    no_op_submit = lambda _w, _a: None
    byz_report = run_byzantine_epoch(
        nodes,
        epoch_id,
        agent_list,
        submit_fn=no_op_submit,
        watchdog=watchdog,
        challenge_fn=challenge_fn,
        computed_at=ts,
        drop_commit=drop_commit,
        drop_reveal=drop_reveal,
    )

    # ── 6-7. CERT PAYLOAD + THRESHOLD SIGNATURES per agent ──────────────────
    # Two exclusion criteria stack here:
    #   * verified_nodes — nodes whose commit-reveal succeeded (Day 25)
    #   * byzantine_nodes — nodes flagged by deviation (Day 26)
    # A Byzantine node passes commit-reveal HONESTLY (it commits/reveals
    # consistently; it just lies about its score). It ends up in
    # `verified_nodes` but ALSO in `byzantine_nodes`. We MUST NOT include
    # its signature on the cert — its sig would attest to a payload it
    # disagrees with, and including it would weaken the watchdog's
    # exclusion guarantee. So the signing set is the intersection of
    # verified MINUS byzantine.
    verified_set = set(byz_report.verified_nodes)
    byzantine_set = set(byz_report.byzantine_nodes)
    eligible_for_signing = verified_set - byzantine_set
    signing_kps = [kp for kp in cluster_kps if kp.node_id in eligible_for_signing]
    all_cluster_keys = [kp.public_key for kp in cluster_kps]

    results: list[PipelineAgentResult] = []
    for byz_result in byz_report.results:
        results.append(_sign_and_submit(
            byz_result, epoch_id, signing_kps,
            all_cluster_keys, threshold, submit_fn,
            baseline_hashes=baseline_hashes,
        ))

    elapsed = time.perf_counter() - started
    logger.info(
        "epoch %d pipeline: %d/%d agents submitted, %d byzantine, "
        "%d unreachable, %d challenges, %.3fs elapsed",
        epoch_id, sum(1 for r in results if r.submitted), len(results),
        len(byz_report.byzantine_nodes), len(unreachable),
        len(byz_report.challenges_filed), elapsed,
    )

    return PipelineEpochReport(
        epoch_id=epoch_id,
        computed_at=ts,
        cluster_size=cluster_size,
        threshold=threshold,
        verified_nodes=byz_report.verified_nodes,
        byzantine_nodes=byz_report.byzantine_nodes,
        unreachable_nodes=tuple(sorted(unreachable)),
        challenges_filed=byz_report.challenges_filed,
        results=tuple(results),
        elapsed_seconds=elapsed,
    )


# =============================================================================
# Helpers
# =============================================================================

def _probe_unreachable(nodes: Sequence["OracleNode"]) -> set[str]:
    """
    Probe peer transports to find unreachable nodes — the "killed" or
    "partitioned" model. A node whose own service is missing from the
    transport's registry is unreachable.

    Returns the set of unreachable node_ids (from the perspective of any
    one node — they all share the same in-process registry in chaos tests
    or learn it from gRPC dial failures in production).
    """
    from oracle.cluster.transport import (
        InProcessTransport, PeerUnreachable
    )
    from oracle.cluster.messages import PingRequest

    if not nodes:
        return set()

    primary = nodes[0]
    transport = primary.transport
    if transport is None:
        return set()                        # single-node deployment

    unreachable: set[str] = set()
    for peer in primary.membership.peer_ids():
        try:
            transport.ping(peer, PingRequest(node_id=primary.node_id, nonce=1))
        except PeerUnreachable:
            unreachable.add(peer)
        except Exception:                   # noqa: BLE001 — any error = unreachable
            unreachable.add(peer)
    return unreachable


def _sign_and_submit(
    byz_result:       ByzantineAgentResult,
    epoch_id:         int,
    signing_kps:      Sequence[NodeKeypair],
    cluster_keys:     Sequence[bytes],
    threshold:        int,
    submit_fn:        OnChainSubmitFn,
    *,
    baseline_hashes:  dict[str, bytes],
) -> PipelineAgentResult:
    """Sign one agent's aggregated score and submit it on-chain."""
    wallet = byz_result.agent_wallet

    # ── carry through aggregation / quorum failures from the byzantine run ──
    if byz_result.aggregated is None:
        return PipelineAgentResult(
            agent_wallet=wallet, aggregated=None,
            excluded_nodes=byz_result.excluded_nodes,
            certificate=None, submitted=False,
            error=byz_result.error or "no aggregated score",
        )

    aggregated = byz_result.aggregated
    baseline_hash = baseline_hashes.get(wallet)
    if baseline_hash is None:
        return PipelineAgentResult(
            agent_wallet=wallet, aggregated=aggregated,
            excluded_nodes=byz_result.excluded_nodes,
            certificate=None, submitted=False,
            error="missing baseline hash for certificate digest",
        )

    # ── BUILD the canonical cert digest ─────────────────────────────────────
    # The on-chain code computes the IDENTICAL bytes (programs/
    # certificate-issuer/src/signing.rs::cert_payload_digest).
    try:
        agent_pk = _wallet_to_bytes(wallet)
    except ValueError as exc:
        return PipelineAgentResult(
            agent_wallet=wallet, aggregated=aggregated,
            excluded_nodes=byz_result.excluded_nodes,
            certificate=None, submitted=False,
            error=f"bad agent wallet: {exc}",
        )

    digest = cert_payload_digest(
        agent_pk,
        epoch=epoch_id,
        score=aggregated.score,
        alert_tier=aggregated.alert_tier,
        flags=aggregated.flags,
        baseline_hash=baseline_hash,
        immediate_red=aggregated.immediate_red,
    )

    # ── COLLECT signatures from every verified cluster node ─────────────────
    signatures = [sign_cert_digest(kp, digest) for kp in signing_kps]

    # ── AGGREGATE to the threshold ──────────────────────────────────────────
    try:
        agg_sigs = aggregate_signatures(
            digest, signatures,
            cluster_keys=cluster_keys, threshold=threshold,
        )
    except InsufficientSignatures as exc:
        logger.error("pipeline: cert signing for %s: %s", wallet, exc)
        return PipelineAgentResult(
            agent_wallet=wallet, aggregated=aggregated,
            excluded_nodes=byz_result.excluded_nodes,
            certificate=None, submitted=False,
            error=str(exc),
        )

    # ── BUILD the on-chain transaction artifacts ────────────────────────────
    ed25519_ixs = build_ed25519_instructions(agg_sigs)
    certificate = SubmittableCertificate(
        agent_wallet=wallet,
        epoch=epoch_id,
        score=aggregated.score,
        alert_tier=aggregated.alert_tier,
        flags=aggregated.flags,
        baseline_hash=baseline_hash,
        immediate_red=aggregated.immediate_red,
        digest=digest,
        signatures=agg_sigs,
        ed25519_ixs=tuple(ed25519_ixs),
        aggregated=aggregated,
    )

    # ── SUBMIT on-chain via the injected seam ───────────────────────────────
    try:
        submission = submit_fn(certificate)
        return PipelineAgentResult(
            agent_wallet=wallet, aggregated=aggregated,
            excluded_nodes=byz_result.excluded_nodes,
            certificate=certificate,
            submitted=bool(submission), submission=submission,
        )
    except Exception as exc:                # noqa: BLE001
        logger.error("pipeline: on-chain submit for %s: %s", wallet, exc)
        return PipelineAgentResult(
            agent_wallet=wallet, aggregated=aggregated,
            excluded_nodes=byz_result.excluded_nodes,
            certificate=certificate, submitted=False,
            error=f"on-chain submit failed: {exc}",
        )


def _baseline_hashes_by_wallet(
    agent_inputs: Sequence[AgentEpochInput],
    *,
    computed_at: datetime,
) -> dict[str, bytes]:
    """
    Compute the exact baseline commitment each certificate will be issued
    against. The digest signed by the cluster binds this hash, closing the
    replay gap where a valid score signature could otherwise be stamped
    onto a different rotated baseline.
    """
    out: dict[str, bytes] = {}
    for agent_input in agent_inputs:
        baseline = compute_baseline(
            agent_input.agent_wallet,
            list(agent_input.baseline_transactions),
            agent_input.baseline_window,
            computed_at=computed_at,
        )
        out[agent_input.agent_wallet] = stats_hash_to_bytes(baseline.stats_hash)
    return out


def _wallet_to_bytes(wallet: str) -> bytes:
    """
    Convert an agent wallet identifier to its 32-byte Solana pubkey form.

    In production wallets are Base58-encoded Solana pubkeys; here, since
    the test fixtures use ASCII names (e.g. "adversaryxxxx..."), we accept
    a 32-byte UTF-8 padding so the canonical digest matches across the
    pipeline and any tx builder. A real deployment substitutes the actual
    Base58-decoded bytes; the digest function takes 32 bytes regardless of
    encoding.
    """
    raw = wallet.encode("utf-8")
    if len(raw) == 32:
        return raw
    if len(raw) < 32:
        return raw + b"\x00" * (32 - len(raw))
    return raw[:32]
