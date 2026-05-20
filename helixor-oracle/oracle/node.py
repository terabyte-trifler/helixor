"""
oracle/node.py — the Helixor oracle node.

Phase 4 turns one trusted oracle into a 3-5 node Byzantine-fault-tolerant
cluster. Day 23 is the refactor that makes that possible: it wraps the
existing epoch pipeline in an `OracleNode` — a thing with an IDENTITY, a
cluster TRANSPORT, and the ability both to RUN the detection pipeline and
to SERVE its peers' RPCs.

THE DESIGN GOAL — ZERO BEHAVIOUR CHANGE FOR A SINGLE NODE
---------------------------------------------------------
The whole point of Day 23: a single node must keep working EXACTLY as
before. So `OracleNode` is built so a 1-node cluster is the degenerate
case of the N-node design — not a special path. A lone node:
  - runs the identical `run_epoch` pipeline (Day 14/22),
  - with `SingleNodeConsensus` (Day 22's policy — one node, its verdict
    stands),
  - and `run_epoch` produces a byte-identical EpochReport to the
    pre-Day-23 code.
`OracleNode.run_epoch` is a thin, transparent wrapper — it adds identity
and a cluster seam, it does NOT change scoring. The Day-23 done-when test
proves the report is identical with and without the node wrapper.

WHAT DAY 23 BUILDS vs WHAT COMES LATER
--------------------------------------
Day 23: the node STRUCTURE — identity, transport, a serving surface
(`Ping` works end to end), and the single-node run path.
Days 24-28: the commit-reveal consensus that flows between nodes over the
`Commit` / `Reveal` RPCs. The node's `ClusterService` already has the
commit/reveal handler slots; Day 23 leaves them as honest
"not yet implemented" stubs rather than faking a protocol that is not
built.

DETERMINISM
-----------
The node's scoring path is `run_epoch` — pure, deterministic, stdlib-only.
Identity (signing) and transport (gRPC) are EDGE concerns and never touch
the scoring path, so every node in the cluster scores identically.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone

from detection import DetectorRegistry
from oracle.cluster.identity import NodeIdentity, NodeKeypair
from oracle.cluster.commit_reveal import compute_commit_hash, new_nonce
from oracle.cluster.commit_reveal_round import (
    CommitRejected,
    CommitRevealRound,
    RevealRejected,
)
from oracle.cluster.messages import (
    AgentScore,
    CommitRequest,
    CommitResponse,
    GetScoresRequest,
    GetScoresResponse,
    PingRequest,
    PingResponse,
    RevealRequest,
    RevealResponse,
)
from oracle.cluster.transport import ClusterTransport
from oracle.epoch_runner import (
    AgentEpochInput,
    EpochReport,
    SlashFn,
    SubmitFn,
    run_epoch,
    score_agent,
)
from slashing import ConsensusPolicy, SingleNodeConsensus

logger = logging.getLogger("helixor.oracle.node")


# =============================================================================
# ClusterMembership — the node's view of its cluster
# =============================================================================

@dataclass(frozen=True, slots=True)
class ClusterMembership:
    """
    A node's view of the cluster it belongs to: its own identity plus its
    peers'. Mirrors the on-chain `OracleConfig.oracle_keys`.

    A 1-node cluster has `peers == ()` — the explicit, supported single-node
    deployment.
    """
    self_identity: NodeIdentity
    peers:         tuple[NodeIdentity, ...] = ()

    def __post_init__(self) -> None:
        ids = [self.self_identity.node_id, *(p.node_id for p in self.peers)]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate node_id in cluster membership")
        keys = [self.self_identity.public_key,
                *(p.public_key for p in self.peers)]
        if len({bytes(k) for k in keys}) != len(keys):
            raise ValueError("duplicate public_key in cluster membership")

    @property
    def size(self) -> int:
        """Total cluster size including this node."""
        return 1 + len(self.peers)

    @property
    def is_single_node(self) -> bool:
        return len(self.peers) == 0

    @property
    def consensus_threshold(self) -> int:
        """Strict-majority BFT threshold: floor(n/2) + 1."""
        return self.size // 2 + 1

    def peer_ids(self) -> tuple[str, ...]:
        return tuple(p.node_id for p in self.peers)


# =============================================================================
# OracleNode
# =============================================================================

class OracleNode:
    """
    One oracle node — cluster-ready.

    A node owns:
      - a `NodeKeypair` (its identity + signing key),
      - a `ClusterMembership` (itself + its peers),
      - optionally a `ClusterTransport` (to reach peers; None for a lone
        single node that talks to nobody).

    It can:
      - RUN an epoch — `run_epoch` — the full detection pipeline,
      - SERVE its peers — it implements the `ClusterService` handlers
        (`ping` works; `commit`/`reveal` are Days-24-28 stubs).

    Construct via `OracleNode.single` for the standalone deployment, or with
    a full membership + transport for a cluster member.
    """

    def __init__(
        self,
        keypair:    NodeKeypair,
        membership: ClusterMembership,
        *,
        transport:  ClusterTransport | None = None,
        registry:   DetectorRegistry | None = None,
    ) -> None:
        if keypair.node_id != membership.self_identity.node_id:
            raise ValueError(
                f"keypair node_id {keypair.node_id!r} does not match "
                f"membership self id {membership.self_identity.node_id!r}"
            )
        if keypair.public_key != membership.self_identity.public_key:
            raise ValueError("keypair public key does not match identity")
        self._keypair = keypair
        self._membership = membership
        self._transport = transport
        self._registry = registry
        # The node's view of the current epoch — advanced by the operator.
        self._current_epoch = 1
        # Day 24: this node's own scores, per epoch. Populated by
        # `score_epoch`; served to peers via the `get_scores` handler so
        # the cluster can compute the median. epoch -> {wallet -> AgentScore}.
        self._epoch_scores: dict[int, dict[str, AgentScore]] = {}
        # Day 25: the commit-reveal round per epoch, and this node's own
        # secret nonce per epoch. The round tracks every node's commit and
        # reveal; the nonce is what this node folds into its own commit and
        # discloses only at reveal time.
        self._rounds: dict[int, "CommitRevealRound"] = {}
        self._epoch_nonces: dict[int, bytes] = {}
        # Day 25: the node's logical clock for commit-reveal. The epoch
        # orchestrator advances it as the protocol moves through phases;
        # the commit / reveal handlers stamp peer submissions with it. A
        # logical clock (not the wall clock) keeps the protocol fully
        # deterministic and testable.
        self._round_clock: float = 0.0
        # Day 26: an optional score-corruptor — models a BYZANTINE node.
        # A real Byzantine node's malice happens inside its own process: it
        # runs the engine (or not) and then alters its scores before
        # committing. This hook is that alteration point. None for an
        # honest node; set on a node deliberately made Byzantine for
        # testing / red-teaming. It is applied at the END of `score_epoch`,
        # so the node still commits/reveals its (corrupted) scores
        # consistently — i.e. it passes commit-reveal and must be caught by
        # DEVIATION detection, which is exactly the Day-26 case.
        self._score_corruptor: (
            Callable[[dict[str, AgentScore]], dict[str, AgentScore]] | None
        ) = None
        logger.info(
            "oracle node %s constructed — %d-node cluster%s",
            self.node_id, membership.size,
            " (single-node)" if membership.is_single_node else "",
        )

    # ── Constructors ────────────────────────────────────────────────────────

    @classmethod
    def single(
        cls,
        keypair:  NodeKeypair,
        *,
        registry: DetectorRegistry | None = None,
    ) -> "OracleNode":
        """
        Build a standalone single-node oracle — a degenerate 1-node cluster.
        This is the backward-compatible deployment: it talks to no peers and
        needs no transport.
        """
        membership = ClusterMembership(self_identity=keypair.identity)
        return cls(keypair, membership, transport=None, registry=registry)

    # ── Identity ────────────────────────────────────────────────────────────

    @property
    def node_id(self) -> str:
        return self._keypair.node_id

    @property
    def identity(self) -> NodeIdentity:
        return self._keypair.identity

    @property
    def membership(self) -> ClusterMembership:
        return self._membership

    @property
    def current_epoch(self) -> int:
        return self._current_epoch

    @property
    def transport(self) -> ClusterTransport | None:
        """The node's cluster transport — None for a lone single node."""
        return self._transport

    def set_epoch(self, epoch: int) -> None:
        """Advance the node's view of the current epoch."""
        if epoch < 1:
            raise ValueError("epoch must be >= 1")
        self._current_epoch = epoch

    # ── Running the detection pipeline ──────────────────────────────────────

    def run_epoch(
        self,
        epoch_id:     int,
        agent_inputs: Iterable[AgentEpochInput],
        *,
        submit_fn:    SubmitFn,
        slash_fn:     SlashFn | None = None,
        consensus:    ConsensusPolicy | None = None,
        computed_at:  datetime | None = None,
    ) -> EpochReport:
        """
        Run one scoring epoch on THIS node.

        This is a thin, transparent wrapper over `oracle.epoch_runner.run_epoch`
        — it threads the node's identity through as `node_id` and supplies a
        default `consensus` policy, but it does NOT change scoring. For a
        single node the default consensus is `SingleNodeConsensus`, so the
        resulting `EpochReport` is byte-identical to calling `run_epoch`
        directly without the node wrapper. The Day-23 done-when test proves
        exactly this.

        In a multi-node cluster (Days 24-28) the node will additionally
        commit-reveal with peers before finalising; that step slots in here
        without changing this signature.
        """
        policy = consensus if consensus is not None else SingleNodeConsensus()
        return run_epoch(
            epoch_id=epoch_id,
            agent_inputs=agent_inputs,
            submit_fn=submit_fn,
            slash_fn=slash_fn,
            consensus=policy,
            node_id=self.node_id,
            registry=self._registry,
            computed_at=computed_at,
        )

    # ── Serving peers — the ClusterService handlers ─────────────────────────

    def score_epoch(
        self,
        epoch_id:     int,
        agent_inputs: Iterable[AgentEpochInput],
        *,
        computed_at:  datetime | None = None,
    ) -> dict[str, AgentScore]:
        """
        Score every agent for an epoch and STORE the results on the node,
        keyed by epoch, so peers can fetch them via `get_scores`.

        This is the Day-24 cluster path: a node SCORES (here), the cluster
        EXCHANGES scores (`get_scores`), then aggregates the median
        (oracle/cluster/aggregation.py). It is distinct from `run_epoch`,
        which scores AND submits AND slashes in one pass for a standalone
        node — `score_epoch` produces a node's contribution to the cluster.

        Returns the agent_wallet -> AgentScore map it computed and stored.
        Pure + deterministic given its inputs.
        """
        from scoring import AlertTier as _AlertTier
        from detection import default_registry

        ts = computed_at or datetime.now(timezone.utc)
        registry = self._registry if self._registry is not None else default_registry()
        alert_code = {_AlertTier.GREEN: 0, _AlertTier.YELLOW: 1, _AlertTier.RED: 2}

        scores: dict[str, AgentScore] = {}
        for agent_input in agent_inputs:
            score_result = score_agent(agent_input, registry, computed_at=ts)
            scores[agent_input.agent_wallet] = AgentScore(
                agent_wallet=agent_input.agent_wallet,
                score=score_result.score,
                alert_tier=alert_code[score_result.alert],
                flags=score_result.aggregated_flags,
                immediate_red=score_result.immediate_red,
                confidence=score_result.confidence,
            )
        # Day 26: a Byzantine node corrupts its own scores here, AFTER
        # honest computation — so it still commits/reveals consistently and
        # must be caught by deviation detection, not commit-reveal.
        if self._score_corruptor is not None:
            scores = self._score_corruptor(scores)

        self._epoch_scores[epoch_id] = scores
        logger.info("node %s scored %d agents for epoch %d",
                    self.node_id, len(scores), epoch_id)
        return scores

    def make_byzantine(
        self,
        corruptor: Callable[[dict[str, AgentScore]], dict[str, AgentScore]],
    ) -> None:
        """
        Turn this node Byzantine — install a `corruptor` that alters the
        node's scores after honest computation. For testing and red-teaming
        the Byzantine-detection path; a production node never calls this.
        """
        self._score_corruptor = corruptor

    def make_honest(self) -> None:
        """Remove any Byzantine corruptor — restore honest behaviour."""
        self._score_corruptor = None

    def scores_for_epoch(self, epoch_id: int) -> dict[str, AgentScore] | None:
        """This node's stored scores for an epoch, or None if not yet scored."""
        scores = self._epoch_scores.get(epoch_id)
        return dict(scores) if scores is not None else None

    def ping(self, request: PingRequest) -> PingResponse:
        """
        Answer a peer's liveness probe. Echoes the nonce (proving a fresh,
        non-replayed response) and reports this node's epoch view.
        """
        return PingResponse(
            node_id=self.node_id,
            nonce=request.nonce,
            current_epoch=self._current_epoch,
        )

    # ── Day 25: commit-reveal round lifecycle ───────────────────────────────

    def open_round(
        self,
        epoch:           int,
        node_ids:        Sequence[str],
        *,
        commit_deadline: float,
        reveal_deadline: float,
        opened_at:       float = 0.0,
    ) -> "CommitRevealRound":
        """
        Open this node's commit-reveal round for an epoch. The round tracks
        every cluster node's commit and reveal. Must be called before this
        node — or any peer — can commit.
        """
        if epoch in self._rounds:
            raise RuntimeError(f"node {self.node_id}: round {epoch} already open")
        round_ = CommitRevealRound(
            epoch, node_ids,
            commit_deadline=commit_deadline,
            reveal_deadline=reveal_deadline,
            opened_at=opened_at,
        )
        self._rounds[epoch] = round_
        # The logical round clock is per-round — opening a new round resets
        # it to that round's start, so a fresh epoch is not blocked by the
        # previous epoch's elapsed time.
        self._round_clock = opened_at
        return round_

    def round_for(self, epoch: int) -> "CommitRevealRound | None":
        return self._rounds.get(epoch)

    def advance_round_clock(self, now: float) -> None:
        """
        Advance the node's logical commit-reveal clock. The epoch
        orchestrator calls this as the protocol moves between phases; the
        commit / reveal handlers stamp inbound peer submissions with it.
        """
        if now < self._round_clock:
            raise ValueError("the round clock cannot move backwards")
        self._round_clock = now

    def local_commit(self, epoch: int, *, now: float) -> CommitRequest:
        """
        This node commits its OWN scores for `epoch`.

        It must have scored the epoch (`score_epoch`) first. A fresh secret
        nonce is generated and stored; the commit hash binds this node to
        its scores. Returns the `CommitRequest` to broadcast to peers.
        """
        scores = self._epoch_scores.get(epoch)
        if scores is None:
            raise RuntimeError(
                f"node {self.node_id}: cannot commit epoch {epoch} — "
                f"score_epoch was not run"
            )
        round_ = self._rounds.get(epoch)
        if round_ is None:
            raise RuntimeError(
                f"node {self.node_id}: no open round for epoch {epoch}"
            )
        ordered = tuple(scores[w] for w in sorted(scores))
        nonce = new_nonce()
        self._epoch_nonces[epoch] = nonce
        commit_hash = compute_commit_hash(ordered, nonce)
        # Record our own commit in our own round view.
        round_.submit_commit(self.node_id, commit_hash, now=now)
        return CommitRequest(
            node_id=self.node_id, epoch=epoch, commit_hash=commit_hash,
        )

    def local_reveal(self, epoch: int, *, now: float) -> RevealRequest:
        """
        This node reveals its OWN (scores, nonce) for `epoch`, to broadcast
        to peers. Must have committed first.
        """
        scores = self._epoch_scores.get(epoch)
        nonce = self._epoch_nonces.get(epoch)
        if scores is None or nonce is None:
            raise RuntimeError(
                f"node {self.node_id}: cannot reveal epoch {epoch} — "
                f"not committed"
            )
        round_ = self._rounds.get(epoch)
        if round_ is None:
            raise RuntimeError(
                f"node {self.node_id}: no open round for epoch {epoch}"
            )
        ordered = tuple(scores[w] for w in sorted(scores))
        round_.submit_reveal(self.node_id, ordered, nonce, now=now)
        return RevealRequest(
            node_id=self.node_id, epoch=epoch, scores=ordered, salt=nonce,
        )

    # ── Serving peers — commit / reveal handlers (real, Day 25) ─────────────

    def commit(self, request: CommitRequest) -> CommitResponse:
        """
        Phase-1 commit handler — records a PEER's commit in this node's
        round view. The commit is a hash only; this node learns nothing
        about the peer's actual scores until the reveal phase.

        Rejects (with a reason) if there is no open round for the epoch,
        the commit phase has closed, or the peer already committed.
        """
        round_ = self._rounds.get(request.epoch)
        if round_ is None:
            return CommitResponse(
                accepted=False,
                reason=f"node {self.node_id} has no open round for "
                       f"epoch {request.epoch}",
            )
        try:
            round_.submit_commit(
                request.node_id, request.commit_hash, now=self._round_clock,
            )
        except CommitRejected as exc:
            return CommitResponse(accepted=False, reason=str(exc))
        return CommitResponse(accepted=True)

    def reveal(self, request: RevealRequest) -> RevealResponse:
        """
        Phase-2 reveal handler — records a PEER's reveal in this node's
        round view and VERIFIES it against the peer's earlier commit.

        A reveal whose (scores, nonce) does not hash to the peer's commit
        is recorded `verified=False` — this is exactly how a node that
        copied a peer's score is caught: its commit, made in Phase 1,
        cannot match scores it copied in Phase 2.
        """
        round_ = self._rounds.get(request.epoch)
        if round_ is None:
            return RevealResponse(
                verified=False,
                reason=f"node {self.node_id} has no open round for "
                       f"epoch {request.epoch}",
            )
        try:
            record = round_.submit_reveal(
                request.node_id, request.scores, request.salt,
                now=self._round_clock,
            )
        except RevealRejected as exc:
            return RevealResponse(verified=False, reason=str(exc))
        return RevealResponse(verified=record.verified, reason=record.reason)

    def get_scores(self, request: GetScoresRequest) -> GetScoresResponse:
        """
        Day-24 score-exchange handler. Returns this node's stored epoch
        scores so a peer can compute the cluster median.

        If this node has not scored the requested epoch yet, `available`
        is False — the peer treats that exactly like an offline node (this
        node simply does not contribute to that epoch's median). Honest
        about not-yet-scored rather than returning an empty score set that
        looks like "scored, no agents".
        """
        scores = self._epoch_scores.get(request.epoch)
        if scores is None:
            return GetScoresResponse(
                node_id=self.node_id, epoch=request.epoch,
                available=False,
            )
        # Deterministic order — sorted by wallet — so the response is stable.
        ordered = tuple(scores[w] for w in sorted(scores))
        return GetScoresResponse(
            node_id=self.node_id, epoch=request.epoch,
            available=True, scores=ordered,
        )

    # ── Reaching peers — uses the transport ─────────────────────────────────

    def ping_peer(self, peer_id: str) -> PingResponse:
        """
        Ping a peer by id. Requires a transport — a lone single node has
        none and calling this on one is a usage error.
        """
        if self._transport is None:
            raise RuntimeError(
                f"node {self.node_id} has no transport — it is a single-node "
                f"deployment with no peers to reach"
            )
        nonce = self._next_nonce()
        request = PingRequest(node_id=self.node_id, nonce=nonce)
        response = self._transport.ping(peer_id, request)
        # The peer must echo our nonce — guards against a stale / replayed
        # response.
        if response.nonce != nonce:
            raise RuntimeError(
                f"peer {peer_id} echoed nonce {response.nonce}, "
                f"expected {nonce}"
            )
        return response

    def ping_all_peers(self) -> dict[str, PingResponse | None]:
        """
        Ping every peer. Returns peer_id -> PingResponse, or None for a peer
        that could not be reached. Never raises for an unreachable peer —
        liveness is a status, not an error.
        """
        from oracle.cluster.transport import PeerUnreachable

        out: dict[str, PingResponse | None] = {}
        for peer_id in self._membership.peer_ids():
            try:
                out[peer_id] = self.ping_peer(peer_id)
            except PeerUnreachable:
                logger.warning("peer %s unreachable from %s",
                               peer_id, self.node_id)
                out[peer_id] = None
        return out

    # ── Internals ───────────────────────────────────────────────────────────

    _nonce_counter: int = 0

    def _next_nonce(self) -> int:
        """A monotonic per-node nonce for outbound RPCs."""
        self._nonce_counter += 1
        return self._nonce_counter
