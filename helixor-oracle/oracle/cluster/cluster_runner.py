"""
oracle/cluster/cluster_runner.py — the cluster epoch orchestrator.

Day 24 actually runs the cluster. `ClusterEpochRunner` drives one epoch
across the 3-5 node cluster:

  1. SCORE    — every node scores every agent independently (its own
                deterministic detection pipeline).
  2. EXCHANGE — nodes fetch each other's scores over the transport
                (the `get_scores` RPC).
  3. AGGREGATE— the median is computed per agent (BFT-robust — one faulty
                or offline node cannot move it).
  4. SUBMIT   — the median score is submitted on-chain (via an injected
                submit seam, the same pattern as the single-node runner).

THE BFT GUARANTEE
-----------------
The exchange step tolerates a missing peer: a node that is offline (or
that has not scored the epoch) simply contributes no score. As long as a
QUORUM — a strict majority — still contributes, the median is well-defined
and correct. With 3 nodes, killing 1 leaves 2, which is quorum, and the
median of the 2 honest nodes is the correct score. This is the Day-24
done-when: "killing 1 node still produces a correct score from the
remaining 2."

A node whose own scoring is faulty (it returns a wrong value) is handled
the same way by the median — its outlier value is simply not the middle.

WHO RUNS THIS
-------------
Each node runs its own `ClusterEpochRunner` against its own view of the
cluster — there is no central coordinator. Because scoring, exchange, and
median aggregation are all deterministic, every honest node's runner
reaches the byte-identical aggregated score, so they all submit the same
thing. (Submission is idempotent on-chain — see the certificate program's
write-once PDA — so N nodes submitting the identical score is safe.)
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from oracle.cluster.aggregation import (
    AggregatedScore,
    ConsensusNotMet,
    NodeScore,
    QuorumNotMet,
    aggregate_scores,
)
from oracle.cluster.messages import AgentScore, GetScoresRequest
from oracle.cluster.transport import ClusterTransport, PeerUnreachable
from oracle.epoch_runner import AgentEpochInput

if TYPE_CHECKING:
    # Imported for type hints only — importing it at runtime would create a
    # cycle (oracle.node -> oracle.cluster -> cluster_runner -> oracle.node).
    # ClusterEpochRunner only needs OracleNode's interface, not its module.
    from oracle.node import OracleNode

logger = logging.getLogger("helixor.oracle.cluster.runner")


# A cluster submission function takes the agent + the AGGREGATED score and
# anchors it on-chain. Injected, like the single-node SubmitFn.
ClusterSubmitFn = Callable[[str, AggregatedScore], object]


# =============================================================================
# Per-agent + whole-epoch cluster results
# =============================================================================

@dataclass(frozen=True, slots=True)
class ClusterAgentResult:
    """The cluster's outcome for one agent in one epoch."""
    agent_wallet: str
    aggregated:   AggregatedScore | None      # None if quorum was not met
    submitted:    bool
    submission:   object | None = None
    error:        str = ""


@dataclass(frozen=True, slots=True)
class ClusterEpochReport:
    """The outcome of one cluster epoch."""
    epoch_id:           int
    computed_at:        datetime
    cluster_size:       int
    contributing_nodes: tuple[str, ...]       # nodes that contributed scores
    results:            tuple[ClusterAgentResult, ...]

    @property
    def agent_count(self) -> int:
        return len(self.results)

    @property
    def submitted_count(self) -> int:
        return sum(1 for r in self.results if r.submitted)

    @property
    def quorum_failure_count(self) -> int:
        return sum(1 for r in self.results if r.aggregated is None)

    def by_wallet(self, wallet: str) -> ClusterAgentResult | None:
        for r in self.results:
            if r.agent_wallet == wallet:
                return r
        return None


# =============================================================================
# ClusterEpochRunner
# =============================================================================

class ClusterEpochRunner:
    """
    Runs one epoch across the cluster from the perspective of `local_node`.

    `local_node` scores locally; the runner then fetches every peer's
    scores over `local_node`'s transport, aggregates the median, and
    submits. A peer that cannot be reached, or that has not scored the
    epoch, is simply omitted — the median is taken over whoever
    contributed, provided quorum holds.
    """

    def __init__(self, local_node: OracleNode) -> None:
        self._node = local_node

    def run_epoch(
        self,
        epoch_id:     int,
        agent_inputs: Sequence[AgentEpochInput],
        *,
        submit_fn:    ClusterSubmitFn,
        computed_at:  datetime | None = None,
    ) -> ClusterEpochReport:
        """
        Run one cluster epoch: score locally, exchange with peers, aggregate
        the median, submit.

        A failure aggregating or submitting ONE agent is contained — it
        becomes an error / quorum-failure on that agent's result and the
        epoch continues.
        """
        ts = computed_at or datetime.now(timezone.utc)
        cluster_size = self._node.membership.size
        agent_list = list(agent_inputs)

        # ── 1. SCORE locally (unless this node already scored this epoch) ───
        # A node that already ran `score_epoch` for this epoch — e.g. as
        # step 1 of `simulate_cluster_epoch`, or because the operator
        # scored ahead of aggregating — reuses those scores. Scoring is
        # deterministic, so re-scoring would yield the identical result;
        # reusing simply avoids the redundant work.
        existing = self._node.scores_for_epoch(epoch_id)
        if existing is not None:
            local_scores = existing
        else:
            local_scores = self._node.score_epoch(
                epoch_id, agent_list, computed_at=ts,
            )

        # ── 2. EXCHANGE — collect every node's scores ───────────────────────
        # node_id -> {wallet -> AgentScore}. Starts with this node's own.
        all_node_scores: dict[str, dict[str, AgentScore]] = {
            self._node.node_id: local_scores,
        }
        contributing = [self._node.node_id]
        for peer_id, peer_scores in self._fetch_peer_scores(epoch_id):
            if peer_scores is not None:
                all_node_scores[peer_id] = peer_scores
                contributing.append(peer_id)
            else:
                logger.warning(
                    "epoch %d: peer %s contributed no scores "
                    "(offline or not yet scored)", epoch_id, peer_id,
                )

        logger.info(
            "epoch %d: %d/%d nodes contributed scores",
            epoch_id, len(contributing), cluster_size,
        )

        # ── 3 + 4. AGGREGATE the median, then SUBMIT ────────────────────────
        results: list[ClusterAgentResult] = []
        for agent_input in agent_list:
            wallet = agent_input.agent_wallet
            results.append(
                self._aggregate_and_submit(
                    wallet, all_node_scores, cluster_size, submit_fn,
                )
            )

        return ClusterEpochReport(
            epoch_id=epoch_id,
            computed_at=ts,
            cluster_size=cluster_size,
            contributing_nodes=tuple(sorted(contributing)),
            results=tuple(results),
        )

    # ── Step 2 helper: fetch peer scores over the transport ─────────────────

    def _fetch_peer_scores(
        self, epoch_id: int,
    ) -> Iterable[tuple[str, dict[str, AgentScore] | None]]:
        """
        Fetch every peer's epoch scores. Yields (peer_id, scores) where
        `scores` is None if the peer was unreachable or had not scored —
        both are tolerated; the peer just does not contribute to the median.
        """
        membership = self._node.membership
        if membership.is_single_node:
            return                                    # no peers to fetch
        transport = self._require_transport()
        request = GetScoresRequest(node_id=self._node.node_id, epoch=epoch_id)

        for peer_id in membership.peer_ids():
            try:
                response = transport.get_scores(peer_id, request)
            except PeerUnreachable:
                # An offline peer — tolerated. It contributes nothing.
                yield peer_id, None
                continue
            if not response.available:
                # Reachable but has not scored this epoch yet — also None.
                yield peer_id, None
                continue
            yield peer_id, {s.agent_wallet: s for s in response.scores}

    # ── Step 3+4 helper: aggregate one agent + submit ───────────────────────

    def _aggregate_and_submit(
        self,
        wallet:          str,
        all_node_scores: dict[str, dict[str, AgentScore]],
        cluster_size:    int,
        submit_fn:       ClusterSubmitFn,
    ) -> ClusterAgentResult:
        # Collect every node's score for THIS agent.
        node_scores = [
            NodeScore(node_id=node_id, score=scores[wallet])
            for node_id, scores in all_node_scores.items()
            if wallet in scores
        ]

        # ── Aggregate the median ────────────────────────────────────────────
        try:
            aggregated = aggregate_scores(
                wallet, node_scores, cluster_size=cluster_size,
            )
        except QuorumNotMet as exc:
            logger.error("epoch aggregation: %s", exc)
            return ClusterAgentResult(
                agent_wallet=wallet, aggregated=None, submitted=False,
                error=str(exc),
            )
        except ConsensusNotMet as exc:
            logger.error("epoch aggregation: %s", exc)
            return ClusterAgentResult(
                agent_wallet=wallet, aggregated=None, submitted=False,
                error=str(exc),
            )
        except ValueError as exc:
            logger.error("epoch aggregation failed for %s: %s", wallet, exc)
            return ClusterAgentResult(
                agent_wallet=wallet, aggregated=None, submitted=False,
                error=f"aggregation failed: {exc}",
            )

        # ── Submit the median ───────────────────────────────────────────────
        try:
            submission = submit_fn(wallet, aggregated)
            return ClusterAgentResult(
                agent_wallet=wallet, aggregated=aggregated,
                submitted=bool(submission), submission=submission,
            )
        except Exception as exc:                       # noqa: BLE001
            logger.error("epoch submission failed for %s: %s", wallet, exc)
            return ClusterAgentResult(
                agent_wallet=wallet, aggregated=aggregated, submitted=False,
                error=f"submission failed: {exc}",
            )

    def _require_transport(self) -> ClusterTransport:
        transport = self._node.transport
        if transport is None:
            raise RuntimeError(
                f"node {self._node.node_id} has no transport — a cluster "
                f"epoch needs one to exchange scores with peers"
            )
        return transport


# =============================================================================
# simulate_cluster_epoch — run every node, the faithful multi-process model
# =============================================================================

def simulate_cluster_epoch(
    nodes:        Sequence["OracleNode"],
    epoch_id:     int,
    agent_inputs: Sequence[AgentEpochInput],
    *,
    submit_fn:    ClusterSubmitFn,
    computed_at:  datetime | None = None,
) -> dict[str, ClusterEpochReport]:
    """
    Run a full cluster epoch across `nodes` — a faithful model of N
    independent node processes.

    In production each of the 3-5 nodes is its own process (on its own VM)
    running its own `ClusterEpochRunner`. There is no central coordinator.
    This helper models that honestly:

      1. EVERY node scores the epoch independently (its own pipeline) —
         this is what each node process does on its own;
      2. THEN every node runs its `ClusterEpochRunner`, which fetches the
         peers' now-available scores and aggregates the median.

    Step 1 is separated out because in a real deployment all nodes score
    concurrently before any exchange happens — a node cannot fetch a
    peer's scores until that peer has produced them. Doing all scoring
    first is the deterministic, single-process equivalent of N processes
    scoring in parallel.

    Returns node_id -> that node's ClusterEpochReport. Because scoring,
    exchange, and median aggregation are all deterministic, every honest
    node's report carries the IDENTICAL aggregated scores — which is the
    cluster's whole point.
    """
    ts = computed_at or datetime.now(timezone.utc)
    agent_list = list(agent_inputs)

    # ── 1. Every node scores independently ──────────────────────────────────
    for node in nodes:
        node.score_epoch(epoch_id, agent_list, computed_at=ts)

    # ── 2. Every node aggregates from its own perspective ───────────────────
    reports: dict[str, ClusterEpochReport] = {}
    for node in nodes:
        runner = ClusterEpochRunner(node)
        reports[node.node_id] = runner.run_epoch(
            epoch_id, agent_list, submit_fn=submit_fn, computed_at=ts,
        )
    return reports
