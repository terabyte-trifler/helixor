"""
oracle/cluster/commit_reveal_runner.py — a commit-reveal cluster epoch.

Day 24's `ClusterEpochRunner` exchanged scores directly. Day 25 replaces
that exchange with a COMMIT-REVEAL round, then feeds the verified result
into the same Day-24 median aggregator.

THE EPOCH, END TO END
---------------------
    1. SCORE    every node scores the epoch independently.
    2. OPEN     every node opens its commit-reveal round.
    3. COMMIT   every node computes commit_hash = sha256(scores||nonce)
                and broadcasts it. Nobody can see anyone's scores yet.
    4. REVEAL   once the commit phase closes, every node broadcasts
                (scores, nonce). Each peer VERIFIES the reveal against the
                commit — a copier's reveal fails here.
    5. AGGREGATE the VERIFIED reveals are aggregated by median (Day 24).
                A node that did not reveal, or whose reveal failed
                verification, is faulty and simply does not contribute.

`simulate_commit_reveal_epoch` runs this across N in-process nodes — a
faithful model of N node processes, since the protocol is broadcast-based
and every node runs the identical round logic.

TIMEOUTS
--------
The round carries a commit deadline and a reveal deadline. The
orchestrator drives a logical clock through them. A node that does not
commit before the commit deadline, or commits but does not reveal a valid
score before the reveal deadline, is timed out — treated as faulty,
exactly like an offline node. As long as a quorum still reveals validly,
the epoch produces a score.

DETERMINISM
-----------
Scoring, commit hashing, verification, and median aggregation are all
deterministic. The only non-deterministic input is each node's nonce
(which MUST be random) — and the nonce never affects the AGGREGATED score,
only the commit hash. So every honest node's runner reaches the identical
aggregated result.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from oracle.cluster.aggregation import (
    AggregatedScore,
    NodeScore,
    QuorumNotMet,
    aggregate_scores,
    quorum_for,
)
from oracle.cluster.commit_reveal_round import RoundPhase
from oracle.cluster.messages import AgentScore
from oracle.cluster.transport import PeerUnreachable
from oracle.epoch_runner import AgentEpochInput

if TYPE_CHECKING:
    from oracle.node import OracleNode

logger = logging.getLogger("helixor.oracle.cluster.commit_reveal")


# Reuse the Day-24 cluster submit seam shape.
ClusterSubmitFn = Callable[[str, AggregatedScore], object]


# =============================================================================
# Default phase durations (logical-clock units)
# =============================================================================

DEFAULT_COMMIT_WINDOW = 10.0
DEFAULT_REVEAL_WINDOW = 10.0


# =============================================================================
# Results
# =============================================================================

@dataclass(frozen=True, slots=True)
class CommitRevealAgentResult:
    """The cluster's outcome for one agent after a commit-reveal round."""
    agent_wallet: str
    aggregated:   AggregatedScore | None
    submitted:    bool
    submission:   object | None = None
    error:        str = ""


@dataclass(frozen=True, slots=True)
class CommitRevealEpochReport:
    """The outcome of one commit-reveal cluster epoch."""
    epoch_id:        int
    computed_at:     datetime
    cluster_size:    int
    committed_nodes: tuple[str, ...]
    verified_nodes:  tuple[str, ...]
    faulty_nodes:    tuple[str, ...]
    results:         tuple[CommitRevealAgentResult, ...]
    # VULN-05: nodes that COMMITTED but never produced a reveal by the
    # reveal-deadline timeout. Distinct from `faulty_nodes` (which also
    # captures missed commits and failed verifications) — surfaced so the
    # watchdog can attribute PROOF_NON_REVEAL strikes per epoch.
    non_revealers:   tuple[str, ...] = ()
    # VULN-05: True iff the cluster closed the reveal phase early via the
    # partial-reveal quorum, before all committers revealed. A signal
    # that one or more nodes routinely miss the reveal window.
    closed_by_quorum: bool = False

    @property
    def agent_count(self) -> int:
        return len(self.results)

    @property
    def submitted_count(self) -> int:
        return sum(1 for r in self.results if r.submitted)

    @property
    def quorum_failure_count(self) -> int:
        return sum(1 for r in self.results if r.aggregated is None)

    def by_wallet(self, wallet: str) -> CommitRevealAgentResult | None:
        for r in self.results:
            if r.agent_wallet == wallet:
                return r
        return None


# =============================================================================
# simulate_commit_reveal_epoch
# =============================================================================

def simulate_commit_reveal_epoch(
    nodes:           Sequence["OracleNode"],
    epoch_id:        int,
    agent_inputs:    Sequence[AgentEpochInput],
    *,
    submit_fn:       ClusterSubmitFn,
    computed_at:     datetime | None = None,
    commit_window:   float = DEFAULT_COMMIT_WINDOW,
    reveal_window:   float = DEFAULT_REVEAL_WINDOW,
    drop_commit:     Sequence[str] = (),
    drop_reveal:     Sequence[str] = (),
) -> dict[str, CommitRevealEpochReport]:
    """
    Run one full commit-reveal cluster epoch across `nodes`.

    `drop_commit` / `drop_reveal` name nodes that FAIL to commit / reveal —
    used to exercise timeout handling: such a node is timed out and treated
    as faulty.

    Returns node_id -> that node's CommitRevealEpochReport. Every honest
    node's report carries the identical aggregated scores.
    """
    ts = computed_at or datetime.now(timezone.utc)
    agent_list = list(agent_inputs)
    node_ids = [n.node_id for n in nodes]
    drop_commit_set = set(drop_commit)
    drop_reveal_set = set(drop_reveal)

    commit_deadline = commit_window
    reveal_deadline = commit_window + reveal_window
    # VULN-05: open every round with a partial-reveal quorum so a single
    # committed-but-silent node cannot force the cluster to wait the full
    # reveal window. Quorum mirrors the median aggregator's quorum
    # (floor(n/2)+1) — once that many verified reveals are in, the
    # cluster can produce a result and proceed.
    min_reveals = quorum_for(len(nodes)) if nodes else None

    # ── 1. SCORE — every node scores independently ──────────────────────────
    for node in nodes:
        node.score_epoch(epoch_id, agent_list, computed_at=ts)

    # ── 2. OPEN — every node opens its round ────────────────────────────────
    for node in nodes:
        node.open_round(
            epoch_id, node_ids,
            commit_deadline=commit_deadline,
            reveal_deadline=reveal_deadline,
            opened_at=0.0,
            min_reveals=min_reveals,
        )
        node.advance_round_clock(0.0)

    # ── 3. COMMIT — every node commits; broadcast each commit to peers ──────
    commit_now = 1.0
    commits = {}
    for node in nodes:
        if node.node_id in drop_commit_set:
            logger.warning("epoch %d: node %s drops its commit (fault)",
                           epoch_id, node.node_id)
            continue
        commits[node.node_id] = node.local_commit(epoch_id, now=commit_now)

    for node in nodes:
        node.advance_round_clock(commit_now)
        for committer_id, commit_req in commits.items():
            if committer_id == node.node_id:
                continue                      # already in our own round view
            node.commit(commit_req)

    # ── 4. REVEAL — close commit phase, then every node reveals ─────────────
    reveal_now = commit_deadline + 1.0
    for node in nodes:
        node.advance_round_clock(reveal_now)

    reveals = {}
    for node in nodes:
        if node.node_id in drop_commit_set:
            continue                          # never committed -> cannot reveal
        if node.node_id in drop_reveal_set:
            logger.warning("epoch %d: node %s drops its reveal (fault)",
                           epoch_id, node.node_id)
            continue
        reveals[node.node_id] = node.local_reveal(epoch_id, now=reveal_now)

    for node in nodes:
        for revealer_id, reveal_req in reveals.items():
            if revealer_id == node.node_id:
                continue
            node.reveal(reveal_req)

    # ── close the round ─────────────────────────────────────────────────────
    close_now = reveal_deadline + 1.0
    for node in nodes:
        node.advance_round_clock(close_now)

    # ── 5. AGGREGATE — from each node's perspective ─────────────────────────
    reports: dict[str, CommitRevealEpochReport] = {}
    for node in nodes:
        reports[node.node_id] = _aggregate_from_round(
            node, epoch_id, agent_list, ts, submit_fn, close_now,
        )
    return reports


def _aggregate_from_round(
    node:        "OracleNode",
    epoch_id:    int,
    agent_list:  Sequence[AgentEpochInput],
    ts:          datetime,
    submit_fn:   ClusterSubmitFn,
    now:         float,
) -> CommitRevealEpochReport:
    """Aggregate one node's view of a closed commit-reveal round."""
    round_ = node.round_for(epoch_id)
    assert round_ is not None, "round must be open"

    cluster_size = node.membership.size
    verified = round_.verified_scores(now)         # node_id -> scores tuple
    faulty = round_.faulty_nodes(now)
    non_revealers = round_.non_revealers(now)      # VULN-05

    logger.info(
        "epoch %d (node %s): %d committed, %d verified, %d faulty, "
        "%d non-revealers, closed_by_quorum=%s",
        epoch_id, node.node_id,
        len(round_.committed_nodes()), len(verified), len(faulty),
        len(non_revealers), round_.closed_by_quorum,
    )

    # Index verified scores by agent for the median.
    results: list[CommitRevealAgentResult] = []
    for agent_input in agent_list:
        wallet = agent_input.agent_wallet
        node_scores = [
            NodeScore(node_id=nid, score=_find(scores, wallet))
            for nid, scores in verified.items()
            if _find(scores, wallet) is not None
        ]
        results.append(
            _aggregate_and_submit(wallet, node_scores, cluster_size, submit_fn)
        )

    return CommitRevealEpochReport(
        epoch_id=epoch_id,
        computed_at=ts,
        cluster_size=cluster_size,
        committed_nodes=tuple(sorted(round_.committed_nodes())),
        verified_nodes=tuple(sorted(round_.verified_nodes())),
        faulty_nodes=tuple(sorted(faulty)),
        results=tuple(results),
        non_revealers=tuple(sorted(non_revealers)),
        closed_by_quorum=round_.closed_by_quorum,
    )


def _find(scores: Sequence[AgentScore], wallet: str) -> AgentScore | None:
    for s in scores:
        if s.agent_wallet == wallet:
            return s
    return None


def _aggregate_and_submit(
    wallet:       str,
    node_scores:  Sequence[NodeScore],
    cluster_size: int,
    submit_fn:    ClusterSubmitFn,
) -> CommitRevealAgentResult:
    """Median-aggregate one agent's verified scores and submit."""
    try:
        aggregated = aggregate_scores(
            wallet, list(node_scores), cluster_size=cluster_size,
        )
    except QuorumNotMet as exc:
        logger.error("commit-reveal aggregation: %s", exc)
        return CommitRevealAgentResult(
            agent_wallet=wallet, aggregated=None, submitted=False,
            error=str(exc),
        )
    except ValueError as exc:
        logger.error("commit-reveal aggregation failed for %s: %s", wallet, exc)
        return CommitRevealAgentResult(
            agent_wallet=wallet, aggregated=None, submitted=False,
            error=f"aggregation failed: {exc}",
        )

    try:
        submission = submit_fn(wallet, aggregated)
        return CommitRevealAgentResult(
            agent_wallet=wallet, aggregated=aggregated,
            submitted=bool(submission), submission=submission,
        )
    except Exception as exc:                           # noqa: BLE001
        logger.error("commit-reveal submission failed for %s: %s", wallet, exc)
        return CommitRevealAgentResult(
            agent_wallet=wallet, aggregated=aggregated, submitted=False,
            error=f"submission failed: {exc}",
        )
