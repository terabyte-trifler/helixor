"""
oracle/cluster/byzantine_runner.py — a commit-reveal epoch with Byzantine
detection and watchdog escalation.

Day 25's commit-reveal epoch produces a set of VERIFIED reveals (the nodes
whose revealed scores hashed to their commits). But a verified reveal can
still be WRONG: hash verification proves a node committed to its scores
independently, not that the scores are correct. A Byzantine node can score
honestly-shaped garbage, commit it, and reveal it — passing commit-reveal
while poisoning the result.

Day 26 adds the layer that catches that:

    commit-reveal epoch  (Day 25)
      -> VERIFIED reveals
        -> DEVIATION ANALYSIS  — flag nodes >30% off the cluster median
          -> EXCLUDE the Byzantine nodes from aggregation
            -> aggregate the HONEST-MAJORITY median  (Day 24)
              -> WATCHDOG  — accumulate strikes; challenge repeat offenders

So the cluster does not merely tolerate a Byzantine node statistically
(the median already did that) — it NAMES it, EXCLUDES it explicitly, and
ESCALATES a persistent offender to on-chain slashing.

DETERMINISM
-----------
Detection, exclusion, re-aggregation, and strike accounting are all
deterministic. Every honest node runs the identical pipeline and reaches
the identical verdict — including the identical decision to challenge.
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
)
from oracle.cluster.byzantine import (
    BYZANTINE_DEVIATION_THRESHOLD,
    DeviationReport,
    analyse_deviation,
)
from oracle.cluster.byzantine_watchdog import (
    ByzantineChallenge,
    ByzantineWatchdog,
    ChallengeFn,
    EpochByzantineFlag,
    NonRevealFlag,
    SlowDriftFlag,
)
from oracle.cluster.drift_detector import (
    DriftDetector,
    DriftFlag,
)
from oracle.cluster.commit_reveal_runner import (
    ClusterSubmitFn,
    simulate_commit_reveal_epoch,
)
from oracle.cluster.messages import AgentScore
from oracle.epoch_runner import AgentEpochInput

if TYPE_CHECKING:
    from oracle.node import OracleNode

logger = logging.getLogger("helixor.oracle.cluster.byzantine_runner")


# =============================================================================
# Results
# =============================================================================

@dataclass(frozen=True, slots=True)
class ByzantineAgentResult:
    """One agent's outcome — the honest-majority median and who was excluded."""
    agent_wallet:    str
    aggregated:      AggregatedScore | None
    deviation:       DeviationReport
    excluded_nodes:  tuple[str, ...]      # Byzantine nodes left out
    submitted:       bool
    submission:      object | None = None
    error:           str = ""
    # VULN-03: cross-epoch drift verdict for this agent in this epoch.
    # None when no DriftDetector is wired into the run.
    drift:           DriftFlag | None = None
    # VULN-03: nodes named as slow-drift attackers for this agent over the
    # rolling window. May overlap with excluded_nodes (a node both far off
    # the current median AND consistently drifting) but typically catches
    # the subtler cases excluded_nodes misses.
    drift_attackers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ByzantineEpochReport:
    """One epoch's outcome with Byzantine detection."""
    epoch_id:         int
    computed_at:      datetime
    cluster_size:     int
    verified_nodes:   tuple[str, ...]
    byzantine_nodes:  tuple[str, ...]       # flagged Byzantine this epoch
    challenges_filed: tuple[ByzantineChallenge, ...]
    results:          tuple[ByzantineAgentResult, ...]
    # VULN-03: nodes attributed as slow-drift attackers somewhere this epoch.
    drift_attackers:  tuple[str, ...] = ()
    # VULN-03: drift-specific challenges filed this epoch (proof_type=SlowDrift).
    drift_challenges: tuple[ByzantineChallenge, ...] = ()
    # VULN-05: nodes that COMMITTED but never produced a verified reveal
    # before the reveal-deadline timeout. Surfaced to operators and fed
    # into the watchdog's PROOF_NON_REVEAL strike track.
    non_revealers:    tuple[str, ...] = ()
    # VULN-05: non-reveal challenges filed this epoch (proof_type=NonReveal).
    non_reveal_challenges: tuple[ByzantineChallenge, ...] = ()
    # VULN-05: True iff the commit-reveal round closed early on the
    # partial-reveal quorum (rather than all-revealed or the timeout).
    closed_by_quorum: bool = False

    @property
    def submitted_count(self) -> int:
        return sum(1 for r in self.results if r.submitted)

    @property
    def quorum_failure_count(self) -> int:
        return sum(1 for r in self.results if r.aggregated is None)

    def by_wallet(self, wallet: str) -> ByzantineAgentResult | None:
        for r in self.results:
            if r.agent_wallet == wallet:
                return r
        return None


# =============================================================================
# run_byzantine_epoch
# =============================================================================

def run_byzantine_epoch(
    nodes:         Sequence["OracleNode"],
    epoch_id:      int,
    agent_inputs:  Sequence[AgentEpochInput],
    *,
    submit_fn:     ClusterSubmitFn,
    watchdog:      ByzantineWatchdog,
    challenge_fn:  ChallengeFn | None = None,
    computed_at:   datetime | None = None,
    deviation_threshold: float = BYZANTINE_DEVIATION_THRESHOLD,
    drop_commit:   Sequence[str] = (),
    drop_reveal:   Sequence[str] = (),
    drift_detector: DriftDetector | None = None,
) -> ByzantineEpochReport:
    """
    Run one commit-reveal epoch, then detect and act on Byzantine nodes.

    Steps:
      1. Run the Day-25 commit-reveal epoch -> verified reveals.
      2. For each agent, analyse deviation: flag nodes >threshold off the
         cluster median.
      3. EXCLUDE the flagged nodes; re-aggregate the honest-majority median.
      4. Feed the epoch's Byzantine flags to the `watchdog`, which
         accumulates strikes and challenges repeat offenders.

    The Byzantine node's commit-reveal participation is honest in FORM (it
    committed and revealed consistently) — `drop_commit` / `drop_reveal`
    are still available to also model nodes that fault at the protocol
    level. A node can therefore fail Day-25 (no valid reveal) OR Day-26
    (revealed but deviates) — both get it excluded.

    Returns a `ByzantineEpochReport`. Deterministic given its inputs.
    """
    ts = computed_at or datetime.now(timezone.utc)
    agent_list = list(agent_inputs)
    cluster_size = nodes[0].membership.size if nodes else 0

    # ── 1. The Day-25 commit-reveal epoch ───────────────────────────────────
    # We give it a NO-OP submit — Day 26 submits AFTER excluding Byzantine
    # nodes, so the commit-reveal step must not submit the un-screened
    # median. It exists here only to drive commit-reveal and surface the
    # verified score sets.
    cr_reports = simulate_commit_reveal_epoch(
        nodes, epoch_id, agent_list,
        submit_fn=lambda _w, _a: None,            # no-op: submit comes later
        computed_at=ts,
        drop_commit=drop_commit,
        drop_reveal=drop_reveal,
    )
    # Every honest node's report is identical; take node 0's verified set.
    primary = nodes[0]
    round_ = primary.round_for(epoch_id)
    assert round_ is not None
    close_now = close_time(round_)
    verified = round_.verified_scores(close_now)            # node -> scores
    # VULN-05: surface committed-but-silent nodes for the watchdog. Once
    # we are past the reveal deadline (we always are at `close_now`), this
    # set is final for the epoch.
    non_revealers = round_.non_revealers(close_now)

    # ── 2 + 3. Per-agent deviation analysis, exclusion, re-aggregation ──────
    results: list[ByzantineAgentResult] = []
    epoch_flags: list[EpochByzantineFlag] = []
    byzantine_this_epoch: set[str] = set()
    drift_flags_for_watchdog: list[SlowDriftFlag] = []
    drift_attackers_this_epoch: set[str] = set()

    for agent_input in agent_list:
        wallet = agent_input.agent_wallet
        # Collect every verified node's score for this agent.
        per_node: dict[str, AgentScore] = {}
        for node_id, scores in verified.items():
            match = _find(scores, wallet)
            if match is not None:
                per_node[node_id] = match

        if not per_node:
            results.append(ByzantineAgentResult(
                agent_wallet=wallet, aggregated=None,
                deviation=DeviationReport(wallet, 0, ()),
                excluded_nodes=(), submitted=False,
                error="no verified scores for this agent",
            ))
            continue

        # ── deviation analysis ─────────────────────────────────────────────
        deviation = analyse_deviation(
            wallet, {nid: s.score for nid, s in per_node.items()},
            threshold=deviation_threshold,
        )
        byzantine = set(deviation.byzantine_nodes)
        byzantine_this_epoch |= byzantine
        for nid in byzantine:
            byz_score = per_node[nid].score
            epoch_flags.append(EpochByzantineFlag(
                node_id=nid, epoch=epoch_id, subject_agent=wallet,
                accused_score=byz_score, cluster_median=deviation.median,
            ))

        # ── exclude Byzantine nodes, re-aggregate the honest majority ──────
        honest_scores = [
            NodeScore(node_id=nid, score=s)
            for nid, s in per_node.items()
            if nid not in byzantine
        ]
        result = _aggregate_honest(
            wallet, honest_scores, cluster_size,
            deviation, tuple(sorted(byzantine)), submit_fn,
        )

        # ── VULN-03 cross-epoch drift detection ────────────────────────────
        if drift_detector is not None and result.aggregated is not None:
            drift_flag = drift_detector.observe(
                agent_wallet=wallet,
                epoch=epoch_id,
                aggregated_score=result.aggregated.score,
                per_node_scores={
                    nid: s.score for nid, s in per_node.items()
                    if nid not in byzantine
                },
                cluster_median=deviation.median,
            )
            attackers = drift_detector.drift_attackers(wallet)
            drift_attackers_this_epoch.update(attackers)

            # Convert per-agent attacker attribution into watchdog-readable
            # SlowDriftFlag records. The mean signed deviation is taken
            # from the detector's per-node attribution view.
            attribution_by_node = {
                a.node_id: a
                for a in drift_detector.node_attributions(wallet)
            }
            for attacker_id in attackers:
                attribution = attribution_by_node[attacker_id]
                drift_flags_for_watchdog.append(SlowDriftFlag(
                    node_id=attacker_id,
                    epoch=epoch_id,
                    subject_agent=wallet,
                    mean_signed_deviation=attribution.mean_signed_deviation,
                    drift_direction=attribution.drift_direction,
                    epochs_observed=attribution.epochs_contributed,
                ))

            result = ByzantineAgentResult(
                agent_wallet=result.agent_wallet,
                aggregated=result.aggregated,
                deviation=result.deviation,
                excluded_nodes=result.excluded_nodes,
                submitted=result.submitted,
                submission=result.submission,
                error=result.error,
                drift=drift_flag,
                drift_attackers=attackers,
            )

        results.append(result)

    # ── 4. Watchdog — strikes + escalation ──────────────────────────────────
    challenges = watchdog.record_epoch(
        epoch_id, epoch_flags, challenge_fn=challenge_fn,
    )

    # VULN-03: drift-strikes are tracked on a separate counter with their
    # own escalation threshold; the resulting challenges carry SlowDrift
    # evidence and are reported alongside the Byzantine challenges above.
    drift_challenges: list[ByzantineChallenge] = []
    if drift_flags_for_watchdog:
        drift_challenges = watchdog.record_drift_attackers(
            epoch_id, drift_flags_for_watchdog, challenge_fn=challenge_fn,
        )

    # VULN-05: non-reveal strikes are accumulated per-epoch a node
    # committed to the commit-reveal round and then failed to produce a
    # verified reveal before the deadline. Routed through the same
    # challenge_fn seam as the other strike tracks so production wires
    # the on-chain instruction and tests pass a recording stub.
    non_reveal_challenges: list[ByzantineChallenge] = []
    if non_revealers:
        non_reveal_flags = [
            NonRevealFlag(
                node_id=nid, epoch=epoch_id,
                reveal_deadline=round_.reveal_deadline,
            )
            for nid in sorted(non_revealers)
        ]
        non_reveal_challenges = watchdog.record_non_revealers(
            epoch_id, non_reveal_flags, challenge_fn=challenge_fn,
        )

    return ByzantineEpochReport(
        epoch_id=epoch_id,
        computed_at=ts,
        cluster_size=cluster_size,
        verified_nodes=tuple(sorted(verified)),
        byzantine_nodes=tuple(sorted(byzantine_this_epoch)),
        challenges_filed=tuple(challenges),
        results=tuple(results),
        drift_attackers=tuple(sorted(drift_attackers_this_epoch)),
        drift_challenges=tuple(drift_challenges),
        non_revealers=tuple(sorted(non_revealers)),
        non_reveal_challenges=tuple(non_reveal_challenges),
        closed_by_quorum=round_.closed_by_quorum,
    )


def close_time(round_) -> float:
    """A logical time guaranteed past the round's reveal deadline."""
    return round_._reveal_deadline + 1.0


def _find(scores: Sequence[AgentScore], wallet: str) -> AgentScore | None:
    for s in scores:
        if s.agent_wallet == wallet:
            return s
    return None


def _aggregate_honest(
    wallet:          str,
    honest_scores:   Sequence[NodeScore],
    cluster_size:    int,
    deviation:       DeviationReport,
    excluded:        tuple[str, ...],
    submit_fn:       ClusterSubmitFn,
) -> ByzantineAgentResult:
    """Aggregate the honest-majority median (Byzantine nodes already removed)."""
    try:
        aggregated = aggregate_scores(
            wallet, list(honest_scores), cluster_size=cluster_size,
        )
    except QuorumNotMet as exc:
        logger.error("byzantine epoch: %s", exc)
        return ByzantineAgentResult(
            agent_wallet=wallet, aggregated=None, deviation=deviation,
            excluded_nodes=excluded, submitted=False, error=str(exc),
        )
    except ValueError as exc:
        return ByzantineAgentResult(
            agent_wallet=wallet, aggregated=None, deviation=deviation,
            excluded_nodes=excluded, submitted=False,
            error=f"aggregation failed: {exc}",
        )

    try:
        submission = submit_fn(wallet, aggregated)
        return ByzantineAgentResult(
            agent_wallet=wallet, aggregated=aggregated, deviation=deviation,
            excluded_nodes=excluded, submitted=bool(submission),
            submission=submission,
        )
    except Exception as exc:                           # noqa: BLE001
        return ByzantineAgentResult(
            agent_wallet=wallet, aggregated=aggregated, deviation=deviation,
            excluded_nodes=excluded, submitted=False,
            error=f"submission failed: {exc}",
        )
