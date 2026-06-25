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
from collections.abc import Callable, Mapping, Sequence
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
from oracle.cluster.input_commitment import (
    COMMITMENT_BYTES,
    SlotAnchor,
    commitments_agree,
    compute_input_commitment,
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
from baseline import compute_baseline, stats_hash_to_bytes
from detection.types import FlagBit
from oracle.epoch_runner import AgentEpochInput

if TYPE_CHECKING:
    from oracle.node import OracleNode

logger = logging.getLogger("phylanx.oracle.cluster.byzantine_runner")


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
    # AW-01: the 32-byte cluster-majority input-provenance commitment for
    # this agent. `None` ONLY when no quorum agreed on a commitment — in
    # that case the certificate path (pipeline._sign_and_submit) refuses
    # to issue a cert because there is no input-provenance majority to
    # attest to.
    input_commitment: bytes | None = None
    # AW-01: node_ids whose computed `input_commitment` diverged from the
    # cluster majority for this agent. Surfaced via FlagBit.INPUT_DIVERGENCE
    # on the aggregated score so the watchdog can attribute strikes to nodes
    # that disagree about what the upstream pipeline delivered.
    input_divergent_nodes: tuple[str, ...] = ()
    # AW-01-EXT: the SlotAnchor the cluster pinned at scoring time. Carried
    # on the result so the cert pipeline can fold the SAME anchor into
    # `cert_payload_digest` AND submit it on-chain for SlotHashes
    # verification. `None` ONLY when the runner had no anchor wired (legacy
    # tests); the cert pipeline refuses to issue a cert in that case for
    # the same reason a missing input_commitment does.
    slot_anchor:     SlotAnchor | None = None


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
    # VULN-22: nodes whose commit was rejected for (scoring_algo,
    # scoring_weights) version mismatch against the round's pinned
    # version. These nodes are SILENTLY EXCLUDED — surfaced here for
    # operator visibility (typically signals an in-progress rolling
    # upgrade), but NEVER flagged as `byzantine_nodes` and NEVER fed to
    # the watchdog's per-epoch strike track. Slashing a node for being
    # on the wrong version of the scoring algorithm would let an
    # adversary grief honest operators every deploy window — which is
    # exactly the upgrade-induced-liveness-attack the audit describes.
    version_excluded_nodes: tuple[str, ...] = ()

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
    # AW-01 input-provenance hooks.
    #
    # `input_commitment_overrides` maps (node_id, agent_wallet) → 32-byte
    # commitment to substitute that node's commitment for that agent — the
    # poisoned-pipeline simulation. When absent, the node computes the
    # honest commitment from `agent_inputs`.
    #
    # `input_commitment_quorum` is the cross-node quorum needed before the
    # cluster will sign a cert; defaults to a strict majority of the
    # cluster size. Below quorum → no commitment → no cert (the AW-01
    # closing of the gap).
    input_commitment_overrides: Mapping[tuple[str, str], bytes] | None = None,
    input_commitment_quorum:    int | None = None,
    # AW-01-EXT: the SlotAnchor the cluster pins for THIS epoch (one anchor
    # per epoch, shared across every agent scored). The anchor is folded
    # into the input commitment AND threaded onto each agent's
    # `ByzantineAgentResult.slot_anchor` so the cert pipeline can submit it
    # for on-chain SlotHashes verification. Defaults to None for
    # back-compat with legacy tests that pre-date AW-01-EXT.
    slot_anchor:                SlotAnchor | None = None,
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
    # VULN-22: surface version-mismatched nodes (commits rejected at
    # phase 1 because their algo/weights version did not match the
    # round's pinned version). These nodes are NOT in `verified` (no
    # accepted commit -> no reveal -> no score), so they will NOT appear
    # in `byzantine_this_epoch` from deviation analysis. We capture the
    # set here purely for operator visibility; they MUST NOT be passed
    # to the watchdog as Byzantine flags.
    version_excluded = round_.version_mismatched_nodes()

    # ── 2 + 3. Per-agent deviation analysis, exclusion, re-aggregation ──────
    results: list[ByzantineAgentResult] = []
    epoch_flags: list[EpochByzantineFlag] = []
    byzantine_this_epoch: set[str] = set()
    drift_flags_for_watchdog: list[SlowDriftFlag] = []
    drift_attackers_this_epoch: set[str] = set()

    # AW-01: a strict-majority quorum if the caller didn't pin one.
    # cluster_size==0 (degenerate / single-node tests) collapses to 1.
    aw01_quorum = (
        input_commitment_quorum
        if input_commitment_quorum is not None
        else max(1, (cluster_size // 2) + 1)
    )
    overrides = input_commitment_overrides or {}
    # AW-01-EXT: every honest node folds the SAME slot anchor into its
    # commitment. A node that pinned a different anchor (e.g. a divergent
    # Solana RPC) lands in the divergent minority and is surfaced through
    # the existing INPUT_DIVERGENCE strike track — no separate watchdog
    # plumbing needed for the off-chain path.
    effective_anchor = slot_anchor if slot_anchor is not None else SlotAnchor.zero()

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

        # ── AW-01: per-node + cross-node input commitment ──────────────────
        # Every honest node computes the same SHA-256 over the canonical
        # inputs; a poisoned-pipeline node (modelled via
        # `input_commitment_overrides`) computes a different one. We tally
        # the per-node commitments and ONLY proceed with the cert path if a
        # quorum agreed. Nodes whose commitment dissents from the majority
        # are surfaced via `input_divergent_nodes` and the
        # FlagBit.INPUT_DIVERGENCE bit, so the watchdog can attribute
        # strikes to nodes that disagree about upstream inputs.
        commitment_baseline_hash = _agent_baseline_hash_for_commitment(
            agent_input, computed_at=ts,
        )
        node_ids_sorted = sorted(per_node.keys())
        per_node_commitments: list[bytes] = []
        for nid in node_ids_sorted:
            override = overrides.get((nid, wallet))
            if override is not None:
                if len(override) != COMMITMENT_BYTES:
                    raise ValueError(
                        f"input_commitment_overrides[{nid},{wallet}] must "
                        f"be {COMMITMENT_BYTES} bytes; got {len(override)}"
                    )
                per_node_commitments.append(override)
            else:
                per_node_commitments.append(compute_input_commitment(
                    agent_wallet=wallet,
                    baseline_window=agent_input.baseline_window,
                    current_window=agent_input.current_window,
                    baseline_transactions=agent_input.baseline_transactions,
                    current_transactions=agent_input.current_transactions,
                    baseline_hash=commitment_baseline_hash,
                    slot_anchor=effective_anchor,
                ))
        majority_commitment, divergent_indices = commitments_agree(
            per_node_commitments, quorum=aw01_quorum,
        )
        divergent_nodes = tuple(sorted(
            node_ids_sorted[i] for i in divergent_indices
        ))

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
        # ── AW-01: aggregate THEN submit. We need the divergence flag OR'd
        # into `aggregated.flags` BEFORE submit_fn sees the score, so any
        # downstream consumer (cert pipeline, telemetry, on-chain emit)
        # observes the same flagged score the watchdog sees. The cert path
        # (`pipeline._sign_and_submit`) additionally refuses to issue a
        # cert when `input_commitment is None` — no input-majority, no cert.
        result = _aggregate_honest_then_submit(
            wallet, honest_scores, cluster_size,
            deviation, tuple(sorted(byzantine)), submit_fn,
            input_commitment=majority_commitment,
            divergent_nodes=divergent_nodes,
            slot_anchor=slot_anchor,
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
                # AW-01 / AW-01-EXT: preserve the fields the previous
                # _aggregate_honest_then_submit call set; the drift branch
                # must not silently drop them.
                input_commitment=result.input_commitment,
                input_divergent_nodes=result.input_divergent_nodes,
                slot_anchor=result.slot_anchor,
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
        version_excluded_nodes=tuple(sorted(version_excluded)),
    )


def close_time(round_) -> float:
    """A logical time guaranteed past the round's reveal deadline."""
    return round_._reveal_deadline + 1.0


def _agent_baseline_hash_for_commitment(
    agent_input: AgentEpochInput,
    *,
    computed_at: datetime,
) -> bytes:
    """
    Compute the same 32-byte baseline hash the cert pipeline binds, so the
    input commitment covers the agent's baseline binding too. Pure
    function: deterministic given the agent input + computed_at.
    """
    baseline = compute_baseline(
        agent_input.agent_wallet,
        list(agent_input.baseline_transactions),
        agent_input.baseline_window,
        computed_at=computed_at,
    )
    return stats_hash_to_bytes(baseline.stats_hash)


def _apply_input_divergence_flag(
    aggregated:       AggregatedScore | None,
    *,
    input_commitment: bytes | None,
    divergent_nodes:  tuple[str, ...],
) -> AggregatedScore | None:
    """
    OR FlagBit.INPUT_DIVERGENCE into `aggregated.flags` when the cluster
    either diverged on its commitment OR failed to reach an AW-01 quorum.
    Pure transform on the frozen dataclass.
    """
    if aggregated is None:
        return None
    if not (divergent_nodes or input_commitment is None):
        return aggregated
    from dataclasses import replace
    return replace(
        aggregated, flags=int(aggregated.flags) | int(FlagBit.INPUT_DIVERGENCE),
    )


def _find(scores: Sequence[AgentScore], wallet: str) -> AgentScore | None:
    for s in scores:
        if s.agent_wallet == wallet:
            return s
    return None


def _aggregate_honest_then_submit(
    wallet:           str,
    honest_scores:    Sequence[NodeScore],
    cluster_size:     int,
    deviation:        DeviationReport,
    excluded:         tuple[str, ...],
    submit_fn:        ClusterSubmitFn,
    *,
    input_commitment: bytes | None,
    divergent_nodes:  tuple[str, ...],
    slot_anchor:      SlotAnchor | None,
) -> ByzantineAgentResult:
    """
    Aggregate the honest-majority median, fold in AW-01 input-divergence
    flag and commitment, THEN call submit_fn with the fully-flagged score.

    Order matters: submit_fn must see the same flagged score the watchdog
    and the cert pipeline will see. Otherwise the on-chain emit / telemetry
    would carry a different `flags` value than the in-memory result.
    """
    def _fail(error: str) -> ByzantineAgentResult:
        return ByzantineAgentResult(
            agent_wallet=wallet, aggregated=None, deviation=deviation,
            excluded_nodes=excluded, submitted=False, error=error,
            input_commitment=input_commitment,
            input_divergent_nodes=divergent_nodes,
            slot_anchor=slot_anchor,
        )

    try:
        aggregated = aggregate_scores(
            wallet, list(honest_scores), cluster_size=cluster_size,
        )
    except QuorumNotMet as exc:
        logger.error("byzantine epoch: %s", exc)
        return _fail(str(exc))
    except ValueError as exc:
        return _fail(f"aggregation failed: {exc}")

    aggregated = _apply_input_divergence_flag(
        aggregated,
        input_commitment=input_commitment,
        divergent_nodes=divergent_nodes,
    )

    try:
        submission = submit_fn(wallet, aggregated)
        return ByzantineAgentResult(
            agent_wallet=wallet, aggregated=aggregated, deviation=deviation,
            excluded_nodes=excluded, submitted=bool(submission),
            submission=submission,
            input_commitment=input_commitment,
            input_divergent_nodes=divergent_nodes,
            slot_anchor=slot_anchor,
        )
    except Exception as exc:                           # noqa: BLE001
        return ByzantineAgentResult(
            agent_wallet=wallet, aggregated=aggregated, deviation=deviation,
            excluded_nodes=excluded, submitted=False,
            error=f"submission failed: {exc}",
            input_commitment=input_commitment,
            input_divergent_nodes=divergent_nodes,
            slot_anchor=slot_anchor,
        )
