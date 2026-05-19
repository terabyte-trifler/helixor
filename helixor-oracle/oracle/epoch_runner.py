"""
oracle/epoch_runner.py — the epoch pipeline: V2 detection engine + on-chain submit.

WHAT THIS IS
------------
The epoch runner is the orchestration layer that, once per scoring epoch,
walks every tracked agent through the full pipeline:

    transactions -> feature extraction -> baseline -> V2 detection engine
                 -> composite ScoreResult -> on-chain submission

The Doc-3 MVP had an epoch runner that called the MVP scorer. This is the
V2 runner: it calls `run_detection_engine` (the five-dimension V2 composite
scorer built across Days 5-13). The MVP scorer is gone from the scoring
call — but the ON-CHAIN SUBMISSION PATH is unchanged: the runner submits
through the exact same `oracle/commit_baseline.py` machinery the MVP used.

WHY THE SUBMISSION FUNCTION IS INJECTED
---------------------------------------
`run_epoch` takes its submission step as a parameter (`submit_fn`). In
production that is `submit_score_commitment`, which goes through the real
`submit_baseline_commitment` on-chain path. In tests it is a recording
stub. This keeps the runner fully testable without a live validator while
guaranteeing the production path is the unchanged on-chain machinery.

A NOTE ON THE ON-CHAIN SCORE INSTRUCTION
----------------------------------------
A dedicated `submit_score` Anchor instruction is Phase-3 work (Days 18-24).
Until it lands, a score's on-chain anchor is the committed baseline hash
(Day 3's `commit_baseline`). `submit_score_commitment` therefore routes
through `submit_baseline_commitment` today; the function is the seam where
the dedicated instruction slots in without touching the runner.

Everything here is pure orchestration — deterministic given its inputs.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone

from baseline import BaselineStats, compute_baseline
from detection import DetectorRegistry, default_registry, run_detection_engine
from detection.consistency_context import ConsistencyContext
from detection.performance_context import MarketContext, NEUTRAL_MARKET
from detection.security_context import SecurityContext
from features import ExtractionWindow, Transaction, extract
from scoring import ScoreResult
from slashing import (
    ConsensusPolicy,
    SingleNodeConsensus,
    SlashDecision,
    evaluate_slash,
    verdict_from_score,
)

logger = logging.getLogger("helixor.epoch_runner")


# =============================================================================
# Inputs — one agent's epoch data
# =============================================================================

@dataclass(frozen=True, slots=True)
class AgentEpochInput:
    """
    Everything the runner needs to score ONE agent for an epoch.

    `baseline_transactions` build the agent's baseline; `current_transactions`
    are the epoch window being scored against it. The three contexts
    (security / market / consistency) carry the registration + cohort data
    the stateful detectors need; all default to empty/neutral.
    """
    agent_wallet:          str
    baseline_transactions: Sequence[Transaction]
    current_transactions:  Sequence[Transaction]
    baseline_window:       ExtractionWindow
    current_window:        ExtractionWindow
    security_context:      SecurityContext = field(default_factory=SecurityContext)
    market_context:        MarketContext = NEUTRAL_MARKET
    consistency_context:   ConsistencyContext = field(default_factory=ConsistencyContext)
    # The agent's previous epoch score, if any — engages the delta guard rail.
    previous_score:        int | None = None


# =============================================================================
# Outputs
# =============================================================================

@dataclass(frozen=True, slots=True)
class AgentEpochResult:
    """The outcome of scoring one agent: the V2 score + the submission record."""
    agent_wallet:  str
    score_result:  ScoreResult
    submitted:     bool
    submission:    object | None = None     # CommitResult, or a test stub, or None
    error:         str = ""
    # ── Day 22: the slash-evaluation outcome ────────────────────────────────
    # The tiered slash decision for this agent. None only if scoring failed
    # (no ScoreResult to evaluate).
    slash_decision: SlashDecision | None = None
    # True if this agent was slashed on-chain this epoch.
    slashed:        bool = False
    # The slash submission record (a SlashResult, a test stub, or None).
    slash_submission: object | None = None


@dataclass(frozen=True, slots=True)
class EpochReport:
    """The outcome of a whole epoch run."""
    epoch_id:        int
    computed_at:     datetime
    results:         tuple[AgentEpochResult, ...]

    @property
    def agent_count(self) -> int:
        return len(self.results)

    @property
    def submitted_count(self) -> int:
        return sum(1 for r in self.results if r.submitted)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if r.error)

    @property
    def slashed_count(self) -> int:
        """How many agents were slashed on-chain this epoch."""
        return sum(1 for r in self.results if r.slashed)

    def by_wallet(self, wallet: str) -> AgentEpochResult | None:
        for r in self.results:
            if r.agent_wallet == wallet:
                return r
        return None


# =============================================================================
# The score-submission seam
# =============================================================================

# A submission function takes a wallet + its ScoreResult and returns a
# submission record (anything truthy = submitted). The runner never calls
# the chain directly — it goes through whatever submit_fn it is given.
SubmitFn = Callable[[str, ScoreResult], object]


# A slash function takes a wallet + the SlashDecision and executes the slash
# on-chain (via the slash-authority execute_slash instruction), returning a
# slash record (anything truthy = slashed). Like SubmitFn it is INJECTED:
# production wires the real on-chain path, tests pass a recording stub. The
# runner only calls slash_fn when a SlashDecision says should_slash — so a
# non-slashing epoch never touches it.
SlashFn = Callable[[str, SlashDecision], object]


def make_onchain_submitter(commit_config) -> SubmitFn:
    """
    Build the PRODUCTION submission function — the one that goes through the
    real, unchanged on-chain path.

    NOTE: a dedicated `submit_score` instruction is Phase-3 work. Until it
    lands, the score's on-chain anchor is the committed baseline hash, so
    this routes through `submit_baseline_commitment` (Day 3). When the
    dedicated instruction exists, only this function changes — the runner
    does not.
    """
    import asyncio

    from oracle.commit_baseline import submit_baseline_commitment

    def _submit(wallet: str, score_result: ScoreResult) -> object:
        # The on-chain anchor today is the baseline commitment. The score
        # itself is carried in the off-chain `agent_scores` table (migration
        # 0008) keyed by the same baseline_stats_hash.
        raise NotImplementedError(
            "live on-chain score submission requires a running validator + "
            "the Phase-3 submit_score instruction; use a recording submit_fn "
            "for tests, or wire submit_baseline_commitment for baseline anchoring"
        )

    return _submit


# =============================================================================
# The epoch runner
# =============================================================================

def score_agent(
    agent_input: AgentEpochInput,
    registry:    DetectorRegistry,
    *,
    computed_at: datetime,
) -> ScoreResult:
    """
    Run the full V2 pipeline for ONE agent:
        baseline txs   -> compute_baseline
        current txs    -> extract features
        (features, baseline, contexts) -> V2 detection engine -> ScoreResult

    Pure + deterministic given its inputs. Does NOT submit — see run_epoch.
    """
    baseline = compute_baseline(
        agent_input.agent_wallet,
        list(agent_input.baseline_transactions),
        agent_input.baseline_window,
        computed_at=computed_at,
    )
    features = extract(
        list(agent_input.current_transactions),
        agent_input.current_window,
    )

    # The stateful detectors need their contexts. The registry's default
    # detectors are context-free; to honour per-agent context we build a
    # per-agent registry overlaying the three stateful detectors.
    agent_registry = _registry_with_contexts(
        registry,
        security_context=agent_input.security_context,
        market_context=agent_input.market_context,
        consistency_context=agent_input.consistency_context,
    )

    return run_detection_engine(
        features,
        baseline,
        agent_registry,
        previous_score=agent_input.previous_score,
        computed_at=computed_at,
    )


def run_epoch(
    epoch_id:     int,
    agent_inputs: Iterable[AgentEpochInput],
    *,
    submit_fn:    SubmitFn,
    slash_fn:     SlashFn | None = None,
    consensus:    ConsensusPolicy | None = None,
    node_id:      str = "oracle-node-0",
    registry:     DetectorRegistry | None = None,
    computed_at:  datetime | None = None,
) -> EpochReport:
    """
    Run one scoring epoch over a set of agents.

    Per agent the pipeline is now THREE steps:
        1. SCORE   — run the V2 detection engine -> ScoreResult.
        2. SUBMIT  — submit the score via `submit_fn`.
        3. SLASH   — evaluate the tiered slash decision; if it says
                     should_slash, execute the slash via `slash_fn`.

    The slash step (Day 22) connects detection to the slash-authority
    program. It is CONSERVATIVE: a merely-degrading agent (a low score with
    no confirmed security compromise) is NOT slashed — the low score is the
    consequence. Only a security-dimension IMMEDIATE_RED that the oracle
    cluster CONFIRMS triggers a slash. See slashing/evaluator.py.

    `slash_fn` is the on-chain execute_slash seam — like `submit_fn`, it is
    injected (production wires the real instruction; tests pass a recording
    stub). If `slash_fn` is None the runner still EVALUATES the slash
    decision (it appears on each result) but does not execute — useful for
    a dry run.

    `consensus` is the ConsensusPolicy that decides whether a security
    flag is cluster-confirmed; it defaults to SingleNodeConsensus (today's
    single-node deployment). `node_id` labels this node's verdict.

    A failure in ANY step for one agent is contained — it becomes an error
    on that agent's result and the epoch continues.

    Deterministic given (agent_inputs, registry, consensus, computed_at)
    and deterministic submit_fn / slash_fn.
    """
    reg = registry if registry is not None else default_registry()
    ts = computed_at or datetime.now(timezone.utc)
    consensus_policy = consensus if consensus is not None else SingleNodeConsensus()

    results: list[AgentEpochResult] = []
    for agent_input in agent_inputs:
        wallet = agent_input.agent_wallet

        # ── 1. Score ────────────────────────────────────────────────────────
        try:
            score_result = score_agent(agent_input, reg, computed_at=ts)
        except Exception as exc:                       # noqa: BLE001
            logger.error("epoch %d: scoring failed for %s: %s",
                         epoch_id, wallet, exc)
            results.append(AgentEpochResult(
                agent_wallet=wallet, score_result=None,    # type: ignore[arg-type]
                submitted=False, error=f"scoring failed: {exc}",
            ))
            continue

        # ── 2. Submit ───────────────────────────────────────────────────────
        try:
            submission = submit_fn(wallet, score_result)
        except Exception as exc:                       # noqa: BLE001
            logger.error("epoch %d: submission failed for %s: %s",
                         epoch_id, wallet, exc)
            results.append(AgentEpochResult(
                agent_wallet=wallet, score_result=score_result,
                submitted=False, error=f"submission failed: {exc}",
            ))
            continue

        # ── 3. Slash evaluation ─────────────────────────────────────────────
        # Derive this node's verdict, run it through the consensus policy,
        # then make the tiered slash decision. The decision is always
        # computed (and recorded); whether it is ACTED ON depends on
        # should_slash and on slash_fn being provided.
        try:
            verdict = verdict_from_score(node_id, score_result)
            consensus_result = consensus_policy.evaluate([verdict])
            decision = evaluate_slash(
                score_result, consensus_result, agent_wallet=wallet,
            )
        except Exception as exc:                       # noqa: BLE001
            logger.error("epoch %d: slash evaluation failed for %s: %s",
                         epoch_id, wallet, exc)
            results.append(AgentEpochResult(
                agent_wallet=wallet, score_result=score_result,
                submitted=bool(submission), submission=submission,
                error=f"slash evaluation failed: {exc}",
            ))
            continue

        # ── 3b. Execute the slash, if the decision says so ──────────────────
        slashed = False
        slash_submission: object | None = None
        slash_error = ""
        if decision.should_slash and slash_fn is not None:
            try:
                slash_submission = slash_fn(wallet, decision)
                slashed = bool(slash_submission)
                logger.info("epoch %d: slashed %s — %s",
                            epoch_id, wallet, decision.reason)
            except Exception as exc:                   # noqa: BLE001
                logger.error("epoch %d: slash execution failed for %s: %s",
                             epoch_id, wallet, exc)
                slash_error = f"slash execution failed: {exc}"
        elif decision.should_slash:
            # A slash was warranted but no slash_fn was given — dry run.
            logger.info("epoch %d: slash WARRANTED for %s (no slash_fn — "
                        "not executed): %s", epoch_id, wallet, decision.reason)

        results.append(AgentEpochResult(
            agent_wallet=wallet, score_result=score_result,
            submitted=bool(submission), submission=submission,
            error=slash_error,
            slash_decision=decision,
            slashed=slashed,
            slash_submission=slash_submission,
        ))

    return EpochReport(epoch_id=epoch_id, computed_at=ts, results=tuple(results))


# =============================================================================
# Per-agent registry overlay
# =============================================================================

def _registry_with_contexts(
    base_registry:       DetectorRegistry,
    *,
    security_context:    SecurityContext,
    market_context:      MarketContext,
    consistency_context: ConsistencyContext,
) -> DetectorRegistry:
    """
    Build a registry whose three STATEFUL detectors (security, performance,
    consistency) carry this agent's contexts, while the two stateless ones
    (drift, anomaly) are reused from the base registry unchanged.

    This is how per-agent cohort / market / domain context reaches the
    detectors without breaking the fixed `Detector.score(features, baseline)`
    Protocol — the context is bound at detector construction.
    """
    from detection.consistency import ConsistencyDetector
    from detection.performance import PerformanceDetector
    from detection.registry import DetectorRegistry as _Registry
    from detection.security import SecurityDetector
    from detection.types import DimensionId

    return _Registry({
        DimensionId.DRIFT:       base_registry.get(DimensionId.DRIFT),
        DimensionId.ANOMALY:     base_registry.get(DimensionId.ANOMALY),
        DimensionId.SECURITY:    SecurityDetector(security_context),
        DimensionId.PERFORMANCE: PerformanceDetector(market_context),
        DimensionId.CONSISTENCY: ConsistencyDetector(consistency_context),
    })
