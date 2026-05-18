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
through the existing `oracle/submit.py` update_score machinery.

WHY THE SUBMISSION FUNCTION IS INJECTED
---------------------------------------
`run_epoch` takes its submission step as a parameter (`submit_fn`). In
production that is built by `make_onchain_submitter()`, which calls the real
`update_score` transaction submitter. In tests it is a recording stub. This
keeps the runner fully testable without a live validator while guaranteeing
the production path remains the same on-chain machinery.

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


def make_onchain_submitter(commit_config) -> SubmitFn:
    """
    Build the PRODUCTION submission function — the one that goes through
    the existing on-chain `update_score` path.

    `commit_config` is accepted for compatibility with the Day-3 baseline
    commit path, but the score submitter reads the current runtime settings
    used by `oracle.submit`: SOLANA_RPC_URL, HEALTH_ORACLE_PROGRAM_ID, and
    ORACLE_KEYPAIR_PATH.
    """
    import asyncio

    from solana.rpc.async_api import AsyncClient

    from oracle.submit import derive_program_id, load_oracle_keypair, submit_score_update
    from indexer.config import settings

    program_id = derive_program_id()
    oracle_kp = load_oracle_keypair()

    def _submit(wallet: str, score_result: ScoreResult) -> object:
        async def _run():
            async with AsyncClient(settings.solana_rpc_url, commitment="confirmed") as rpc:
                return await submit_score_update(
                    rpc, program_id, oracle_kp, wallet, score_result,
                )

        return asyncio.run(_run())

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
    registry:     DetectorRegistry | None = None,
    computed_at:  datetime | None = None,
) -> EpochReport:
    """
    Run one scoring epoch over a set of agents.

    For each agent: run the V2 pipeline, then submit via `submit_fn`. A
    failure scoring or submitting ONE agent is contained — it becomes an
    error on that agent's result and the epoch continues.

    `submit_fn` is the on-chain submission seam — see make_onchain_submitter
    for production, or pass a recording stub in tests.

    Deterministic given (agent_inputs, registry, computed_at) and a
    deterministic submit_fn.
    """
    reg = registry if registry is not None else default_registry()
    ts = computed_at or datetime.now(timezone.utc)

    results: list[AgentEpochResult] = []
    for agent_input in agent_inputs:
        wallet = agent_input.agent_wallet
        # ── Score ───────────────────────────────────────────────────────────
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

        # ── Submit ──────────────────────────────────────────────────────────
        try:
            submission = submit_fn(wallet, score_result)
            results.append(AgentEpochResult(
                agent_wallet=wallet, score_result=score_result,
                submitted=bool(submission), submission=submission,
            ))
        except Exception as exc:                       # noqa: BLE001
            logger.error("epoch %d: submission failed for %s: %s",
                         epoch_id, wallet, exc)
            results.append(AgentEpochResult(
                agent_wallet=wallet, score_result=score_result,
                submitted=False, error=f"submission failed: {exc}",
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
