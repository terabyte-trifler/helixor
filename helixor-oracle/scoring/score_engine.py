"""
scoring/score_engine.py — orchestrator for full scoring pipeline.

This is what Day 7's epoch_runner imports. It:
  1. Loads (or computes) the baseline for an agent
  2. Computes the current 7-day window from agent_transactions
  3. Reads the previous score for the guard rail
  4. Runs the pure scoring engine
  5. Persists the score (current + history)

Public API:
    await score_one(conn, agent_wallet)         → ScoreResult or None
    await score_all_due(conn)                    → outcomes dict
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import asyncpg
import structlog

from scoring import baseline_engine, repo as baseline_repo, score_repo
from scoring.engine import (
    DEFAULT_WEIGHTS,
    IncompatibleAlgoVersion,
    ScoreResult,
    ScoringWeights,
    score_agent,
)
from scoring.window import (
    DEFAULT_MIN_WINDOW_TX,
    DEFAULT_WINDOW_DAYS,
    InsufficientWindowData,
    compute_window,
)

log = structlog.get_logger(__name__)


# =============================================================================
# Score one agent end-to-end
# =============================================================================

async def score_one(
    conn:           asyncpg.Connection,
    agent_wallet:   str,
    *,
    window_days:    int = DEFAULT_WINDOW_DAYS,
    min_window_tx:  int = DEFAULT_MIN_WINDOW_TX,
    weights:        ScoringWeights = DEFAULT_WEIGHTS,
) -> ScoreResult | None:
    """
    Compute, store, and return the score for one agent.

    Returns None when:
      - Agent has no baseline yet
      - Window has insufficient data

    Raises (caller decides):
      - IncompatibleAlgoVersion (baseline algo version unsupported)
      - asyncpg errors (DB-level failures)
    """
    bound_log = log.bind(agent=agent_wallet[:12] + "...")

    # ── 1. Load baseline ─────────────────────────────────────────────────────
    baseline = await baseline_repo.get_baseline(conn, agent_wallet)
    if baseline is None:
        bound_log.info("score_skipped_no_baseline")
        return None

    # ── 2. Compute current 7-day window ──────────────────────────────────────
    window_end   = datetime.now(tz=timezone.utc)
    window_start = window_end - timedelta(days=window_days)

    txs = await baseline_repo.fetch_window_transactions(
        conn, agent_wallet,
        window_start=window_start,
        window_end=window_end,
    )

    try:
        window = compute_window(
            txs,
            window_start=window_start,
            window_end=window_end,
            min_window_tx=min_window_tx,
        )
    except InsufficientWindowData as e:
        bound_log.info("score_skipped_insufficient_window",
                       observed=e.observed, required=e.required)
        return None

    # ── 3. Read previous score for guard rail ────────────────────────────────
    previous_score = await score_repo.get_current_score(conn, agent_wallet)

    # ── 4. Run pure scoring engine ───────────────────────────────────────────
    try:
        result = score_agent(
            window,
            baseline,
            previous_score=previous_score,
            weights=weights,
        )
    except IncompatibleAlgoVersion as e:
        bound_log.error("score_skipped_incompatible_baseline",
                        baseline_version=baseline.algo_version)
        raise

    # ── 5. Persist ───────────────────────────────────────────────────────────
    await score_repo.upsert_score(conn, agent_wallet, result)

    bound_log.info(
        "score_computed",
        score=result.score,
        alert=result.alert,
        anomaly=result.anomaly_flag,
        guard_rail=result.breakdown.guard_rail_applied,
        sr_pts=result.breakdown.success_rate_score,
        consistency_pts=result.breakdown.consistency_score,
        stability_pts=result.breakdown.stability_score,
    )

    return result


# =============================================================================
# Batch score all agents due for scoring (Day 7 epoch driver)
# =============================================================================

async def score_all_due(
    conn:    asyncpg.Connection,
    *,
    weights: ScoringWeights = DEFAULT_WEIGHTS,
) -> dict[str, str]:
    """
    Find all agents whose score is due, compute new scores, persist.
    Returns dict mapping agent_wallet → outcome.

    Outcomes:
      "scored"          — successfully scored
      "no_baseline"     — agent has no baseline yet
      "insufficient_tx" — window has too few transactions
      "incompatible"    — baseline algo version unsupported
      "error"           — unexpected failure (logged separately)
    """
    targets = await score_repo.find_agents_due_for_scoring(conn)
    log.info("score_batch_starting", count=len(targets))

    outcomes: dict[str, str] = {}

    for agent in targets:
        try:
            result = await score_one(conn, agent, weights=weights)
            outcomes[agent] = "scored" if result else "no_baseline_or_insufficient_window"
        except IncompatibleAlgoVersion:
            outcomes[agent] = "incompatible"
        except Exception as e:
            outcomes[agent] = "error"
            log.error(
                "score_failed",
                agent=agent[:12] + "...",
                error=str(e),
            )

    summary: dict[str, int] = {}
    for outcome in outcomes.values():
        summary[outcome] = summary.get(outcome, 0) + 1

    log.info("score_batch_complete", **summary)
    return outcomes
