"""
oracle/epoch_runner.py — the daily scoring + on-chain submission loop.

What it does each pass:
  1. Find agents whose score is unsynced (Day 6's find_unsynced_scores)
  2. For each: submit update_score on-chain via signed tx
  3. On success: mark_score_onchain so we don't resubmit
  4. On TooFrequent: silently skip (cooldown is by design)
  5. On Paused/Unauthorized: log loudly, halt the pass (operator intervention)
  6. On TransientError: retry the agent up to 3 times with exponential backoff

Run as a long-lived service (docker-compose) or one-shot (cron).

Run as service:    python -m oracle.epoch_runner
Run as one-shot:   python -m oracle.epoch_runner --once
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import structlog
from solana.rpc.async_api import AsyncClient
from solders.pubkey import Pubkey

from indexer import db
from indexer.config import settings
from oracle.submit import (
    DeltaTooLarge,
    Paused,
    SubmissionError,
    SubmitResult,
    TooFrequent,
    TransientError,
    Unauthorized,
    load_oracle_keypair,
    submit_score_update,
)
from scoring import score_engine, score_repo

log = structlog.get_logger(__name__)


# How often to wake when running as a service (vs --once mode)
EPOCH_INTERVAL_SECONDS = 60 * 60        # 1 hour — checks for unsynced every hour

# Per-agent retry budget for transient errors
PER_AGENT_RETRY_LIMIT = 3
PER_AGENT_RETRY_BACKOFF_SECONDS = (5, 15, 45)

# Hard limit on how many agents we'll process in a single pass (to bound runtime)
MAX_AGENTS_PER_PASS = 100


# =============================================================================
# Outcome tracking
# =============================================================================

OUTCOMES = (
    "submitted", "too_frequent", "delta_too_large",
    "unauthorized", "paused", "deactivated",
    "transient_failed", "no_score", "invalid_wallet",
)


# =============================================================================
# Single-agent submission with retry
# =============================================================================

async def submit_with_retry(
    rpc, program_id, oracle_kp, conn, agent_wallet,
) -> tuple[str, SubmitResult | None]:
    """
    Submit one agent's score, retrying on transient errors only.
    Returns (outcome_label, SubmitResult-or-None).
    """
    score_row = await score_repo.get_full_current_score(conn, agent_wallet)
    if score_row is None:
        return ("no_score", None)

    try:
        Pubkey.from_string(agent_wallet)
    except ValueError:
        bound_log = log.bind(agent=agent_wallet[:12] + "...")
        bound_log.warning("invalid_agent_wallet_skipping")
        return ("invalid_wallet", None)

    # Reconstruct ScoreResult-shaped object for submit (we only need the
    # fields the on-chain payload uses).
    from scoring.engine import ScoreBreakdown, ScoreResult
    result = ScoreResult(
        score                 = score_row["score"],
        alert                 = score_row["alert"],
        anomaly_flag          = score_row["anomaly_flag"],
        breakdown             = ScoreBreakdown(
            success_rate_score = score_row["success_rate_score"],
            consistency_score  = score_row["consistency_score"],
            stability_score    = score_row["stability_score"],
            raw_score          = score_row["raw_score"],
            guard_rail_applied = score_row["guard_rail_applied"],
            consistency_ratio  = 0.0, stability_ratio = 0.0,
        ),
        window_success_rate   = float(score_row["window_success_rate"]),
        window_tx_count       = score_row["window_tx_count"],
        window_sol_volatility = score_row["window_sol_volatility"],
        baseline_hash         = score_row["baseline_hash"],
        baseline_algo_version = score_row["baseline_algo_version"],
        scoring_algo_version  = score_row["scoring_algo_version"],
        weights_version       = score_row["weights_version"],
    )

    bound_log = log.bind(agent=agent_wallet[:12] + "...")

    for attempt in range(PER_AGENT_RETRY_LIMIT):
        try:
            sub_result = await submit_score_update(
                rpc, program_id, oracle_kp, agent_wallet, result,
            )
            await score_repo.mark_score_onchain(conn, agent_wallet, sub_result.tx_signature)
            bound_log.info(
                "score_synced_onchain",
                tx_sig=sub_result.tx_signature[:20] + "...",
                slot=sub_result.slot,
            )
            return ("submitted", sub_result)

        except TooFrequent:
            # 23h cooldown is by design — silently skip until next pass
            bound_log.debug("skipped_cooldown_active")
            return ("too_frequent", None)

        except DeltaTooLarge as e:
            bound_log.error("guard_rail_triggered", error=str(e))
            # Don't retry — investigation needed. Score stays unsynced.
            return ("delta_too_large", None)

        except Unauthorized:
            bound_log.error("oracle_unauthorized")
            # Halt this entire pass — config rotation needed
            raise

        except Paused:
            bound_log.error("oracle_paused")
            raise

        except SubmissionError as e:
            if "agent_deactivated" in str(e):
                bound_log.warning("agent_deactivated_skipping")
                return ("deactivated", None)
            # Other unrecognised submission error — treat as transient
            bound_log.warning("unknown_submission_error", error=str(e))

        except TransientError as e:
            if attempt + 1 < PER_AGENT_RETRY_LIMIT:
                wait = PER_AGENT_RETRY_BACKOFF_SECONDS[attempt]
                bound_log.warning(
                    "submit_transient_failure_retrying",
                    attempt=attempt + 1, wait_seconds=wait, error=str(e)[:100],
                )
                await asyncio.sleep(wait)
            else:
                bound_log.error(
                    "submit_failed_giving_up",
                    error=str(e)[:200], attempts=PER_AGENT_RETRY_LIMIT,
                )
                return ("transient_failed", None)

    return ("transient_failed", None)


# =============================================================================
# One epoch pass
# =============================================================================

async def run_one_pass(rpc, program_id, oracle_kp) -> dict[str, int]:
    """One pass through unsynced agents. Returns outcome counts."""
    pool = await db.get_pool()

    counts: dict[str, int] = {k: 0 for k in OUTCOMES}

    async with pool.acquire() as conn:
        # First, ensure scores are computed (Day 6) for all agents that need it
        await score_engine.score_all_due(conn)

        # Then find scores not yet on-chain
        unsynced = await score_repo.find_unsynced_scores(conn)

    if not unsynced:
        log.info("epoch_pass_no_work")
        return counts

    log.info("epoch_pass_starting", unsynced_count=len(unsynced))

    # Bound work per pass
    targets = unsynced[:MAX_AGENTS_PER_PASS]

    for agent in targets:
        async with pool.acquire() as conn:
            try:
                outcome, _ = await submit_with_retry(
                    rpc, program_id, oracle_kp, conn, agent,
                )
                counts[outcome] = counts.get(outcome, 0) + 1
            except (Unauthorized, Paused) as e:
                # These halt the pass — operator intervention needed
                log.error("epoch_pass_halted", reason=type(e).__name__)
                break

    log.info("epoch_pass_complete", **counts)
    return counts


# =============================================================================
# Main loop
# =============================================================================

async def setup() -> tuple[AsyncClient, Pubkey, "Keypair"]:
    """Build the long-lived RPC client + program id handle."""
    oracle_kp = load_oracle_keypair()

    # Ensure oracle has SOL for cert rents + tx fees
    rpc = AsyncClient(settings.solana_rpc_url, commitment="confirmed")
    bal = await rpc.get_balance(oracle_kp.pubkey())
    log.info("oracle_node_starting", pubkey=str(oracle_kp.pubkey()),
             balance_sol=bal.value / 1_000_000_000 if bal.value else 0)

    if (bal.value or 0) < 100_000_000:  # < 0.1 SOL
        log.warning("oracle_low_balance",
                    balance_lamports=bal.value,
                    hint="Top up the oracle wallet or it can't pay tx fees")

    program_id = Pubkey.from_string(settings.health_oracle_program_id)

    return rpc, program_id, oracle_kp


async def loop_forever():
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
    )

    await db.init_pool()
    rpc, program_id, oracle_kp = await setup()

    log.info("epoch_runner_starting", interval_s=EPOCH_INTERVAL_SECONDS)

    try:
        while True:
            try:
                await run_one_pass(rpc, program_id, oracle_kp)
            except Exception as e:
                log.error("epoch_iteration_failed", error=str(e))
            await asyncio.sleep(EPOCH_INTERVAL_SECONDS)
    finally:
        await rpc.close()
        await db.close_pool()


async def run_once():
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
    )

    await db.init_pool()
    rpc, program_id, oracle_kp = await setup()

    try:
        counts = await run_one_pass(rpc, program_id, oracle_kp)
        log.info("epoch_runner_one_shot_done", **counts)
    finally:
        await rpc.close()
        await db.close_pool()


def main() -> None:
    p = argparse.ArgumentParser(description="Helixor epoch runner")
    p.add_argument("--once", action="store_true",
                   help="Run one pass and exit (default: run forever)")
    args = p.parse_args()

    try:
        if args.once:
            asyncio.run(run_once())
        else:
            asyncio.run(loop_forever())
    except KeyboardInterrupt:
        log.info("epoch_runner_stopped_by_user")


if __name__ == "__main__":
    main()
