"""
scoring/window.py — compute the CURRENT 7-day window stats.

Same shape as baseline signals, but over a shorter rolling window.
Unlike baseline (smooth, 30 days, recomputed daily), the window is the
agent's *recent* behavior — what they've done since the last scoring epoch.

Pure functions. No I/O.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from scoring.signals import TransactionRecord


# Default window — matches the spec (7 days)
DEFAULT_WINDOW_DAYS = 7

# Below this many txs we don't have enough signal to score reliably.
# Lower than baseline's MIN_TX_COUNT because a 7-day window has 1/4 the
# data of a 30-day window.
DEFAULT_MIN_WINDOW_TX = 5
SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"


@dataclass(frozen=True, slots=True)
class WindowStats:
    """Current 7-day stats. Same three signals as baseline."""

    success_rate:      float       # 0.0 - 1.0
    tx_count:          int         # total in window
    daily_tx_avg:      float       # tx_count / elapsed_active_days
    sol_volatility_mad: int        # MAD over daily |sol_change|
    active_days:       int
    elapsed_days:      float       # actual fractional days from first tx → now
    window_start:      datetime
    window_end:        datetime
    padding_tx_ratio:  float = 0.0  # likely low-signal system-only padding


class InsufficientWindowData(Exception):
    """Window has fewer than min_window_tx transactions."""
    def __init__(self, observed: int, required: int):
        self.observed = observed
        self.required = required
        super().__init__(
            f"Window has {observed} transactions, need at least {required}"
        )


def compute_window(
    transactions:    Iterable[TransactionRecord],
    *,
    window_start:    datetime,
    window_end:      datetime,
    min_window_tx:   int = DEFAULT_MIN_WINDOW_TX,
) -> WindowStats:
    """
    Compute the current-window stats from in-window transactions.

    Args:
        transactions: tx records ALREADY filtered to [window_start, window_end)
        window_start: tz-aware UTC
        window_end:   tz-aware UTC
        min_window_tx: refuse to score with fewer than this many txs

    Raises:
        InsufficientWindowData if window has too few transactions.
    """
    txs = list(transactions)

    if len(txs) < min_window_tx:
        raise InsufficientWindowData(len(txs), min_window_tx)

    # ── Signal 1: success rate ───────────────────────────────────────────────
    successes = sum(1 for tx in txs if tx.success)
    success_rate = successes / len(txs)
    padding_like = sum(1 for tx in txs if _is_padding_like(tx.program_ids, tx.sol_change))
    padding_tx_ratio = padding_like / len(txs)

    # ── Group by UTC day ─────────────────────────────────────────────────────
    daily_count: dict = defaultdict(int)
    daily_sol_abs: dict = defaultdict(int)
    for tx in txs:
        d = tx.block_time.date()
        daily_count[d]   += 1
        daily_sol_abs[d] += abs(tx.sol_change)

    active_days = len(daily_count)

    # ── Daily tx average — divide by ELAPSED days, not window length ─────────
    # If the agent was registered 3 days ago, dividing by 7 understates
    # their daily activity. Use elapsed time from earliest tx → window_end.
    earliest_tx_time = min(tx.block_time for tx in txs)
    elapsed_seconds  = (window_end - earliest_tx_time).total_seconds()
    elapsed_days     = max(elapsed_seconds / 86400.0, 1.0)  # min 1 day to avoid div-by-zero
    daily_tx_avg     = len(txs) / elapsed_days

    # ── SOL volatility (MAD, robust) ─────────────────────────────────────────
    if active_days >= 2:
        daily_sol_values = list(daily_sol_abs.values())
        median_sol = statistics.median(daily_sol_values)
        deviations = [abs(v - median_sol) for v in daily_sol_values]
        sol_volatility_mad = int(statistics.median(deviations))
    else:
        # Single active day — no volatility measurable.
        # 0 means "indistinguishable from baseline" for the scoring engine.
        sol_volatility_mad = 0

    return WindowStats(
        success_rate       = round(success_rate, 6),
        tx_count           = len(txs),
        daily_tx_avg       = round(daily_tx_avg, 4),
        sol_volatility_mad = sol_volatility_mad,
        active_days        = active_days,
        elapsed_days       = round(elapsed_days, 2),
        window_start       = window_start,
        window_end         = window_end,
        padding_tx_ratio   = round(padding_tx_ratio, 6),
    )


def _is_padding_like(program_ids: tuple[str, ...], sol_change: int) -> bool:
    if not program_ids:
        return True
    return set(program_ids).issubset({SYSTEM_PROGRAM_ID}) and abs(sol_change) <= 10_000
