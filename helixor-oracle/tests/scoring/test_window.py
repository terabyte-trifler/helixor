"""
tests/scoring/test_window.py — unit tests for the 7-day window computation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from scoring.signals import TransactionRecord
from scoring.window import (
    DEFAULT_MIN_WINDOW_TX,
    InsufficientWindowData,
    compute_window,
)


UTC = timezone.utc


def _tx(
    t: datetime,
    success: bool = True,
    sol_change: int = 0,
    program_ids: tuple[str, ...] = (),
) -> TransactionRecord:
    return TransactionRecord(
        block_time=t,
        success=success,
        sol_change=sol_change,
        program_ids=program_ids,
    )


# =============================================================================
# Threshold checks
# =============================================================================

class TestThresholds:

    def test_below_min_raises(self):
        now = datetime.now(tz=UTC)
        txs = [_tx(now - timedelta(hours=i)) for i in range(3)]

        with pytest.raises(InsufficientWindowData) as exc:
            compute_window(
                txs,
                window_start=now - timedelta(days=7),
                window_end=now,
                min_window_tx=5,
            )
        assert exc.value.observed == 3
        assert exc.value.required == 5

    def test_at_threshold_succeeds(self):
        now = datetime.now(tz=UTC)
        txs = [_tx(now - timedelta(hours=i * 12)) for i in range(5)]
        ws = compute_window(
            txs,
            window_start=now - timedelta(days=7),
            window_end=now,
            min_window_tx=5,
        )
        assert ws.tx_count == 5


# =============================================================================
# Stat correctness
# =============================================================================

class TestStats:

    def test_success_rate_calculation(self):
        now = datetime.now(tz=UTC)
        # 8 of 10 succeed = 80%
        txs = [
            _tx(now - timedelta(hours=i * 6), success=(i < 8))
            for i in range(10)
        ]
        ws = compute_window(
            txs,
            window_start=now - timedelta(days=7),
            window_end=now,
        )
        assert ws.success_rate == 0.8
        assert ws.tx_count == 10

    def test_daily_tx_avg_uses_elapsed_not_window_length(self):
        """Agent registered 2 days ago shouldn't be divided by 7."""
        now = datetime.now(tz=UTC)
        # 20 txs over the last 2 days
        txs = []
        for hour_offset in range(20):
            txs.append(_tx(now - timedelta(hours=hour_offset)))

        ws = compute_window(
            txs,
            window_start=now - timedelta(days=7),
            window_end=now,
        )
        # elapsed_days ~= 19/24 ≈ 0.79 → clamped to 1.0 minimum
        # 20 txs / 1.0 day → 20.0 avg
        assert ws.daily_tx_avg >= 19.0  # close to 20 (depending on exact elapsed)
        assert ws.elapsed_days >= 1.0

    def test_volatility_with_single_active_day_is_zero(self):
        """Only one active day → no volatility measurable."""
        now = datetime.now(tz=UTC)
        txs = [_tx(now - timedelta(minutes=i * 5)) for i in range(10)]
        ws = compute_window(
            txs,
            window_start=now - timedelta(days=7),
            window_end=now,
        )
        assert ws.active_days == 1
        assert ws.sol_volatility_mad == 0

    def test_padding_ratio_flags_system_only_micro_transfers(self):
        now = datetime.now(tz=UTC)
        txs = [
            _tx(now - timedelta(hours=i), sol_change=5000,
                program_ids=("11111111111111111111111111111111",))
            for i in range(9)
        ]
        txs.append(_tx(now - timedelta(hours=10), sol_change=500_000,
                       program_ids=("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",)))

        ws = compute_window(
            txs,
            window_start=now - timedelta(days=7),
            window_end=now,
        )

        assert ws.padding_tx_ratio == 0.9
