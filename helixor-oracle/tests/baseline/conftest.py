"""
tests/baseline/conftest.py — shared fixtures for baseline-engine tests.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from features.types import ExtractionWindow, Transaction

# Fixed reference instant so nothing depends on the wall clock.
REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)

PROG_SWAP     = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
PROG_LEND     = "So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo"
PROG_STAKE    = "Stake11111111111111111111111111111111111111"
PROG_TRANSFER = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"


def make_tx(
    *,
    offset_hours:  float,
    success:       bool = True,
    programs:      tuple[str, ...] = (PROG_TRANSFER,),
    sol_change:    int = 0,
    fee:           int = 5000,
    priority_fee:  int = 0,
    compute_units: int = 0,
    counterparty:  str | None = None,
    slot:          int | None = None,
    sig:           str | None = None,
    end:           datetime = REF_END,
) -> Transaction:
    block_time = end - timedelta(hours=offset_hours)
    derived_slot = slot if slot is not None else 100_000_000 + int(offset_hours * 1000)
    derived_sig  = sig if sig is not None else f"SIG{int(offset_hours*1000):010d}".ljust(64, "x")
    return Transaction(
        signature=derived_sig,
        slot=derived_slot,
        block_time=block_time,
        success=success,
        program_ids=programs,
        sol_change=sol_change,
        fee=fee,
        priority_fee=priority_fee,
        compute_units=compute_units,
        counterparty=counterparty,
    )


def make_active_agent_txs(
    *,
    days:            int = 30,
    txs_per_day:     int = 5,
    success_rate:    float = 0.95,
    programs:        tuple[str, ...] = (PROG_SWAP,),
    end:             datetime = REF_END,
) -> list[Transaction]:
    """
    A realistic agent: `txs_per_day` transactions on each of the last `days`
    days, with a deterministic success pattern matching `success_rate`.
    """
    txs: list[Transaction] = []
    for day in range(days):
        for k in range(txs_per_day):
            # spread within the day, deterministic
            offset_hours = day * 24 + (k * 24.0 / txs_per_day) + 1.0
            idx = day * txs_per_day + k
            # deterministic success pattern: every Nth tx fails
            fail_every = max(2, int(round(1.0 / max(1e-9, 1.0 - success_rate))))
            success = (idx % fail_every) != 0
            txs.append(make_tx(
                offset_hours=offset_hours,
                success=success,
                programs=programs,
                sol_change=1_000_000 if k % 2 == 0 else -500_000,
                counterparty=f"cp{idx % 7}",
                end=end,
            ))
    return txs


@pytest.fixture
def window_30d() -> ExtractionWindow:
    return ExtractionWindow.ending_at(REF_END, days=30)
