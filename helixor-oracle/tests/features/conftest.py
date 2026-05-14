"""
tests/features/conftest.py — shared fixtures + transaction builders.

The builders produce deterministic Transaction objects so tests can assert
exact feature values, not ranges.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from features.types import ExtractionWindow, Transaction


# A fixed reference instant — all test windows hang off this so nothing
# depends on the wall clock.
REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


# Well-known program IDs reused across tests.
PROG_SWAP     = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
PROG_LEND     = "So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo"
PROG_STAKE    = "Stake11111111111111111111111111111111111111"
PROG_TRANSFER = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
PROG_UNKNOWN  = "UnknownProgram1111111111111111111111111111"


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
    """
    Build a Transaction at `end - offset_hours`. Larger offset = older.

    slot + sig default to deterministic values derived from the offset so
    canonical sorting is stable across builds.
    """
    block_time = end - timedelta(hours=offset_hours)
    derived_slot = slot if slot is not None else 100_000_000 + int(offset_hours * 1000)
    derived_sig  = sig if sig is not None else f"SIG{int(offset_hours*1000):08d}".ljust(64, "x")
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


@pytest.fixture
def window_30d() -> ExtractionWindow:
    """A 30-day window ending at the reference instant."""
    return ExtractionWindow.ending_at(REF_END, days=30)


@pytest.fixture
def window_7d() -> ExtractionWindow:
    return ExtractionWindow.ending_at(REF_END, days=7)


@pytest.fixture
def empty_txs() -> list[Transaction]:
    return []
