"""
tests/scoring/conftest.py — baseline fixture for composite tests.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from baseline import compute_baseline
from features import ExtractionWindow, Transaction


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def baseline():
    """A real v2 BaselineStats — gives compute_composite_score a real stats_hash to stamp."""
    txs = []
    for day in range(30):
        for k in range(5):
            idx = day * 5 + k
            txs.append(Transaction(
                signature=f"S{idx:08d}".ljust(64, "x"),
                slot=100_000_000 + idx,
                block_time=REF_END - timedelta(hours=day * 24 + k * 2 + 1.0),
                success=(idx % 20) != 0,
                program_ids=("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",),
                sol_change=1_000_000 if k % 2 == 0 else -400_000,
                fee=5000,
                priority_fee=0,
                compute_units=200_000,
                counterparty=f"cp{idx % 7}",
            ))
    return compute_baseline(
        "11111111111111111111111111111112",
        txs,
        ExtractionWindow.ending_at(REF_END, days=30),
        computed_at=REF_END,
    )
