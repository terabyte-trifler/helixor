"""
tests/detection/conftest.py — fixtures that give detector tests REAL inputs.

Day-4 detectors are stubs that ignore their inputs, so any valid
(FeatureVector, BaselineStats) pair works. We build them through the actual
Day-1 extract() + Day-2 compute_baseline() so the tests also serve as a
final integration smoke check across all three days.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from baseline import BaselineStats, compute_baseline
from features import ExtractionWindow, Transaction, extract


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
PROG_SWAP = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"


def _make_txs(*, days: int = 30, txs_per_day: int = 5, success_rate: float = 0.95):
    txs = []
    fail_every = max(2, int(round(1.0 / max(1e-9, 1.0 - success_rate))))
    for day in range(days):
        for k in range(txs_per_day):
            idx = day * txs_per_day + k
            txs.append(Transaction(
                signature=f"S{idx:08d}".ljust(64, "x"),
                slot=100_000_000 + idx,
                block_time=REF_END - timedelta(hours=day * 24 + k * 2 + 1.0),
                success=(idx % fail_every) != 0,
                program_ids=(PROG_SWAP,),
                sol_change=1_000_000 if k % 2 == 0 else -400_000,
                fee=5000,
                priority_fee=1000 if k % 3 == 0 else 0,
                compute_units=200_000,
                counterparty=f"cp{idx % 7}",
            ))
    return txs


@pytest.fixture
def window_30d() -> ExtractionWindow:
    return ExtractionWindow.ending_at(REF_END, days=30)


@pytest.fixture
def features(window_30d):
    """A real 100-feature vector from the Day-1 extractor."""
    return extract(_make_txs(), window_30d)


@pytest.fixture
def baseline(window_30d) -> BaselineStats:
    """A real v2 BaselineStats from the Day-2 engine."""
    return compute_baseline(
        agent_wallet="11111111111111111111111111111112",
        transactions=_make_txs(),
        window=window_30d,
        computed_at=REF_END,
    )
