"""
tests/features/test_determinism.py — purity + determinism.

extract() must be a pure function: same inputs → byte-identical output, every
time, regardless of input ordering or call count. This is load-bearing for
the Phase 4 oracle cluster (3 nodes must compute identical vectors).
"""

from __future__ import annotations

import random

from features import extract
from features.types import ExtractionWindow
from tests.features.conftest import (
    PROG_LEND, PROG_STAKE, PROG_SWAP, PROG_TRANSFER, PROG_UNKNOWN,
    REF_END, make_tx,
)


def _diverse_txs():
    """A spread of transactions touching every feature group."""
    return [
        make_tx(offset_hours=1.0,  programs=(PROG_SWAP,),     sol_change=1_000_000,
                fee=5000, priority_fee=1000, compute_units=200_000,
                counterparty="cpA", success=True),
        make_tx(offset_hours=3.5,  programs=(PROG_LEND,),     sol_change=-500_000,
                fee=8000, compute_units=150_000, counterparty="cpB", success=True),
        make_tx(offset_hours=10.0, programs=(PROG_TRANSFER,), sol_change=-200_000,
                fee=5000, counterparty="cpA", success=False),
        make_tx(offset_hours=26.0, programs=(PROG_STAKE, PROG_SWAP), sol_change=2_000_000,
                fee=12000, priority_fee=5000, compute_units=400_000,
                counterparty="cpC", success=True),
        make_tx(offset_hours=80.0, programs=(PROG_UNKNOWN,),  sol_change=0,
                fee=5000, success=True),
        make_tx(offset_hours=200.0, programs=(PROG_SWAP,),    sol_change=750_000,
                fee=6000, counterparty="cpB", success=True),
    ]


def test_same_input_same_output():
    txs = _diverse_txs()
    window = ExtractionWindow.ending_at(REF_END, 30)
    fv1 = extract(txs, window)
    fv2 = extract(txs, window)
    assert fv1 == fv2
    assert fv1.to_list() == fv2.to_list()


def test_input_order_does_not_matter():
    """Shuffling the input transaction list must not change the output."""
    txs = _diverse_txs()
    window = ExtractionWindow.ending_at(REF_END, 30)
    canonical = extract(txs, window)

    rng = random.Random(42)
    for _ in range(10):
        shuffled = txs[:]
        rng.shuffle(shuffled)
        assert extract(shuffled, window) == canonical


def test_repeated_calls_are_stable():
    txs = _diverse_txs()
    window = ExtractionWindow.ending_at(REF_END, 30)
    first = extract(txs, window)
    for _ in range(50):
        assert extract(txs, window) == first


def test_extract_does_not_mutate_input():
    txs = _diverse_txs()
    window = ExtractionWindow.ending_at(REF_END, 30)
    snapshot = [
        (t.signature, t.slot, t.block_time, t.success, t.program_ids,
         t.sol_change, t.fee, t.priority_fee, t.compute_units, t.counterparty)
        for t in txs
    ]
    extract(txs, window)
    after = [
        (t.signature, t.slot, t.block_time, t.success, t.program_ids,
         t.sol_change, t.fee, t.priority_fee, t.compute_units, t.counterparty)
        for t in txs
    ]
    assert snapshot == after
    assert len(txs) == 6  # list itself untouched


def test_transactions_outside_window_are_ignored():
    window = ExtractionWindow.ending_at(REF_END, 7)   # 7-day window
    inside  = [make_tx(offset_hours=h) for h in (1, 50, 100, 160)]   # all < 7d
    outside = [make_tx(offset_hours=h) for h in (200, 500, 1000)]    # all > 7d
    fv_inside_only = extract(inside, window)
    fv_combined    = extract(inside + outside, window)
    assert fv_inside_only == fv_combined


def test_tie_breaking_is_total():
    """Transactions sharing block_time must still sort deterministically."""
    window = ExtractionWindow.ending_at(REF_END, 30)
    # Three txs at the SAME timestamp, distinguished only by slot + sig.
    same_time = [
        make_tx(offset_hours=5.0, slot=3, sig="C".ljust(64, "x")),
        make_tx(offset_hours=5.0, slot=1, sig="A".ljust(64, "x")),
        make_tx(offset_hours=5.0, slot=2, sig="B".ljust(64, "x")),
    ]
    a = extract(same_time, window)
    b = extract(list(reversed(same_time)), window)
    assert a == b
