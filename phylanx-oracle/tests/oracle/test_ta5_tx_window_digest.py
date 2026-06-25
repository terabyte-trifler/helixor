"""
tests/oracle/test_ta5_tx_window_digest.py — TA-5 canonical digest tests.

Pins:
  - Digest is 32 bytes (sha256)
  - Deterministic: same inputs → byte-identical bytes
  - Order-independent: input sequence order doesn't affect digest
  - Field-sensitive: any field change → digest change
  - Window-sensitive: same txs in a different window → different digest
  - Empty window has distinct sentinel, still window-bound
  - Duplicate signatures raise ValueError
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from features import ExtractionWindow, Transaction
from oracle.tx_window_digest import (
    EMPTY_DIGEST,
    compute_tx_window_digest,
)


REF = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
WINDOW = ExtractionWindow.ending_at(REF, days=30)


def _tx(*, sig: str = "S00000001", slot: int = 100, sol_change: int = 1_000_000) -> Transaction:
    return Transaction(
        signature=sig.ljust(64, "x"),
        slot=slot,
        block_time=REF - timedelta(hours=1),
        success=True,
        program_ids=("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",),
        sol_change=sol_change,
        fee=5000,
        priority_fee=0,
        compute_units=200_000,
        counterparty="cp1",
    )


# ----------------------------------------------------------------------------
# Shape + bounds
# ----------------------------------------------------------------------------

def test_digest_is_32_bytes_sha256():
    d = compute_tx_window_digest([_tx()], WINDOW)
    assert isinstance(d, bytes)
    assert len(d) == 32


def test_empty_digest_constant_is_32_bytes():
    assert isinstance(EMPTY_DIGEST, bytes)
    assert len(EMPTY_DIGEST) == 32


# ----------------------------------------------------------------------------
# Determinism
# ----------------------------------------------------------------------------

def test_same_inputs_byte_identical():
    txs = [_tx(sig="A"), _tx(sig="B", slot=101)]
    d1 = compute_tx_window_digest(txs, WINDOW)
    d2 = compute_tx_window_digest(list(txs), WINDOW)
    assert d1 == d2


def test_order_independence():
    txs_forward = [_tx(sig="A", slot=100), _tx(sig="B", slot=101), _tx(sig="C", slot=99)]
    txs_reverse = list(reversed(txs_forward))
    assert (
        compute_tx_window_digest(txs_forward, WINDOW)
        == compute_tx_window_digest(txs_reverse, WINDOW)
    )


# ----------------------------------------------------------------------------
# Field sensitivity — any change → digest change
# ----------------------------------------------------------------------------

def test_signature_change_changes_digest():
    base = _tx(sig="A")
    altered = _tx(sig="B")
    assert (
        compute_tx_window_digest([base], WINDOW)
        != compute_tx_window_digest([altered], WINDOW)
    )


def test_slot_change_changes_digest():
    assert (
        compute_tx_window_digest([_tx(slot=100)], WINDOW)
        != compute_tx_window_digest([_tx(slot=101)], WINDOW)
    )


def test_sol_change_change_changes_digest():
    assert (
        compute_tx_window_digest([_tx(sol_change=1000)], WINDOW)
        != compute_tx_window_digest([_tx(sol_change=-1000)], WINDOW)
    )


def test_success_change_changes_digest():
    a = _tx()
    b = Transaction(
        signature=a.signature, slot=a.slot, block_time=a.block_time,
        success=False,  # flipped
        program_ids=a.program_ids, sol_change=a.sol_change, fee=a.fee,
        priority_fee=a.priority_fee, compute_units=a.compute_units,
        counterparty=a.counterparty,
    )
    assert (
        compute_tx_window_digest([a], WINDOW)
        != compute_tx_window_digest([b], WINDOW)
    )


# ----------------------------------------------------------------------------
# Window sensitivity
# ----------------------------------------------------------------------------

def test_different_window_changes_digest():
    other = ExtractionWindow.ending_at(REF + timedelta(days=1), days=30)
    assert (
        compute_tx_window_digest([_tx()], WINDOW)
        != compute_tx_window_digest([_tx()], other)
    )


def test_empty_window_bound_to_window():
    d_a = compute_tx_window_digest([], WINDOW)
    d_b = compute_tx_window_digest([], ExtractionWindow.ending_at(REF + timedelta(days=7), days=30))
    assert d_a != d_b
    # Both still 32 bytes and distinct from EMPTY_DIGEST (which is the
    # window-independent sentinel; the public function always binds the
    # window).
    assert len(d_a) == 32
    assert d_a != EMPTY_DIGEST


# ----------------------------------------------------------------------------
# Invariants — duplicate signatures
# ----------------------------------------------------------------------------

def test_duplicate_signatures_rejected():
    tx_a = _tx(sig="DUPSIG")
    tx_b = _tx(sig="DUPSIG", slot=999)  # same sig, different slot
    with pytest.raises(ValueError, match="duplicate signature"):
        compute_tx_window_digest([tx_a, tx_b], WINDOW)


# ----------------------------------------------------------------------------
# Counterparty optional field
# ----------------------------------------------------------------------------

def test_counterparty_none_vs_present_differ():
    a = _tx()
    b = Transaction(
        signature=a.signature, slot=a.slot, block_time=a.block_time,
        success=a.success, program_ids=a.program_ids, sol_change=a.sol_change,
        fee=a.fee, priority_fee=a.priority_fee, compute_units=a.compute_units,
        counterparty=None,
    )
    assert (
        compute_tx_window_digest([a], WINDOW)
        != compute_tx_window_digest([b], WINDOW)
    )


# ----------------------------------------------------------------------------
# Cross-node verification
# ----------------------------------------------------------------------------

def test_two_independent_callers_agree():
    """Mirror the BFT consensus path: two callers, same data → same bytes."""
    txs = [
        _tx(sig="A", slot=100), _tx(sig="B", slot=101),
        _tx(sig="C", slot=102, sol_change=-1_000_000),
    ]
    d_node1 = compute_tx_window_digest(txs, WINDOW)
    # Node 2 retrieved them in a different DB order:
    d_node2 = compute_tx_window_digest(list(reversed(txs)), WINDOW)
    assert d_node1 == d_node2
