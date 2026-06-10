"""
diagnosis/detectors/_canon.py — internal helper for canonical tx ordering.

Every Day-36 detector walks the same canonically-sorted transaction list.
Centralising the sort key here means a future tweak (e.g. tie-breaker on
program-id list) lands in one place and every detector picks it up.

Canonical order: ascending (block_time, slot, signature). This mirrors the
feature extractor's contract (`features/extractor.py`) so a kernel run and a
feature run see the same ordering.
"""

from __future__ import annotations

from collections.abc import Sequence

from features.types import ExtractionWindow, Transaction


def canonical_window_txs(
    transactions: Sequence[Transaction],
    window:       ExtractionWindow,
) -> tuple[Transaction, ...]:
    """
    Return the subset of `transactions` whose `block_time` falls inside
    `window`, sorted into canonical (block_time, slot, signature) order.

    Filtering is INCLUSIVE on both ends — matches ExtractionWindow.contains.
    Pure.
    """
    inside = [t for t in transactions if window.contains(t.block_time)]
    inside.sort(key=lambda t: (t.block_time, t.slot, t.signature))
    return tuple(inside)
