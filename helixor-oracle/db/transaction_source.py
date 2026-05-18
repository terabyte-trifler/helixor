"""
db/transaction_source.py — the transaction-source abstraction.

THE DETERMINISM BOUNDARY
------------------------
The feature extractor and baseline engine are PURE FUNCTIONS — they take a
`Sequence[Transaction]` and are byte-deterministic. That purity is the
Phase-4 BFT guarantee: three oracle nodes computing the same score must see
the same bytes. They must NEVER do I/O.

So Day 15 does NOT make the extractor read from TimescaleDB. It introduces
a `TransactionSource` — the seam between "where transactions live" and
"the pure function that consumes them". A source returns a
`Sequence[Transaction]` for an (agent, window); the extractor consumes it
exactly as before.

Two implementations:
  * `TimescaleTransactionSource`  — reads the TimescaleDB hypertable
                                    (db/transaction_repository.py).
  * `InMemoryTransactionSource`   — an in-process list, for tests and for
                                    the pure-pipeline path that already
                                    holds its transactions.

CANONICAL ORDER — why it matters
--------------------------------
A hypertable stores rows across time-partitioned chunks; a plain table
stores them in one heap. Their natural scan orders differ. If a source
returned rows in storage order, the extractor would see different byte
sequences from different stores and the BFT scores would diverge.

Every source MUST therefore return transactions in CANONICAL ORDER:
ascending (block_time, slot, signature). This is total (signatures are
unique) and storage-independent. `canonical_sort` is the single definition;
every source applies it.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol, runtime_checkable

from features import ExtractionWindow, Transaction


# =============================================================================
# Canonical ordering — the determinism contract
# =============================================================================

def canonical_sort(transactions: Iterable[Transaction]) -> list[Transaction]:
    """
    Sort transactions into the canonical, storage-independent order:
    ascending (block_time, slot, signature).

    This order is TOTAL — `signature` is globally unique, so no two
    transactions ever tie. Every TransactionSource returns its results
    through this function, so the pure extractor sees byte-identical input
    regardless of where the rows were stored or how they were scanned.
    """
    return sorted(
        transactions,
        key=lambda t: (t.block_time, t.slot, t.signature),
    )


# =============================================================================
# The protocol
# =============================================================================

@runtime_checkable
class TransactionSource(Protocol):
    """
    A source of transactions for an (agent, time-window) query.

    Implementations MUST return transactions in `canonical_sort` order.
    """

    async def fetch_window(
        self,
        agent_wallet: str,
        window:       ExtractionWindow,
    ) -> Sequence[Transaction]:
        """Return this agent's transactions whose block_time is in `window`,
        in canonical order."""
        ...


# =============================================================================
# In-memory implementation — tests + the pure-pipeline path
# =============================================================================

class InMemoryTransactionSource:
    """
    A `TransactionSource` backed by an in-process list. Used by tests and by
    any caller that already holds its transactions (the pure pipeline).

    Window filtering + canonical ordering match the TimescaleDB source
    exactly, so swapping sources never changes the extractor's input.
    """

    __slots__ = ("_by_agent",)

    def __init__(self, transactions: Iterable[Transaction] = ()) -> None:
        self._by_agent: dict[str, list[Transaction]] = {}
        for tx in transactions:
            self._by_agent.setdefault("", []).append(tx)

    def add_for(self, agent_wallet: str, transactions: Iterable[Transaction]) -> None:
        """Register an agent's transactions."""
        self._by_agent.setdefault(agent_wallet, []).extend(transactions)

    async def fetch_window(
        self,
        agent_wallet: str,
        window:       ExtractionWindow,
    ) -> Sequence[Transaction]:
        rows = self._by_agent.get(agent_wallet, [])
        in_window = [tx for tx in rows if window.contains(tx.block_time)]
        return canonical_sort(in_window)
