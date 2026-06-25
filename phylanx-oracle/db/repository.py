"""
db/repository.py — the transaction repository abstraction.

The feature extractor (`extract`) and baseline engine (`compute_baseline`)
are PURE functions over a `list[Transaction]` — they must stay that way
(the Phase-4 BFT rule: determinism-critical code touches no I/O). Day 15
does NOT push a database connection into them.

Instead it introduces a repository: the boundary between "where the
transactions live" (now TimescaleDB) and "the pure functions that score
them". A caller fetches a window from the repository, then hands the
resulting list to the pure functions exactly as before.

Two implementations:
  - `InMemoryTransactionRepo` — a pure, deterministic in-memory store, used
    by tests and by deterministic replay.
  - `TimescaleTransactionRepo` (db/timescale_repo.py) — the production
    implementation, reading the Day-15 hypertable.

Both satisfy the same `TransactionRepository` Protocol, so the extractor
and baseline engine never know which one they are reading from.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from features import ExtractionWindow
from features.types import Transaction


# =============================================================================
# TransactionQuery — a typed window request
# =============================================================================

@dataclass(frozen=True, slots=True)
class TransactionQuery:
    """
    A request for one agent's transactions over a time window.

    `window_start` / `window_end` are tz-aware UTC; the range is
    half-open [start, end) — the same convention as ExtractionWindow.
    """
    agent_wallet: str
    window_start: datetime
    window_end:   datetime

    def __post_init__(self) -> None:
        if not self.agent_wallet:
            raise ValueError("TransactionQuery.agent_wallet must be non-empty")
        for name, ts in (("window_start", self.window_start),
                         ("window_end", self.window_end)):
            if ts.tzinfo is None:
                raise ValueError(f"{name} must be timezone-aware UTC")
        if self.window_end <= self.window_start:
            raise ValueError(
                f"window_end {self.window_end} must be after "
                f"window_start {self.window_start}"
            )

    @classmethod
    def for_extraction_window(
        cls, agent_wallet: str, window: ExtractionWindow,
    ) -> "TransactionQuery":
        """Build a query covering an ExtractionWindow."""
        return cls(
            agent_wallet=agent_wallet,
            window_start=window.start,
            window_end=window.end,
        )


# =============================================================================
# TransactionRepository — the read interface
# =============================================================================

@runtime_checkable
class TransactionRepository(Protocol):
    """
    The read interface the feature extractor / baseline engine use.

    A repository returns transactions in CHRONOLOGICAL order (block_time
    ascending) — the extractor and the daily-series builder both assume
    chronological input.
    """

    def fetch_transactions(self, query: TransactionQuery) -> list[Transaction]:
        """All of one agent's transactions in [window_start, window_end)."""
        ...

    def agent_wallets(self) -> list[str]:
        """Every agent wallet the repository has transactions for."""
        ...


# =============================================================================
# InMemoryTransactionRepo — pure, deterministic
# =============================================================================

class InMemoryTransactionRepo:
    """
    An in-memory `TransactionRepository`. Pure and deterministic — used by
    tests and by deterministic replay (a BFT oracle node can replay a fixed
    transaction set through this and get byte-identical features).

    Transactions are stored per-agent, kept sorted by block_time.
    """

    __slots__ = ("_by_agent",)

    def __init__(self, transactions: Iterable[Transaction] | None = None) -> None:
        self._by_agent: dict[str, list[Transaction]] = {}
        if transactions:
            self.add_many(transactions)

    # ── Writes ──────────────────────────────────────────────────────────────

    def add(self, agent_wallet: str, transaction: Transaction) -> None:
        """Add one transaction for an agent. Idempotent on signature."""
        bucket = self._by_agent.setdefault(agent_wallet, [])
        if any(t.signature == transaction.signature for t in bucket):
            return                                  # dedup on signature
        bucket.append(transaction)
        bucket.sort(key=lambda t: (t.block_time, t.signature))

    # Write-interface parity with TimescaleTransactionRepo, so the backfill
    # job and live ingest path are repository-agnostic.
    def insert_transaction(
        self, agent_wallet: str, transaction: Transaction,
    ) -> None:
        """Idempotent insert of one transaction — alias of `add`."""
        self.add(agent_wallet, transaction)

    def add_many(
        self,
        transactions: Iterable[Transaction],
        *,
        agent_wallet: str | None = None,
    ) -> None:
        """
        Add many transactions. `agent_wallet` is required — a Transaction
        does not carry its owning agent.

        Bulk path: dedups and sorts ONCE at the end rather than per insert,
        so seeding a large history is O(n log n), not O(n² log n).
        """
        if agent_wallet is None:
            raise ValueError(
                "add_many requires agent_wallet — a Transaction does not "
                "carry its owning agent"
            )
        bucket = self._by_agent.setdefault(agent_wallet, [])
        seen = {t.signature for t in bucket}
        for tx in transactions:
            if tx.signature not in seen:
                bucket.append(tx)
                seen.add(tx.signature)
        bucket.sort(key=lambda t: (t.block_time, t.signature))

    # ── Reads (the TransactionRepository interface) ─────────────────────────

    def fetch_transactions(self, query: TransactionQuery) -> list[Transaction]:
        bucket = self._by_agent.get(query.agent_wallet, [])
        # Half-open [start, end); bucket is already sorted.
        return [
            t for t in bucket
            if query.window_start <= t.block_time < query.window_end
        ]

    def agent_wallets(self) -> list[str]:
        return sorted(self._by_agent)

    # ── Introspection ───────────────────────────────────────────────────────

    def transaction_count(self, agent_wallet: str | None = None) -> int:
        if agent_wallet is not None:
            return len(self._by_agent.get(agent_wallet, []))
        return sum(len(b) for b in self._by_agent.values())
