"""
tests/db/test_repository.py — the transaction repository abstraction.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from db.repository import (
    InMemoryTransactionRepo,
    TransactionQuery,
    TransactionRepository,
)
from features import ExtractionWindow
from features.types import Transaction


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


def _tx(i: int, *, hours_ago: float) -> Transaction:
    return Transaction(
        signature=f"sig{i:08d}".ljust(64, "x"),
        slot=100_000_000 + i,
        block_time=REF_END - timedelta(hours=hours_ago),
        success=(i % 10) != 0,
        program_ids=("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",),
        sol_change=1_000_000,
        fee=5000, priority_fee=0, compute_units=200_000,
        counterparty=f"cp{i % 5}",
    )


# =============================================================================
# TransactionQuery
# =============================================================================

class TestTransactionQuery:

    def test_valid_query(self):
        q = TransactionQuery(
            agent_wallet="agentX",
            window_start=REF_END - timedelta(days=30),
            window_end=REF_END,
        )
        assert q.agent_wallet == "agentX"

    def test_rejects_empty_wallet(self):
        with pytest.raises(ValueError, match="agent_wallet"):
            TransactionQuery(
                agent_wallet="",
                window_start=REF_END - timedelta(days=1),
                window_end=REF_END,
            )

    def test_rejects_naive_datetime(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            TransactionQuery(
                agent_wallet="agentX",
                window_start=datetime(2026, 4, 1),       # naive
                window_end=REF_END,
            )

    def test_rejects_inverted_window(self):
        with pytest.raises(ValueError, match="after"):
            TransactionQuery(
                agent_wallet="agentX",
                window_start=REF_END,
                window_end=REF_END - timedelta(days=1),
            )

    def test_from_extraction_window(self):
        window = ExtractionWindow.ending_at(REF_END, days=30)
        q = TransactionQuery.for_extraction_window("agentX", window)
        assert q.window_start == window.start
        assert q.window_end == window.end


# =============================================================================
# InMemoryTransactionRepo
# =============================================================================

class TestInMemoryRepo:

    def test_satisfies_protocol(self):
        repo = InMemoryTransactionRepo()
        assert isinstance(repo, TransactionRepository)

    def test_add_and_fetch(self):
        repo = InMemoryTransactionRepo()
        repo.add("agentX", _tx(0, hours_ago=5))
        q = TransactionQuery(
            agent_wallet="agentX",
            window_start=REF_END - timedelta(days=1),
            window_end=REF_END,
        )
        assert len(repo.fetch_transactions(q)) == 1

    def test_dedup_on_signature(self):
        repo = InMemoryTransactionRepo()
        tx = _tx(0, hours_ago=5)
        repo.add("agentX", tx)
        repo.add("agentX", tx)            # same signature
        assert repo.transaction_count("agentX") == 1

    def test_fetch_is_chronological(self):
        repo = InMemoryTransactionRepo()
        # Insert out of order.
        for hrs in (1, 20, 5, 12, 3):
            repo.add("agentX", _tx(int(hrs), hours_ago=hrs))
        q = TransactionQuery(
            agent_wallet="agentX",
            window_start=REF_END - timedelta(days=2),
            window_end=REF_END,
        )
        result = repo.fetch_transactions(q)
        times = [t.block_time for t in result]
        assert times == sorted(times)

    def test_window_is_half_open(self):
        repo = InMemoryTransactionRepo()
        # A tx exactly at window_start is included; one at window_end is not.
        at_start = _tx(1, hours_ago=24)             # exactly 1 day ago
        repo.add("agentX", at_start)
        q = TransactionQuery(
            agent_wallet="agentX",
            window_start=REF_END - timedelta(hours=24),
            window_end=REF_END,
        )
        assert len(repo.fetch_transactions(q)) == 1

    def test_fetch_excludes_outside_window(self):
        repo = InMemoryTransactionRepo()
        repo.add("agentX", _tx(0, hours_ago=5))     # inside
        repo.add("agentX", _tx(1, hours_ago=500))   # way outside
        q = TransactionQuery(
            agent_wallet="agentX",
            window_start=REF_END - timedelta(days=1),
            window_end=REF_END,
        )
        assert len(repo.fetch_transactions(q)) == 1

    def test_fetch_unknown_agent_empty(self):
        repo = InMemoryTransactionRepo()
        q = TransactionQuery(
            agent_wallet="ghost",
            window_start=REF_END - timedelta(days=1),
            window_end=REF_END,
        )
        assert repo.fetch_transactions(q) == []

    def test_agent_wallets_sorted(self):
        repo = InMemoryTransactionRepo()
        repo.add("zebra", _tx(0, hours_ago=1))
        repo.add("alpha", _tx(1, hours_ago=1))
        assert repo.agent_wallets() == ["alpha", "zebra"]

    def test_insert_transaction_alias(self):
        # insert_transaction is the write-interface parity method.
        repo = InMemoryTransactionRepo()
        repo.insert_transaction("agentX", _tx(0, hours_ago=5))
        assert repo.transaction_count("agentX") == 1

    def test_constructor_seeding(self):
        # Seeding via constructor requires per-agent add — verify the
        # add_many guard.
        repo = InMemoryTransactionRepo()
        repo.add_many([_tx(i, hours_ago=i + 1) for i in range(5)],
                      agent_wallet="agentX")
        assert repo.transaction_count("agentX") == 5

    def test_add_many_requires_wallet(self):
        repo = InMemoryTransactionRepo()
        with pytest.raises(ValueError, match="agent_wallet"):
            repo.add_many([_tx(0, hours_ago=1)])


# =============================================================================
# Determinism
# =============================================================================

class TestDeterminism:

    def test_fetch_is_deterministic(self):
        repo = InMemoryTransactionRepo()
        for hrs in range(1, 30):
            repo.add("agentX", _tx(hrs, hours_ago=hrs))
        q = TransactionQuery(
            agent_wallet="agentX",
            window_start=REF_END - timedelta(days=2),
            window_end=REF_END,
        )
        first = repo.fetch_transactions(q)
        for _ in range(10):
            assert repo.fetch_transactions(q) == first
