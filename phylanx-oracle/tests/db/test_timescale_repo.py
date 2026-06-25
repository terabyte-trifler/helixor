"""
tests/db/test_timescale_repo.py — the TimescaleDB-backed repository.

`TimescaleTransactionRepo` is exercised against a FAKE `DBConnection` that
records the SQL it is given and returns canned rows. This proves the
query construction and the row -> Transaction mapping are correct WITHOUT
needing a live database — the real SQL itself is validated by the
migration (0009) running against TimescaleDB in deployment.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from db.repository import TransactionQuery
from db.timescale_repo import (
    DBConnection,
    TimescaleTransactionRepo,
)
from features.types import Transaction


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)

# VULN-20: the repo now enforces a base58 wallet shape (32..44 chars,
# Bitcoin alphabet). The test wallet is a synthetic-but-valid placeholder.
AGENT_X = "X9" * 22


# =============================================================================
# A fake DBConnection
# =============================================================================

class FakeConnection:
    """
    Records every (sql, params) pair; returns canned rows. The canned rows
    are keyed by a substring of the SQL so different queries get different
    responses.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, list]] = []
        self._responses: dict[str, list[tuple]] = {}

    def set_response(self, sql_fragment: str, rows: list[tuple]) -> None:
        self._responses[sql_fragment] = rows

    def execute(self, sql: str, params) -> list[tuple]:
        self.calls.append((sql, list(params)))
        for fragment, rows in self._responses.items():
            if fragment in sql:
                return rows
        return []


def _tx_row(i: int) -> tuple:
    """A row in agent_transactions SELECT-column order."""
    return (
        AGENT_X,                                          # agent_wallet
        f"sig{i:08d}".ljust(64, "x"),                      # signature
        100_000_000 + i,                                   # slot
        REF_END - timedelta(hours=i),                      # block_time
        (i % 10) != 0,                                     # success
        ["JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"],   # program_ids
        1_000_000,                                         # sol_change
        5000,                                              # fee
        100,                                               # priority_fee
        200_000,                                           # compute_units
        f"cp{i % 5}",                                      # counterparty
    )


# =============================================================================
# Protocol conformance
# =============================================================================

class TestProtocolConformance:

    def test_fake_connection_satisfies_protocol(self):
        assert isinstance(FakeConnection(), DBConnection)

    def test_repo_constructs_with_connection(self):
        repo = TimescaleTransactionRepo(FakeConnection())
        assert repo is not None


# =============================================================================
# fetch_transactions
# =============================================================================

class TestFetchTransactions:

    def test_maps_rows_to_transactions(self):
        conn = FakeConnection()
        conn.set_response("FROM agent_transactions",
                          [_tx_row(0), _tx_row(1), _tx_row(2)])
        repo = TimescaleTransactionRepo(conn)
        q = TransactionQuery(
            agent_wallet=AGENT_X,
            window_start=REF_END - timedelta(days=1),
            window_end=REF_END,
        )
        result = repo.fetch_transactions(q)
        assert len(result) == 3
        assert all(isinstance(t, Transaction) for t in result)

    def test_row_fields_map_correctly(self):
        conn = FakeConnection()
        conn.set_response("FROM agent_transactions", [_tx_row(7)])
        repo = TimescaleTransactionRepo(conn)
        q = TransactionQuery(
            agent_wallet=AGENT_X,
            window_start=REF_END - timedelta(days=1),
            window_end=REF_END,
        )
        tx = repo.fetch_transactions(q)[0]
        assert tx.slot == 100_000_007
        assert tx.sol_change == 1_000_000
        assert tx.priority_fee == 100
        assert tx.program_ids == ("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",)
        assert tx.counterparty == "cp2"

    def test_query_passes_window_params(self):
        conn = FakeConnection()
        repo = TimescaleTransactionRepo(conn)
        start = REF_END - timedelta(days=30)
        q = TransactionQuery(
            agent_wallet=AGENT_X, window_start=start, window_end=REF_END,
        )
        repo.fetch_transactions(q)
        # The window bounds + agent went into the parameter list.
        sql, params = conn.calls[0]
        assert params == [AGENT_X, start, REF_END]

    def test_empty_result(self):
        conn = FakeConnection()           # no canned rows
        repo = TimescaleTransactionRepo(conn)
        q = TransactionQuery(
            agent_wallet=AGENT_X,
            window_start=REF_END - timedelta(days=1),
            window_end=REF_END,
        )
        assert repo.fetch_transactions(q) == []

    def test_null_program_ids_handled(self):
        conn = FakeConnection()
        row = list(_tx_row(0))
        row[5] = None                      # NULL program_ids
        conn.set_response("FROM agent_transactions", [tuple(row)])
        repo = TimescaleTransactionRepo(conn)
        q = TransactionQuery(
            agent_wallet=AGENT_X,
            window_start=REF_END - timedelta(days=1),
            window_end=REF_END,
        )
        assert repo.fetch_transactions(q)[0].program_ids == ()


# =============================================================================
# agent_wallets
# =============================================================================

class TestAgentWallets:

    def test_returns_wallet_list(self):
        conn = FakeConnection()
        conn.set_response("DISTINCT agent_wallet",
                          [("agentA",), ("agentB",), ("agentC",)])
        repo = TimescaleTransactionRepo(conn)
        assert repo.agent_wallets() == ["agentA", "agentB", "agentC"]


# =============================================================================
# Daily rollup — the continuous aggregate read
# =============================================================================

class TestDailyRollup:

    def test_maps_rollup_rows(self):
        conn = FakeConnection()
        day = REF_END - timedelta(days=1)
        conn.set_response("agent_tx_daily", [
            (day, 25, 24, 0.96, 5_000_000, 125_000, 7),
        ])
        repo = TimescaleTransactionRepo(conn)
        rollup = repo.fetch_daily_rollup(
            AGENT_X, REF_END - timedelta(days=30), REF_END,
        )
        assert len(rollup) == 1
        assert rollup[0]["tx_count"] == 25
        assert rollup[0]["success_rate"] == 0.96
        assert rollup[0]["distinct_counterparties"] == 7

    def test_rollup_hits_continuous_aggregate(self):
        conn = FakeConnection()
        repo = TimescaleTransactionRepo(conn)
        repo.fetch_daily_rollup(AGENT_X, REF_END - timedelta(days=30), REF_END)
        # The query targets the continuous aggregate, not the raw table.
        sql, _ = conn.calls[0]
        assert "agent_tx_daily" in sql


# =============================================================================
# insert_transaction
# =============================================================================

class TestInsertTransaction:

    def test_insert_passes_all_columns(self):
        conn = FakeConnection()
        repo = TimescaleTransactionRepo(conn)
        tx = Transaction(
            signature="sig" + "x" * 61,
            slot=100_000_000,
            block_time=REF_END,
            success=True,
            program_ids=("progA", "progB"),
            sol_change=999,
            fee=5000, priority_fee=100, compute_units=200_000,
            counterparty="cpX",
        )
        repo.insert_transaction(AGENT_X, tx)
        sql, params = conn.calls[0]
        assert "INSERT INTO agent_transactions" in sql
        assert params[0] == AGENT_X
        assert params[1] == tx.signature
        # program_ids passed as a list (TEXT[]).
        assert params[5] == ["progA", "progB"]

    def test_insert_is_idempotent_sql(self):
        # The INSERT carries ON CONFLICT DO NOTHING — re-running is safe.
        conn = FakeConnection()
        repo = TimescaleTransactionRepo(conn)
        tx = Transaction(
            signature="sig" + "y" * 61, slot=1, block_time=REF_END,
            success=True, program_ids=(), sol_change=0, fee=0,
            priority_fee=0, compute_units=0, counterparty=None,
        )
        repo.insert_transaction(AGENT_X, tx)
        sql, _ = conn.calls[0]
        assert "ON CONFLICT" in sql
        assert "DO NOTHING" in sql
