"""
db/timescale_repo.py — the TimescaleDB-backed transaction repository.

The production `TransactionRepository`. Reads the Day-15 `agent_transactions`
hypertable; satisfies the exact same Protocol as `InMemoryTransactionRepo`,
so the feature extractor and baseline engine never know which they read.

DATABASE-DRIVER INDEPENDENCE
---------------------------
This module is written against a minimal `DBConnection` Protocol —
`execute(sql, params) -> rows` — rather than importing `psycopg` /
`asyncpg` directly. Reasons:

  1. The determinism-critical code (feature math) must not transitively
     import a database driver — the BFT rule.
  2. It keeps this module unit-testable with a fake connection, and lets
     the deployment choose its driver (psycopg 3 sync, asyncpg, a pool).

In production `DBConnection` is satisfied by a thin adapter over psycopg 3.
A reference adapter is given at the bottom of this file.

QUERY DESIGN
------------
Every read is a single parameterised statement that the Day-15 schema
serves efficiently: the `(agent_wallet, block_time DESC)` index plus the
hypertable's chunk pruning turn a 30-day window into a bounded index range
scan over ~30 daily chunks. The daily-rollup read hits the `agent_tx_daily`
continuous aggregate — a pre-materialised view — instead of aggregating
raw rows.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from db.repository import TransactionQuery
from features.types import Transaction


# =============================================================================
# VULN-20 defense-in-depth — base58 wallet guard
# =============================================================================
#
# The %s-parameterised queries below are already proof against SQLi: the
# psycopg driver never splices the parameter into the SQL string. This
# guard exists for a SECOND failure mode — a future refactor that
# constructs SQL with f-strings or `.format()`. If `agent_wallet` is
# already known to be base58, that refactor cannot exfiltrate data even
# if it accidentally splices the value, because no SQL metacharacter can
# survive the alphabet check.
#
# Kept module-local rather than imported from helixor-api so the oracle
# package has zero cross-package dependencies.

_BASE58_ALPHABET = frozenset(
    "123456789"
    "ABCDEFGHJKLMNPQRSTUVWXYZ"
    "abcdefghijkmnopqrstuvwxyz"
)
_MIN_WALLET_LEN = 32
_MAX_WALLET_LEN = 44


class WalletValidationError(ValueError):
    """Raised when a wallet handed to the repo is not base58-shaped."""


def _ensure_wallet_safe(wallet: str) -> None:
    if not isinstance(wallet, str):
        raise WalletValidationError("wallet must be a string")
    n = len(wallet)
    if n < _MIN_WALLET_LEN or n > _MAX_WALLET_LEN:
        raise WalletValidationError(
            f"wallet length {n} outside {_MIN_WALLET_LEN}..{_MAX_WALLET_LEN}"
        )
    for c in wallet:
        if c not in _BASE58_ALPHABET:
            raise WalletValidationError(
                f"wallet contains non-base58 character {c!r}"
            )


# =============================================================================
# DBConnection — the minimal driver-independent interface
# =============================================================================

@runtime_checkable
class DBConnection(Protocol):
    """
    The minimal database interface this repository needs.

    `execute` runs a parameterised SQL statement and returns the result
    rows as a sequence of tuples (DB-API style). Production adapters wrap
    psycopg 3 / asyncpg; tests pass a fake.
    """

    def execute(self, sql: str, params: Sequence[Any]) -> Sequence[tuple]:
        ...


# =============================================================================
# SQL — single source of truth for the queries
# =============================================================================

# A 30-day (or any) window for one agent. Chronological order — the
# extractor and the daily-series builder both assume ascending block_time.
_FETCH_WINDOW_SQL = """
    SELECT agent_wallet, signature, slot, block_time, success,
           program_ids, sol_change, fee, priority_fee, compute_units,
           counterparty
      FROM agent_transactions
     WHERE agent_wallet = %s
       AND block_time >= %s
       AND block_time <  %s
     ORDER BY block_time ASC, signature ASC
"""

# Distinct agent wallets in the hypertable.
_AGENT_WALLETS_SQL = """
    SELECT DISTINCT agent_wallet
      FROM agent_transactions
     ORDER BY agent_wallet ASC
"""

# Per-agent daily rollup, served by the continuous aggregate. This is what
# the baseline engine's daily-success-rate-series consumes — a 30-row read
# of a materialised view rather than an aggregate over thousands of rows.
_DAILY_ROLLUP_SQL = """
    SELECT day, tx_count, success_count, success_rate,
           net_sol_change, total_fees, distinct_counterparties
      FROM agent_tx_daily
     WHERE agent_wallet = %s
       AND day >= %s
       AND day <  %s
     ORDER BY day ASC
"""

# Idempotent insert — used by the backfill job and the live ingest path.
_INSERT_SQL = """
    INSERT INTO agent_transactions
        (agent_wallet, signature, slot, block_time, success,
         program_ids, sol_change, fee, priority_fee, compute_units,
         counterparty)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (signature, block_time) DO NOTHING
"""


# =============================================================================
# Row -> Transaction
# =============================================================================

def _row_to_transaction(row: tuple) -> Transaction:
    """
    Map an `agent_transactions` row to a `Transaction`.

    Column order MUST match _FETCH_WINDOW_SQL's SELECT list:
      0 agent_wallet  1 signature  2 slot  3 block_time  4 success
      5 program_ids   6 sol_change 7 fee   8 priority_fee 9 compute_units
      10 counterparty
    """
    program_ids = tuple(row[5]) if row[5] is not None else ()
    return Transaction(
        signature=row[1],
        slot=int(row[2]),
        block_time=row[3],
        success=bool(row[4]),
        program_ids=program_ids,
        sol_change=int(row[6]),
        fee=int(row[7]),
        priority_fee=int(row[8]),
        compute_units=int(row[9]),
        counterparty=row[10],
    )


# =============================================================================
# TimescaleTransactionRepo
# =============================================================================

class TimescaleTransactionRepo:
    """
    A `TransactionRepository` backed by the Day-15 TimescaleDB hypertable.

    Construct with any `DBConnection`. Satisfies the same Protocol as
    `InMemoryTransactionRepo`.
    """

    __slots__ = ("_conn",)

    def __init__(self, connection: DBConnection) -> None:
        self._conn = connection

    # ── TransactionRepository interface ─────────────────────────────────────

    def fetch_transactions(self, query: TransactionQuery) -> list[Transaction]:
        """
        All of one agent's transactions in [window_start, window_end),
        chronological. A bounded index range scan over the pruned chunks.
        """
        # VULN-20 — defense in depth (see top of file).
        _ensure_wallet_safe(query.agent_wallet)
        rows = self._conn.execute(
            _FETCH_WINDOW_SQL,
            [query.agent_wallet, query.window_start, query.window_end],
        )
        return [_row_to_transaction(r) for r in rows]

    def agent_wallets(self) -> list[str]:
        rows = self._conn.execute(_AGENT_WALLETS_SQL, [])
        return [r[0] for r in rows]

    # ── Daily rollup — served by the continuous aggregate ───────────────────

    def fetch_daily_rollup(
        self,
        agent_wallet: str,
        window_start: datetime,
        window_end:   datetime,
    ) -> list[dict]:
        """
        The per-day rollup for an agent over a window, read from the
        `agent_tx_daily` continuous aggregate.

        Returns one dict per active day: day, tx_count, success_count,
        success_rate, net_sol_change, total_fees, distinct_counterparties.
        Days with no activity are simply absent (not zero-filled) — the
        same convention as `daily_success_rate_series`.
        """
        # VULN-20 — defense in depth.
        _ensure_wallet_safe(agent_wallet)
        rows = self._conn.execute(
            _DAILY_ROLLUP_SQL, [agent_wallet, window_start, window_end],
        )
        return [
            {
                "day":                     r[0],
                "tx_count":                int(r[1]),
                "success_count":           int(r[2]),
                "success_rate":            float(r[3]),
                "net_sol_change":          int(r[4]),
                "total_fees":              int(r[5]),
                "distinct_counterparties": int(r[6]),
            }
            for r in rows
        ]

    # ── Write path — used by the backfill job + live ingest ─────────────────

    def insert_transaction(
        self, agent_wallet: str, transaction: Transaction,
    ) -> None:
        """Idempotent insert of one transaction (ON CONFLICT DO NOTHING)."""
        # VULN-20 — defense in depth.
        _ensure_wallet_safe(agent_wallet)
        self._conn.execute(_INSERT_SQL, [
            agent_wallet,
            transaction.signature,
            transaction.slot,
            transaction.block_time,
            transaction.success,
            list(transaction.program_ids),
            transaction.sol_change,
            transaction.fee,
            transaction.priority_fee,
            transaction.compute_units,
            transaction.counterparty,
        ])


# =============================================================================
# Reference production adapter — psycopg 3
# =============================================================================

class Psycopg3Connection:
    """
    A reference `DBConnection` over psycopg 3.

    NOT imported at module load — psycopg is a production dependency, not a
    test one, and the determinism-critical code must not transitively
    import a driver. Construct this explicitly in the deployment wiring:

        import psycopg
        conn = Psycopg3Connection(psycopg.connect(DSN))
        repo = TimescaleTransactionRepo(conn)

    `execute` returns `[]` for non-SELECT statements.
    """

    __slots__ = ("_raw",)

    def __init__(self, raw_connection: Any) -> None:
        self._raw = raw_connection

    def execute(self, sql: str, params: Sequence[Any]) -> Sequence[tuple]:
        with self._raw.cursor() as cur:
            cur.execute(sql, list(params))
            if cur.description is None:        # non-SELECT (INSERT/DDL)
                self._raw.commit()
                return []
            return cur.fetchall()
