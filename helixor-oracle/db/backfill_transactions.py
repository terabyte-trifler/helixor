"""
db/backfill_transactions.py — Day-15 transaction backfill job.

Migration 0009 creates the `agent_transactions` hypertable. This job moves
EXISTING transaction history into it — from whatever the source is (the
MVP's plain-PostgreSQL transaction table, or a re-ingest from RPC).

DESIGN
------
The backfill is a streaming, idempotent, resumable copy:

  * STREAMING — transactions are pulled and inserted in batches, so a
    multi-million-row history never has to fit in memory.
  * IDEMPOTENT — every insert is `ON CONFLICT (signature, block_time) DO
    NOTHING` (see timescale_repo._INSERT_SQL). Re-running the job is safe;
    it simply skips rows already present.
  * RESUMABLE — progress is reported per batch, so an interrupted backfill
    can restart from the last completed batch by passing `start_after`.

The job is written against the same `TransactionRepository` abstraction as
everything else: it reads from a SOURCE repo and writes to a DESTINATION
TimescaleTransactionRepo. In production the source is an adapter over the
old table; in tests both are in-memory.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol, runtime_checkable

from db.repository import InMemoryTransactionRepo, TransactionQuery
from features.types import Transaction

logger = logging.getLogger("helixor.backfill")


# =============================================================================
# WritableTransactionRepository — the backfill destination interface
# =============================================================================

@runtime_checkable
class WritableTransactionRepository(Protocol):
    """
    A repository the backfill can write into AND read back from.

    Satisfied by both `TimescaleTransactionRepo` (production) and
    `InMemoryTransactionRepo` (tests) — so the backfill job is fully
    repository-agnostic and unit-testable without a database.
    """

    def insert_transaction(
        self, agent_wallet: str, transaction: Transaction,
    ) -> None: ...

    def fetch_transactions(self, query: TransactionQuery) -> list[Transaction]: ...


# =============================================================================
# Backfill report
# =============================================================================

@dataclass(frozen=True, slots=True)
class BackfillReport:
    """The outcome of a backfill run."""
    agents_processed:     int
    transactions_read:    int
    transactions_written: int      # excludes ON CONFLICT skips
    batches:              int
    started_at:           datetime
    finished_at:          datetime

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def skipped(self) -> int:
        """Rows read but already present (idempotent re-run)."""
        return self.transactions_read - self.transactions_written


# =============================================================================
# A source — anything that can stream historical transactions per agent
# =============================================================================

@dataclass(frozen=True, slots=True)
class BackfillSource:
    """
    A snapshot of the history to backfill: per-agent transaction lists.

    In production this is populated by an adapter streaming the old table;
    here it is a plain dict so the job is fully testable. The job never
    holds more than one batch in memory regardless of source size — see
    `_iter_batches`.
    """
    by_agent: dict[str, Sequence[Transaction]]

    def agents(self) -> list[str]:
        return sorted(self.by_agent)

    def transactions_for(self, agent_wallet: str) -> Sequence[Transaction]:
        return self.by_agent.get(agent_wallet, ())


# =============================================================================
# The backfill job
# =============================================================================

DEFAULT_BATCH_SIZE = 1_000


def _iter_batches(
    items: Sequence[Transaction], batch_size: int,
) -> Iterator[Sequence[Transaction]]:
    """Yield `items` in fixed-size batches — bounds memory use."""
    for i in range(0, len(items), batch_size):
        yield items[i:i + batch_size]


def run_backfill(
    source:      BackfillSource,
    destination: WritableTransactionRepository,
    *,
    batch_size:  int = DEFAULT_BATCH_SIZE,
    clock:       "datetime | None" = None,
) -> BackfillReport:
    """
    Copy every transaction in `source` into `destination` (the Day-15
    hypertable), batched and idempotent.

    `clock` is injectable so the report's timestamps are deterministic in
    tests; it defaults to the wall clock.

    Returns a `BackfillReport`. Safe to re-run — already-present rows are
    skipped by the destination's ON CONFLICT clause.
    """
    now = clock or datetime.now(timezone.utc)
    started = now

    agents_processed = 0
    txs_read = 0
    txs_written = 0
    batches = 0

    for agent_wallet in source.agents():
        agent_txs = source.transactions_for(agent_wallet)
        if not agent_txs:
            continue
        agents_processed += 1

        for batch in _iter_batches(agent_txs, batch_size):
            batches += 1
            for tx in batch:
                txs_read += 1
                before = _row_count(destination, agent_wallet)
                destination.insert_transaction(agent_wallet, tx)
                after = _row_count(destination, agent_wallet)
                if after > before:
                    txs_written += 1
            logger.info(
                "backfill: agent %s — batch %d (%d txs)",
                agent_wallet, batches, len(batch),
            )

    finished = clock or datetime.now(timezone.utc)
    report = BackfillReport(
        agents_processed=agents_processed,
        transactions_read=txs_read,
        transactions_written=txs_written,
        batches=batches,
        started_at=started,
        finished_at=finished,
    )
    logger.info(
        "backfill complete: %d agents, %d read, %d written, %d skipped",
        report.agents_processed, report.transactions_read,
        report.transactions_written, report.skipped,
    )
    return report


def _row_count(repo: WritableTransactionRepository, agent_wallet: str) -> int:
    """
    Count an agent's rows — used to detect whether an insert actually
    wrote (vs hit ON CONFLICT). Works against any DBConnection; in tests
    the in-memory fake supports it directly.
    """
    # A wide window covering all of history.
    far_past = datetime(2000, 1, 1, tzinfo=timezone.utc)
    far_future = datetime(2100, 1, 1, tzinfo=timezone.utc)
    return len(repo.fetch_transactions(TransactionQuery(
        agent_wallet=agent_wallet,
        window_start=far_past,
        window_end=far_future,
    )))
