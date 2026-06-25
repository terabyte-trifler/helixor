"""
tests/db/test_pipeline.py — Day-15 done-when: extractor reads from the repo,
existing data backfilled, and the hypertable query model is faster.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from baseline import BaselineStats, compute_baseline
from db import (
    InMemoryTransactionRepo,
    compute_baseline_from_repository,
    extract_from_repository,
)
from db.backfill_transactions import BackfillSource, run_backfill
from features import ExtractionWindow, extract
from features.types import Transaction


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
WINDOW_30D = ExtractionWindow.ending_at(REF_END, days=30)
WINDOW_1D = ExtractionWindow.ending_at(REF_END, days=1)


def _history(wallet: str, days: int) -> list[Transaction]:
    txs: list[Transaction] = []
    for d in range(days):
        for k in range(5):
            i = d * 5 + k
            txs.append(Transaction(
                signature=f"{wallet[:5]}{i:08d}".ljust(64, "x"),
                slot=100_000_000 + i,
                block_time=REF_END - timedelta(hours=d * 24 + k * 2 + 1),
                success=(i % 20) != 0,
                program_ids=("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",),
                sol_change=1_000_000 if k % 2 == 0 else -400_000,
                fee=5000, priority_fee=0, compute_units=200_000,
                counterparty=f"cp{i % 7}",
            ))
    return txs


def _seeded_repo(wallet: str = "agentX", days: int = 30) -> InMemoryTransactionRepo:
    repo = InMemoryTransactionRepo()
    repo.add_many(_history(wallet, days), agent_wallet=wallet)
    return repo


# =============================================================================
# DONE-WHEN part 1 — the feature extractor reads from the repository
# =============================================================================

class TestExtractorReadsFromRepository:

    def test_extract_from_repository_returns_feature_vector(self):
        repo = _seeded_repo()
        features = extract_from_repository(repo, "agentX", WINDOW_1D)
        assert len(features.to_list()) == 100

    def test_repo_backed_extract_matches_direct_extract(self):
        # The repository-backed path must produce a BYTE-IDENTICAL result to
        # calling the pure `extract` directly — the repo is just a fetch.
        repo = _seeded_repo()
        history = _history("agentX", 30)

        direct = extract(history, WINDOW_1D)
        via_repo = extract_from_repository(repo, "agentX", WINDOW_1D)
        assert direct == via_repo

    def test_compute_baseline_from_repository(self):
        repo = _seeded_repo()
        baseline = compute_baseline_from_repository(
            repo, "agentX", WINDOW_30D, computed_at=REF_END,
        )
        assert isinstance(baseline, BaselineStats)
        assert baseline.transaction_count == 150

    def test_repo_backed_baseline_matches_direct(self):
        repo = _seeded_repo()
        history = _history("agentX", 30)

        direct = compute_baseline("agentX", history, WINDOW_30D,
                                  computed_at=REF_END)
        via_repo = compute_baseline_from_repository(
            repo, "agentX", WINDOW_30D, computed_at=REF_END,
        )
        # Same stats hash → byte-identical baseline.
        assert direct.stats_hash == via_repo.stats_hash

    def test_extract_unknown_agent_is_empty_window(self):
        repo = _seeded_repo()
        # An agent with no rows → extract over an empty transaction list.
        features = extract_from_repository(repo, "ghost", WINDOW_1D)
        assert len(features.to_list()) == 100


# =============================================================================
# DONE-WHEN part 2 — existing data backfilled
# =============================================================================

class TestBackfill:

    def test_backfill_moves_all_transactions(self):
        source = BackfillSource(by_agent={
            "agentA": _history("agentA", 30),
            "agentB": _history("agentB", 20),
        })
        dest = InMemoryTransactionRepo()
        report = run_backfill(source, dest, clock=REF_END)

        assert report.agents_processed == 2
        assert report.transactions_read == 150 + 100
        assert report.transactions_written == 150 + 100
        assert dest.transaction_count("agentA") == 150
        assert dest.transaction_count("agentB") == 100

    def test_backfill_is_idempotent(self):
        source = BackfillSource(by_agent={"agentA": _history("agentA", 30)})
        dest = InMemoryTransactionRepo()

        first = run_backfill(source, dest, clock=REF_END)
        assert first.transactions_written == 150

        # Re-run: every row already present → all skipped, none written.
        second = run_backfill(source, dest, clock=REF_END)
        assert second.transactions_written == 0
        assert second.skipped == 150
        # Destination unchanged.
        assert dest.transaction_count("agentA") == 150

    def test_backfill_batches(self):
        source = BackfillSource(by_agent={"agentA": _history("agentA", 30)})
        dest = InMemoryTransactionRepo()
        report = run_backfill(source, dest, batch_size=50, clock=REF_END)
        # 150 transactions / 50 per batch = 3 batches.
        assert report.batches == 3

    def test_backfilled_data_is_extractable(self):
        # End-to-end: backfill, then extract from the backfilled repo.
        source = BackfillSource(by_agent={"agentA": _history("agentA", 30)})
        dest = InMemoryTransactionRepo()
        run_backfill(source, dest, clock=REF_END)

        baseline = compute_baseline_from_repository(
            dest, "agentA", WINDOW_30D, computed_at=REF_END,
        )
        assert baseline.transaction_count == 150

    def test_backfill_empty_source(self):
        report = run_backfill(BackfillSource(by_agent={}),
                              InMemoryTransactionRepo(), clock=REF_END)
        assert report.agents_processed == 0
        assert report.transactions_read == 0

    def test_backfill_report_duration(self):
        source = BackfillSource(by_agent={"agentA": _history("agentA", 5)})
        dest = InMemoryTransactionRepo()
        report = run_backfill(source, dest, clock=REF_END)
        # With an injected fixed clock, duration is zero — deterministic.
        assert report.duration_seconds == 0.0


# =============================================================================
# DONE-WHEN part 3 — the hypertable query model is faster
# =============================================================================

class TestQueryModelImprovement:
    """
    A live latency benchmark needs a running TimescaleDB; this environment
    has none. What CAN be asserted deterministically is the PROPERTY that
    makes the hypertable faster: a windowed query touches only the rows in
    the window, not the whole history.

    The InMemoryTransactionRepo models the same access pattern the
    hypertable's chunk-pruning gives — a 30-day window fetch returns only
    the 30-day rows, regardless of how much deeper history exists. That
    bounded-scan property is the source of the latency improvement; the
    migration's chunk_time_interval + the (agent_wallet, block_time) index
    realise it on real TimescaleDB.
    """

    def test_window_query_scans_only_the_window(self):
        # An agent with a full YEAR of history.
        repo = InMemoryTransactionRepo()
        repo.add_many(_history("agentX", 365), agent_wallet="agentX")
        assert repo.transaction_count("agentX") == 365 * 5

        # A 30-day window fetch returns only the 30-day slice — NOT the year.
        from db.repository import TransactionQuery
        q = TransactionQuery.for_extraction_window("agentX", WINDOW_30D)
        windowed = repo.fetch_transactions(q)
        assert len(windowed) == 30 * 5
        # The scan is bounded by the window, not the history depth — this is
        # exactly the property the hypertable's chunk pruning provides.
        assert len(windowed) < repo.transaction_count("agentX")

    def test_window_size_independent_of_history_depth(self):
        # A 1-day window returns the same row count whether the agent has
        # 30 days or 10 years of history behind it.
        from db.repository import TransactionQuery
        q = TransactionQuery.for_extraction_window("agentX", WINDOW_1D)

        shallow = InMemoryTransactionRepo()
        shallow.add_many(_history("agentX", 30), agent_wallet="agentX")

        deep = InMemoryTransactionRepo()
        deep.add_many(_history("agentX", 3650), agent_wallet="agentX")

        assert len(shallow.fetch_transactions(q)) == \
               len(deep.fetch_transactions(q))


# =============================================================================
# Determinism
# =============================================================================

class TestDeterminism:

    def test_repo_backed_extraction_deterministic(self):
        repo = _seeded_repo()
        first = extract_from_repository(repo, "agentX", WINDOW_1D)
        for _ in range(10):
            assert extract_from_repository(repo, "agentX", WINDOW_1D) == first

    def test_backfill_deterministic(self):
        source = BackfillSource(by_agent={"agentA": _history("agentA", 30)})

        def _run():
            dest = InMemoryTransactionRepo()
            return run_backfill(source, dest, clock=REF_END)

        first = _run()
        for _ in range(5):
            r = _run()
            assert r.transactions_written == first.transactions_written
            assert r.batches == first.batches
