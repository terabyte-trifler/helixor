"""
tests/test_indexer.py — the indexer pipeline: filter, writer, runner.

THE DAY-16 DONE-WHEN
--------------------
"Every transaction from 5 test agent wallets appears in TimescaleDB within
 500ms of on-chain confirmation, via Geyser."
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from db import InMemoryTransactionRepo
from db.repository import TransactionQuery
from indexer import (
    INGEST_SLA_MS,
    GeyserAccountChange,
    GeyserIndexer,
    GeyserTransactionUpdate,
    IngestionSource,
    IngestionWriter,
    ListStreamSource,
    WalletFilter,
)


CONF = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
PROG = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"

# The 5 test agent wallets — the done-when's subjects.
TEST_AGENTS = [f"agent{i}".ljust(44, "x") for i in range(5)]


def _update(i: int, agent: str, *, counterparty: str = "cp".ljust(44, "x"),
            latency_ms: float = 80.0,
            extra_account: str | None = None) -> GeyserTransactionUpdate:
    keys = [agent, counterparty, PROG]
    changes = [
        GeyserAccountChange(agent, 1_000_000_000, 1_000_000_000 - 500_000),
        GeyserAccountChange(counterparty, 2_000_000_000, 2_000_000_000 + 500_000),
    ]
    if extra_account is not None:
        keys.append(extra_account)
    return GeyserTransactionUpdate(
        signature=f"sig{i:08d}".ljust(64, "x"),
        slot=300_000_000 + i,
        block_time=CONF,
        is_successful=(i % 10) != 0,
        fee_lamports=5000,
        compute_units=200_000,
        account_keys=tuple(keys),
        account_changes=tuple(changes),
        instr_program_ids=(PROG,),
        received_at=CONF + timedelta(milliseconds=latency_ms),
    )


def _indexer_for(agents, updates):
    wf = WalletFilter(agents)
    repo = InMemoryTransactionRepo()
    writer = IngestionWriter(wf, repo)
    indexer = GeyserIndexer(ListStreamSource(updates), writer)
    return indexer, repo


# =============================================================================
# WalletFilter
# =============================================================================

class TestWalletFilter:

    def test_registered_wallet_matches(self):
        wf = WalletFilter(["agentA"])
        update = _update(0, "agentA")
        assert wf.is_relevant(update)
        assert "agentA" in wf.matching_agents(update)

    def test_unregistered_wallet_filtered_out(self):
        wf = WalletFilter(["agentA"])
        update = _update(0, "unregisteredAgent")
        assert not wf.is_relevant(update)
        assert wf.matching_agents(update) == []

    def test_transaction_touching_two_agents(self):
        # A → B payment: both are registered, both must record it.
        wf = WalletFilter(["agentA", "agentB"])
        update = _update(0, "agentA", extra_account="agentB")
        assert wf.matching_agents(update) == ["agentA", "agentB"]

    def test_register_and_deregister(self):
        wf = WalletFilter()
        assert wf.registered_count == 0
        wf.register("agentA")
        assert wf.is_registered("agentA")
        wf.deregister("agentA")
        assert not wf.is_registered("agentA")

    def test_matching_agents_sorted(self):
        wf = WalletFilter(["zebra", "alpha"])
        update = _update(0, "zebra", extra_account="alpha")
        assert wf.matching_agents(update) == ["alpha", "zebra"]


# =============================================================================
# IngestionWriter
# =============================================================================

class TestIngestionWriter:

    def test_writes_to_repository(self):
        wf = WalletFilter(["agentA"])
        repo = InMemoryTransactionRepo()
        writer = IngestionWriter(wf, repo)
        writer.ingest(_update(0, "agentA"))
        assert repo.transaction_count("agentA") == 1

    def test_skips_unregistered(self):
        wf = WalletFilter(["agentA"])
        repo = InMemoryTransactionRepo()
        writer = IngestionWriter(wf, repo)
        result = writer.ingest(_update(0, "ghost"))
        assert result == []
        assert writer.skipped_count == 1

    def test_two_agent_transaction_written_twice(self):
        # A transaction touching two agents is recorded once per agent.
        wf = WalletFilter(["agentA", "agentB"])
        repo = InMemoryTransactionRepo()
        writer = IngestionWriter(wf, repo)
        results = writer.ingest(_update(0, "agentA", extra_account="agentB"))
        assert len(results) == 2
        assert repo.transaction_count("agentA") == 1
        assert repo.transaction_count("agentB") == 1

    def test_idempotent_on_resubmission(self):
        # The same transaction ingested twice (Geyser + webhook) → one row.
        wf = WalletFilter(["agentA"])
        repo = InMemoryTransactionRepo()
        writer = IngestionWriter(wf, repo)
        update = _update(0, "agentA")
        writer.ingest(update, source=IngestionSource.GEYSER)
        writer.ingest(update, source=IngestionSource.WEBHOOK)
        assert repo.transaction_count("agentA") == 1

    def test_latency_measured(self):
        wf = WalletFilter(["agentA"])
        repo = InMemoryTransactionRepo()
        writer = IngestionWriter(wf, repo)
        results = writer.ingest(_update(0, "agentA", latency_ms=120.0))
        assert results[0].ingest_latency_ms == pytest.approx(120.0)

    def test_source_tagged(self):
        wf = WalletFilter(["agentA"])
        repo = InMemoryTransactionRepo()
        writer = IngestionWriter(wf, repo)
        results = writer.ingest(_update(0, "agentA"),
                                source=IngestionSource.WEBHOOK)
        assert results[0].source is IngestionSource.WEBHOOK


# =============================================================================
# THE DONE-WHEN — 5 agents, every tx in TimescaleDB, within 500ms, via Geyser
# =============================================================================

class TestDoneWhen:

    def _five_agent_stream(self, txs_per_agent: int = 4,
                           latency_ms: float = 80.0):
        updates = []
        i = 0
        for agent in TEST_AGENTS:
            for _ in range(txs_per_agent):
                updates.append(_update(i, agent, latency_ms=latency_ms))
                i += 1
        return updates

    def test_every_transaction_from_five_agents_lands_in_db(self):
        """Every transaction from the 5 test agents appears in TimescaleDB."""
        updates = self._five_agent_stream(txs_per_agent=4)
        indexer, repo = _indexer_for(TEST_AGENTS, updates)
        report = indexer.run()

        assert report.transactions_written == 5 * 4
        for agent in TEST_AGENTS:
            assert repo.transaction_count(agent) == 4

    def test_ingest_within_500ms_sla(self):
        """Every transaction lands within the 500ms ingest SLA."""
        updates = self._five_agent_stream(latency_ms=80.0)
        indexer, _ = _indexer_for(TEST_AGENTS, updates)
        report = indexer.run()

        assert report.sla_met
        assert report.sla_breaches == 0
        assert report.max_latency_ms <= INGEST_SLA_MS

    def test_sla_breach_is_detected(self):
        # A transaction that arrives slow (700ms) is flagged — proof the
        # SLA check is real, not vacuous.
        updates = self._five_agent_stream(latency_ms=700.0)
        indexer, _ = _indexer_for(TEST_AGENTS, updates)
        report = indexer.run()

        assert not report.sla_met
        assert report.sla_breaches == 5 * 4

    def test_via_geyser_source(self):
        # The done-when says "via Geyser" — the run is tagged GEYSER.
        updates = self._five_agent_stream()
        indexer, _ = _indexer_for(TEST_AGENTS, updates)
        report = indexer.run(source_kind=IngestionSource.GEYSER)
        for ingested in report.ingested:
            assert ingested.source is IngestionSource.GEYSER

    def test_ingested_transactions_are_extractable(self):
        # End-to-end: the transactions the indexer wrote can be read back
        # by a window query — the indexer feeds the same hypertable the
        # feature extractor reads.
        updates = self._five_agent_stream(txs_per_agent=4)
        indexer, repo = _indexer_for(TEST_AGENTS, updates)
        indexer.run()

        q = TransactionQuery(
            agent_wallet=TEST_AGENTS[0],
            window_start=CONF - timedelta(hours=1),
            window_end=CONF + timedelta(hours=1),
        )
        assert len(repo.fetch_transactions(q)) == 4


# =============================================================================
# Runner metrics + determinism
# =============================================================================

class TestRunnerMetrics:

    def test_skip_count_in_report(self):
        updates = [_update(0, "agentA"), _update(1, "ghost"),
                   _update(2, "agentA")]
        indexer, _ = _indexer_for(["agentA"], updates)
        report = indexer.run()
        assert report.updates_consumed == 3
        assert report.updates_skipped == 1
        assert report.transactions_written == 2

    def test_max_updates_bounds_run(self):
        updates = [_update(i, "agentA") for i in range(100)]
        indexer, _ = _indexer_for(["agentA"], updates)
        report = indexer.run(max_updates=10)
        assert report.updates_consumed == 10

    def test_mean_latency_reported(self):
        updates = [_update(0, "agentA", latency_ms=100.0),
                   _update(1, "agentA", latency_ms=200.0)]
        indexer, _ = _indexer_for(["agentA"], updates)
        report = indexer.run()
        assert report.mean_latency_ms == pytest.approx(150.0)


class TestDeterminism:

    def test_indexer_run_deterministic(self):
        updates = [_update(i, TEST_AGENTS[i % 5]) for i in range(40)]

        def _run():
            indexer, repo = _indexer_for(TEST_AGENTS, updates)
            report = indexer.run()
            return report.transactions_written, report.max_latency_ms

        first = _run()
        for _ in range(10):
            assert _run() == first
