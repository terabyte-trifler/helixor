"""
indexer/runner.py — the Geyser indexer runner.

Ties the pieces together: consume the `StreamSource`, filter for registered
agents, decode, persist, measure latency. This is the long-running process
that streams every transaction touching a registered agent wallet off
Geyser and lands it in TimescaleDB.

It is deliberately thin — the StreamSource, WalletFilter, and
IngestionWriter carry the real logic, each tested in isolation. The runner
is the loop plus metrics plus the latency-SLA check.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from indexer.production_config import assert_source_verified_for_cluster
from indexer.stream import StreamSource
from indexer.types import IngestedTransaction, IngestionSource
from indexer.writer import IngestionWriter

logger = logging.getLogger("phylanx.indexer.runner")


# The end-to-end ingest SLA: a transaction must reach TimescaleDB within
# this many milliseconds of on-chain confirmation (the Day-16 done-when).
INGEST_SLA_MS = 500.0


# =============================================================================
# RunReport
# =============================================================================

@dataclass(frozen=True, slots=True)
class RunReport:
    """The outcome of an indexer run (or a bounded run segment, in tests)."""
    updates_consumed:   int
    transactions_written: int
    updates_skipped:    int          # touched no registered agent
    decode_errors:      int
    sla_breaches:       int          # ingests slower than INGEST_SLA_MS
    max_latency_ms:     float
    mean_latency_ms:    float
    ingested:           tuple[IngestedTransaction, ...] = field(default_factory=tuple)

    @property
    def sla_met(self) -> bool:
        """True iff every measured ingest landed within the SLA."""
        return self.sla_breaches == 0


# =============================================================================
# The runner
# =============================================================================

class GeyserIndexer:
    """
    The Geyser indexer. Construct with a `StreamSource` and an
    `IngestionWriter`; call `run()` to consume the stream.

    `run()` consumes until the stream is exhausted. A live Yellowstone
    stream never exhausts — the loop runs for the life of the process; a
    synthetic `ListStreamSource` exhausts, which is what makes the runner
    testable.
    """

    __slots__ = ("_source", "_writer")

    def __init__(self, source: StreamSource, writer: IngestionWriter) -> None:
        # TA-2: pre-flight gate. On mainnet, refuses any source that does
        # not advertise `is_verified_consensus_source = True`. On non-mainnet
        # this is a no-op so devnet/localnet runners stay simple.
        assert_source_verified_for_cluster(source)
        self._source = source
        self._writer = writer

    def run(
        self,
        *,
        source_kind: IngestionSource = IngestionSource.GEYSER,
        max_updates: int | None = None,
    ) -> RunReport:
        """
        Consume the stream, ingesting every update.

        `max_updates` bounds the run (tests, controlled segments); None
        runs until the stream exhausts.

        Returns a `RunReport` with throughput + latency metrics, including
        whether the INGEST_SLA_MS budget was met.
        """
        consumed = 0
        latencies: list[float] = []
        ingested: list[IngestedTransaction] = []

        for update in self._source.updates():
            results = self._writer.ingest(update, source=source_kind)
            consumed += 1
            ingested.extend(results)
            for result in results:
                if result.ingest_latency_ms is not None:
                    latencies.append(result.ingest_latency_ms)

            if max_updates is not None and consumed >= max_updates:
                break

        sla_breaches = sum(1 for ms in latencies if ms > INGEST_SLA_MS)
        max_latency = max(latencies) if latencies else 0.0
        mean_latency = sum(latencies) / len(latencies) if latencies else 0.0

        report = RunReport(
            updates_consumed=consumed,
            transactions_written=self._writer.written_count,
            updates_skipped=self._writer.skipped_count,
            decode_errors=self._writer.decode_error_count,
            sla_breaches=sla_breaches,
            max_latency_ms=max_latency,
            mean_latency_ms=mean_latency,
            ingested=tuple(ingested),
        )
        logger.info(
            "indexer run: %d updates, %d written, %d skipped, %d SLA breaches, "
            "max latency %.1fms",
            report.updates_consumed, report.transactions_written,
            report.updates_skipped, report.sla_breaches, report.max_latency_ms,
        )
        return report
