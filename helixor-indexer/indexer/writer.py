"""
indexer/writer.py — the ingestion writer: decode + persist + latency.

Takes a `GeyserTransactionUpdate`, resolves which registered agents it
belongs to, decodes it to the oracle's `Transaction`, persists it to
TimescaleDB through the Day-15 repository, and measures ingest latency.

The writer is the bridge between the indexer and the Day-15 storage
layer. It writes through the SAME `TransactionRepository` abstraction the
feature extractor reads through — Geyser ingestion and feature extraction
meet at the hypertable.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from indexer.decoder import DecodeError, decode_transaction
from indexer.stream import WalletFilter
from indexer.types import (
    GeyserTransactionUpdate,
    IngestedTransaction,
    IngestionSource,
)

# Shared types/repository from the oracle (same path setup as the decoder).
_ORACLE_ROOT = Path(__file__).resolve().parents[2] / "helixor-oracle"
if str(_ORACLE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ORACLE_ROOT))

from db.repository import TransactionRepository  # noqa: E402

logger = logging.getLogger("helixor.indexer.writer")


# =============================================================================
# IngestionWriter
# =============================================================================

class IngestionWriter:
    """
    Decodes Geyser updates and writes them to TimescaleDB.

    Construct with a `WalletFilter` (which agents are registered) and a
    `TransactionRepository` (where transactions land). One update can
    produce MORE than one write — a transaction touching two registered
    agents is recorded once per agent.
    """

    __slots__ = ("_filter", "_repo", "_written", "_skipped", "_decode_errors")

    def __init__(
        self,
        wallet_filter: WalletFilter,
        repository:    TransactionRepository,
    ) -> None:
        self._filter = wallet_filter
        self._repo = repository
        self._written = 0
        self._skipped = 0
        self._decode_errors = 0

    # ── Metrics ─────────────────────────────────────────────────────────────

    @property
    def written_count(self) -> int:
        return self._written

    @property
    def skipped_count(self) -> int:
        return self._skipped

    @property
    def decode_error_count(self) -> int:
        return self._decode_errors

    # ── Ingest ──────────────────────────────────────────────────────────────

    def ingest(
        self,
        update: GeyserTransactionUpdate,
        *,
        source: IngestionSource = IngestionSource.GEYSER,
    ) -> list[IngestedTransaction]:
        """
        Ingest one Geyser update: decode it for every registered agent it
        touches and persist each result.

        Returns the list of `IngestedTransaction`s written (empty if the
        update touches no registered agent). A decode failure for one agent
        is contained — it is logged and counted, the others still write.
        """
        agents = self._filter.matching_agents(update)
        if not agents:
            self._skipped += 1
            return []

        latency_ms = _ingest_latency_ms(update)
        out: list[IngestedTransaction] = []

        for agent_wallet in agents:
            try:
                transaction = decode_transaction(update, agent_wallet)
            except DecodeError as exc:
                self._decode_errors += 1
                logger.error(
                    "decode failed for agent %s on %s: %s",
                    agent_wallet, update.signature[:16], exc,
                )
                continue

            # Persist through the Day-15 repository. The repository's insert
            # is idempotent (ON CONFLICT DO NOTHING) — a transaction seen by
            # both Geyser and the webhook fallback is written once.
            self._repo.insert_transaction(agent_wallet, transaction)
            self._written += 1
            out.append(IngestedTransaction(
                agent_wallet=agent_wallet,
                transaction=transaction,
                source=source,
                ingest_latency_ms=latency_ms,
            ))

        return out


# =============================================================================
# Latency
# =============================================================================

def _ingest_latency_ms(update: GeyserTransactionUpdate) -> float | None:
    """
    Ingest latency in milliseconds: on-chain confirmation (`block_time`) to
    the instant the indexer received the update (`received_at`).

    None when the update carries no `received_at` stamp.
    """
    if update.received_at is None:
        return None
    delta = update.received_at - update.block_time
    return delta.total_seconds() * 1000.0
