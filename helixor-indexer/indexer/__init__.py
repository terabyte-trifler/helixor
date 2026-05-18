"""
helixor-indexer — the Geyser indexer.

Streams every transaction touching a registered agent wallet off a
Geyser-enabled RPC (Yellowstone gRPC) and writes it to TimescaleDB within
~500ms of on-chain confirmation. The Helius webhook receiver runs alongside
as a fallback / reconciliation source.

Public API:
    GeyserIndexer, RunReport, INGEST_SLA_MS      the runner
    IngestionWriter                              decode + persist
    WalletFilter, StreamSource, ListStreamSource the stream + filter
    decode_transaction, DecodeError              the pure decoder
    WebhookReceiver, decode_webhook_payload      the webhook fallback
    reconcile_agent, reconcile_all,              the reconciler
        ReconciliationResult, DivergenceSeverity
    YellowstoneStreamSource, YellowstoneConfig   the live gRPC edge
    GeyserTransactionUpdate, GeyserAccountChange,
        IngestedTransaction, IngestionSource     the types
"""

from __future__ import annotations

from indexer.decoder import DecodeError, decode_transaction
from indexer.reconciler import (
    DivergenceSeverity,
    ReconciliationReport,
    ReconciliationResult,
    reconcile_agent,
    reconcile_all,
)
from indexer.runner import INGEST_SLA_MS, GeyserIndexer, RunReport
from indexer.stream import ListStreamSource, StreamSource, WalletFilter
from indexer.types import (
    GeyserAccountChange,
    GeyserTransactionUpdate,
    IngestedTransaction,
    IngestionSource,
)
from indexer.webhook_fallback import (
    WebhookDecodeError,
    WebhookReceiver,
    decode_webhook_payload,
)
from indexer.writer import IngestionWriter
from indexer.yellowstone import (
    YellowstoneConfig,
    YellowstoneStreamSource,
    map_subscribe_update,
)

__all__ = [
    "GeyserIndexer", "RunReport", "INGEST_SLA_MS",
    "IngestionWriter",
    "WalletFilter", "StreamSource", "ListStreamSource",
    "decode_transaction", "DecodeError",
    "WebhookReceiver", "decode_webhook_payload", "WebhookDecodeError",
    "reconcile_agent", "reconcile_all",
    "ReconciliationResult", "ReconciliationReport", "DivergenceSeverity",
    "YellowstoneStreamSource", "YellowstoneConfig", "map_subscribe_update",
    "GeyserTransactionUpdate", "GeyserAccountChange",
    "IngestedTransaction", "IngestionSource",
]
