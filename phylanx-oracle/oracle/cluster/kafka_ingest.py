"""
oracle/cluster/kafka_ingest.py — Day-17 Kafka bus → Day-23 cluster bridge.

Day 17 built the Geyser → Kafka event bus (phylanx-indexer/eventbus). The
indexer publishes per-agent transactions to the `agent.transactions`
topic; the cluster consumes them and runs detection. Day 28 wires the two
ends together explicitly.

WHY A SEPARATE INGESTION LAYER
------------------------------
The cluster takes `AgentEpochInput` per agent — a structured object with
the transactions, the baseline reference, the market context, etc. The
event bus delivers raw transaction events. The bridge BATCHES events per
agent and assembles the AgentEpochInput. This separation keeps the
cluster's detection path pure (no Kafka in the determinism-critical zone)
and makes the integration explicit.

DETERMINISM
-----------
The in-memory broker (`InMemoryBroker` from phylanx-indexer) is fully
deterministic — it replays the same events in the same order. So a full
pipeline test on the in-memory broker reproduces byte-identically. The
real `confluent_adapter` is for deployment only.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone

from features import ExtractionWindow, Transaction

logger = logging.getLogger("phylanx.oracle.cluster.kafka_ingest")


# =============================================================================
# Per-agent transaction batch
# =============================================================================

@dataclass(frozen=True, slots=True)
class IngestedAgentBatch:
    """One agent's transactions, harvested from the event bus for an epoch."""
    agent_wallet: str
    transactions: tuple[Transaction, ...]
    window:       ExtractionWindow

    @property
    def transaction_count(self) -> int:
        return len(self.transactions)


# =============================================================================
# Build per-agent batches from a raw transaction stream
# =============================================================================

def batch_transactions_by_agent(
    transactions: Iterable[Transaction],
    *,
    window:       ExtractionWindow,
) -> list[IngestedAgentBatch]:
    """
    Group a flat stream of transactions into per-agent batches.

    The event bus delivers transactions in arrival order; the cluster
    consumes them per agent. We group by `agent_wallet`, sort each agent's
    transactions by timestamp (canonical order — same as the feature
    extractor expects), and emit one `IngestedAgentBatch` per agent.

    Pure + deterministic given its inputs.
    """
    by_agent: dict[str, list[Transaction]] = {}
    for txn in transactions:
        by_agent.setdefault(txn.agent_wallet, []).append(txn)

    batches: list[IngestedAgentBatch] = []
    for wallet in sorted(by_agent):
        ordered = tuple(sorted(by_agent[wallet], key=_txn_sort_key))
        batches.append(IngestedAgentBatch(
            agent_wallet=wallet, transactions=ordered, window=window,
        ))
    return batches


def _txn_sort_key(t: Transaction):
    """Sort transactions by (timestamp, signature) — deterministic."""
    ts = getattr(t, "block_time", None) or getattr(t, "timestamp", None) or 0
    sig = getattr(t, "signature", "") or ""
    return (ts, sig)


# =============================================================================
# Replay transactions from the Day-17 event bus
# =============================================================================

def replay_from_broker(
    broker,
    *,
    topic:         str = "agent.transactions",
    group:         str = "oracle-cluster",
    consumer_id:   str = "oracle-cluster-day28",
    max_messages:  int = 10_000,
) -> list[Transaction]:
    """
    Drain transactions from the Day-17 event bus and decode them.

    This is the gluing layer: the bus carries `EventRecord`s (Day-17
    payloads); the cluster wants `Transaction`s (the feature-extractor
    type). We decode in this layer and hand the cluster typed inputs.

    The function consumes up to `max_messages` from one consumer; the
    in-memory broker replays the topic deterministically. In production the
    `confluent_adapter` (real Kafka) drives this same code unchanged.
    """
    try:
        from eventbus.serialization import decode_transaction
    except ImportError:                                 # pragma: no cover
        # If the eventbus serializer is unavailable in this stack split,
        # fall back to no transactions — the pipeline still runs (it just
        # has nothing to score), so the path is exercised structurally.
        logger.warning("eventbus.serialization not importable from oracle "
                       "stack; replay returns an empty list")
        return []

    # Join the consumer group and read its assigned partitions.
    partitions = broker.join_group(topic, group, consumer_id)
    transactions: list[Transaction] = []
    consumed = 0
    while consumed < max_messages:
        records = broker.poll(
            topic, group, consumer_id, max_records=64,
        )
        if not records:
            break
        for record in records:
            try:
                txn = decode_transaction(record.value)
                transactions.append(txn)
                consumed += 1
            except Exception as exc:                    # noqa: BLE001
                logger.warning("ignoring undecodable bus record: %s", exc)
        broker.commit(topic, group, consumer_id)

    return transactions
