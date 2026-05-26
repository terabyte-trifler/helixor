"""
eventbus/types.py — typed contracts for the Helixor Kafka event pipeline.

Day 17 inserts Kafka between the Geyser indexer and the detection
pipeline. The MVP processed transactions synchronously; V2 needs
guaranteed delivery and decoupled ingest/scoring so a scoring slowdown
never backs up ingestion, and so sub-epoch adversarial alerts can fire
without waiting for the 24h epoch.

This module defines the records that flow through the bus and the topic
names. The broker abstraction is in eventbus/broker.py; the producer and
consumer in eventbus/producer.py / consumer.py.

A NOTE ON "EXACTLY-ONCE"
------------------------
Kafka delivers AT-LEAST-ONCE by default. True end-to-end exactly-once
needs idempotent producers + transactional reads — and even then it is
"effectively once". Helixor's design is the pragmatic, correct one:
AT-LEAST-ONCE delivery from the bus + IDEMPOTENT processing on the
consumer (dedup on transaction signature; the TimescaleDB insert is
already ON CONFLICT DO NOTHING). At-least-once + an idempotent consumer
= effectively-once, with none of the transactional-coordinator fragility.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone


# =============================================================================
# Topic names
# =============================================================================

class Topic(str, enum.Enum):
    """The Kafka topics the Helixor pipeline uses."""
    # Every transaction the Geyser indexer ingests. Consumed by the
    # detection pipeline.
    TRANSACTIONS = "agent.transactions"
    # The security layer's IMMEDIATE_RED fast-path. Sub-epoch — these
    # adversarial alerts cannot wait for the 24h epoch.
    ALERTS       = "agent.alerts"
    # Poison messages — records that failed processing past the retry
    # limit. Quarantined here so they never block a partition.
    DEAD_LETTER  = "agent.deadletter"
    # VULN-14 TOPIC ISOLATION. Certificate-revocation / cert-blocked
    # events live on their OWN topic so they cannot be backed up behind
    # high-volume general telemetry (`agent.transactions`). The cert
    # path's consumer group reads ONLY this topic, so its lag is
    # bounded by cert-event throughput, not by telemetry storms — the
    # exact attack the audit flagged (drown the bus with VULN-07-style
    # spam, induce a stale scoring window). Per-partition keying is
    # still by `agent_wallet`, so per-agent ordering of cert events is
    # preserved.
    CERT_EVENTS  = "agent.cert_events"
    # OFAC-1 SILENT-DELIST TRANSPARENCY. The cluster considered an
    # (agent_wallet, epoch) pair for cert issuance and DECLINED. The
    # substrate is `helixor-oracle/oracle/cert_refusal_log.py` —
    # every per-agent gate (NSS-3, FRP-3, PDS-2, AW-01, AW-01-EXT,
    # quorum, threshold-sig) drops a structured `CertRefusal` here.
    # The auditable property: a captured cluster cannot SILENTLY
    # refuse to score an OFAC-pressured agent, because every refusal
    # carries a stable reason code + the deciding gate. Indexer
    # audit script `audit/cert_refusal_check.py` flags suspicious
    # patterns (`OPERATOR_OVERRIDE` codes, per-jurisdiction-tagged
    # refusal-rate spikes, repeated refusals against a single agent
    # without a corresponding incident-response entry). Per-partition
    # keying is by `agent_wallet`, so per-agent ordering of refusals
    # is preserved across the topic.
    CERT_REFUSED = "agent.cert_events.refused"


# =============================================================================
# EventRecord — one message on the bus
# =============================================================================

@dataclass(frozen=True, slots=True)
class EventRecord:
    """
    One message on a Kafka topic, broker-agnostic.

    `key` is the partition key — Kafka routes all records with the same key
    to the same partition, which preserves per-key ordering. Helixor keys
    by `agent_wallet`, so every transaction for an agent is processed in
    order by a single consumer.

    `value` is the serialised payload (bytes — the wire format). `headers`
    carry metadata (retry count, original topic for dead-lettered records).
    """
    key:     str
    value:   bytes
    headers: dict[str, str] = field(default_factory=dict)
    # Stamped by the producer; carried for latency / ordering diagnostics.
    produced_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.value, (bytes, bytearray)):
            raise TypeError(
                f"EventRecord.value must be bytes, got {type(self.value).__name__}"
            )
        if not isinstance(self.value, bytes):
            object.__setattr__(self, "value", bytes(self.value))

    @property
    def retry_count(self) -> int:
        """How many times processing this record has been retried."""
        return int(self.headers.get("retry_count", "0"))

    def with_retry_incremented(self) -> "EventRecord":
        """A copy with retry_count bumped — used on a processing failure."""
        headers = dict(self.headers)
        headers["retry_count"] = str(self.retry_count + 1)
        return EventRecord(
            key=self.key, value=self.value, headers=headers,
            produced_at=self.produced_at,
        )

    def dead_lettered_from(self, topic: str, reason: str = "") -> "EventRecord":
        """A copy tagged with the topic it was dead-lettered from + why."""
        headers = dict(self.headers)
        headers["dead_letter_origin"] = topic
        if reason:
            headers["dead_letter_reason"] = reason
        return EventRecord(
            key=self.key, value=self.value, headers=headers,
            produced_at=self.produced_at,
        )


# =============================================================================
# ConsumedRecord — an EventRecord paired with its position
# =============================================================================

@dataclass(frozen=True, slots=True)
class ConsumedRecord:
    """
    An `EventRecord` as delivered to a consumer — paired with the partition
    and offset it came from, so the consumer can commit its position.
    """
    topic:     str
    partition: int
    offset:    int
    record:    EventRecord

    @property
    def key(self) -> str:
        return self.record.key

    @property
    def value(self) -> bytes:
        return self.record.value


# =============================================================================
# TopicPartition + offset
# =============================================================================

@dataclass(frozen=True, slots=True)
class TopicPartition:
    """A (topic, partition) pair — the unit of offset tracking."""
    topic:     str
    partition: int


class DeliveryError(Exception):
    """Raised on a produce/consume failure."""
