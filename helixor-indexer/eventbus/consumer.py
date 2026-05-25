"""
eventbus/consumer.py — the detection-pipeline Kafka consumer.

Consumes `agent.transactions`, processes each record (decode + persist +
hand to the detection pipeline), and commits offsets. Built so that
KILLING A CONSUMER MID-STREAM LOSES NOTHING — the Day-17 done-when.

THE DELIVERY GUARANTEE
----------------------
The consumer commits offsets AFTER processing, never before. So:

  poll  →  process  →  commit
                          │
            crash here ───┘  → uncommitted records redeliver to the next
                               consumer in the group → AT-LEAST-ONCE.

At-least-once means a record CAN be delivered twice (crash after process,
before commit). The consumer is therefore IDEMPOTENT — it dedups on the
transaction signature, and the downstream TimescaleDB insert is already
ON CONFLICT DO NOTHING. At-least-once delivery + idempotent processing =
effectively-once, with no transactional-coordinator fragility.

DEAD-LETTER ROUTING
-------------------
A poison message — one that fails processing every time (malformed,
undecodable) — must not block its partition forever. After
`max_retries` failures the consumer routes it to `agent.deadletter` and
commits past it, so the partition advances. Genuine transient failures
get the retries; genuine poison gets quarantined.

VULN-07 MITIGATION
------------------
Every record is signature-verified BEFORE the decoder runs. The consumer
holds a `TrustedProducerSet` (the indexer/oracle-node pubkeys allowed to
produce on this topic). A record that is unsigned, signed by an
untrusted producer, or whose signature does not verify against the
payload is FORGERY — straight to the dead-letter topic, never retried,
never decoded. A network-adjacent attacker who manages to publish onto
the bus without a trusted private key cannot inject data into scoring.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from eventbus.broker import InMemoryBroker, MessageBroker
from eventbus.serialization import SerializationError, deserialize_transaction
from eventbus.signing import (
    SignatureError,
    TrustedProducerSet,
    UntrustedProducer,
    verify_record_headers,
)
from eventbus.types import (
    ConsumedRecord,
    EventRecord,
    Topic,
    TopicPartition,
)

logger = logging.getLogger("helixor.eventbus.consumer")


# =============================================================================
# The processing callback contract
# =============================================================================

# A record processor takes (agent_wallet, Transaction) and does the real
# work — persist to TimescaleDB, hand to the detection pipeline. It returns
# nothing; it RAISES on a failure the consumer should retry / dead-letter.
RecordProcessor = Callable[[str, object], None]


# =============================================================================
# A non-retryable poison error
# =============================================================================

class PoisonMessage(Exception):
    """
    A record that can never be processed (malformed payload, schema
    mismatch). Routed straight to the dead-letter topic — retrying it is
    pointless.
    """


# =============================================================================
# ConsumeReport
# =============================================================================

@dataclass(frozen=True, slots=True)
class ConsumeReport:
    """The outcome of a consume run (or bounded segment)."""
    polled:        int          # records fetched
    processed:     int          # records successfully processed
    dead_lettered: int          # records routed to the dead-letter topic
    retried:       int          # processing retries attempted
    committed_through: dict[int, int] = field(default_factory=dict)


# =============================================================================
# DetectionConsumer
# =============================================================================

class DetectionConsumer:
    """
    The detection-pipeline consumer for `agent.transactions`.

    Construct with a broker, a consumer-group name, a consumer id, and a
    `RecordProcessor`. Call `consume` to poll-process-commit. Members of
    the same group share the topic's partitions; offsets are committed
    per-group, so a crashed consumer's partitions resume — for the next
    consumer — from the last committed offset.
    """

    # A poison message is dead-lettered after this many processing failures.
    DEFAULT_MAX_RETRIES = 3

    def __init__(
        self,
        broker:      MessageBroker,
        *,
        group:       str,
        consumer_id: str,
        processor:   RecordProcessor,
        trusted_producers: TrustedProducerSet,
        topic:       str = Topic.TRANSACTIONS.value,
        dead_letter_topic: str = Topic.DEAD_LETTER.value,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        if trusted_producers is None:
            raise ValueError(
                "DetectionConsumer requires a TrustedProducerSet — VULN-07 "
                "forbids consuming unsigned records"
            )
        self._broker = broker
        self._group = group
        self._consumer_id = consumer_id
        self._processor = processor
        self._trusted = trusted_producers
        self._topic = topic
        self._dlq = dead_letter_topic
        self._max_retries = max_retries

        # Idempotency: signatures already processed by THIS consumer
        # instance. (Cross-instance idempotency is the downstream repo's
        # ON CONFLICT — this set catches in-process redelivery cheaply.)
        self._seen_signatures: set[str] = set()

        # Retry tracking: (partition, offset) -> attempts so far. A
        # transiently-failing record is NOT re-produced (that would
        # duplicate it and confuse offsets); instead it is left uncommitted
        # so the next poll redelivers it, and this map remembers how many
        # times it has failed so it can eventually be dead-lettered.
        self._retry_counts: dict[tuple[int, int], int] = {}

        self._broker.create_topic(topic, 8)
        self._broker.create_topic(dead_letter_topic, 4)
        self._joined = False

    # ── Group membership ────────────────────────────────────────────────────

    def join(self) -> set[int]:
        """Join the consumer group; returns the partitions assigned."""
        assigned = self._broker.join_group(
            self._topic, self._group, self._consumer_id,
        )
        self._joined = True
        logger.info(
            "consumer %s joined group %s — partitions %s",
            self._consumer_id, self._group, sorted(assigned),
        )
        return assigned

    def leave(self) -> None:
        """
        Leave the group (graceful shutdown). Uncommitted records on this
        consumer's partitions are rolled back to the committed offset and
        redelivered to whoever takes over — at-least-once.
        """
        if self._joined:
            self._broker.leave_group(self._topic, self._group, self._consumer_id)
            self._joined = False
            logger.info("consumer %s left group %s", self._consumer_id, self._group)

    # ── Consume ─────────────────────────────────────────────────────────────

    def consume(self, *, max_records: int = 100) -> ConsumeReport:
        """
        One poll-process-commit cycle.

        Polls up to `max_records`, processes each, and commits the offsets
        of everything successfully handled (processed OR dead-lettered).
        A record that failed transiently (still has retries left) is NOT
        committed: the consumer SEEKS its partition back to the committed
        offset so the record redelivers on the next poll. The retry count
        per (partition, offset) is tracked so a genuine poison message is
        eventually dead-lettered rather than retried forever.

        The commit happens AFTER processing — that ordering is the
        at-least-once guarantee.
        """
        if not self._joined:
            self.join()

        batch = self._broker.poll(
            self._topic, self._group, self._consumer_id, max_records,
        )
        if not batch:
            return ConsumeReport(polled=0, processed=0, dead_lettered=0,
                                 retried=0)

        processed = 0
        dead_lettered = 0
        retried = 0
        # partition -> highest offset we may commit (contiguous from start).
        commit_frontier: dict[int, int] = {}
        # partitions to rewind because a record on them must be retried.
        seek_back: set[int] = set()

        for consumed in batch:
            if consumed.partition in seek_back:
                # An earlier record on this partition is retrying; do not
                # process anything after it (preserve per-partition order).
                continue
            outcome = self._handle(consumed)
            retried += outcome["retried"]
            if outcome["done"]:
                commit_frontier[consumed.partition] = consumed.offset + 1
                if outcome["dead_lettered"]:
                    dead_lettered += 1
                else:
                    processed += 1
            else:
                # Transient failure with retries left — rewind this
                # partition so the record redelivers; stop advancing it.
                seek_back.add(consumed.partition)

        if commit_frontier:
            self._broker.commit(self._topic, self._group, commit_frontier)
        if seek_back:
            self._broker.seek_to_committed(
                self._topic, self._group, seek_back,
            )

        return ConsumeReport(
            polled=len(batch),
            processed=processed,
            dead_lettered=dead_lettered,
            retried=retried,
            committed_through=commit_frontier,
        )

    def consume_until_empty(self, *, max_records: int = 100) -> ConsumeReport:
        """Consume repeatedly until a poll returns nothing. Aggregates."""
        polled = processed = dead_lettered = retried = 0
        committed: dict[int, int] = {}
        # A safety bound: a record can be retried at most max_retries times
        # before it is dead-lettered, so the loop is finite. This cap is a
        # belt-and-braces guard against an unforeseen non-terminating case.
        max_iterations = 10_000
        for _ in range(max_iterations):
            report = self.consume(max_records=max_records)
            if report.polled == 0:
                break
            polled += report.polled
            processed += report.processed
            dead_lettered += report.dead_lettered
            retried += report.retried
            committed.update(report.committed_through)
            # Forward progress = something was processed, dead-lettered, OR
            # retried (a retry re-enqueues the record with a higher retry
            # count, so it WILL eventually terminate via dead-lettering).
            # Only a poll that did NOTHING means we are stuck.
            if (report.processed == 0 and report.dead_lettered == 0
                    and report.retried == 0):
                break
        return ConsumeReport(
            polled=polled, processed=processed, dead_lettered=dead_lettered,
            retried=retried, committed_through=committed,
        )

    # ── Per-record handling ─────────────────────────────────────────────────

    def _handle(self, consumed: ConsumedRecord) -> dict:
        """
        Process one record. Returns:
          done          — True if the record is fully handled (do not
                           redeliver): processed OR dead-lettered.
          dead_lettered — True if it was routed to the DLQ.
          retried       — retry attempts made on this call (0 or 1).
        """
        record = consumed.record

        # ── VULN-07: verify provenance BEFORE decoding. ─────────────────────
        # An unsigned / untrusted / tampered record is forgery, not malformed
        # data — it never enters the decoder, never enters the processor, and
        # is never retried. Straight to dead-letter, every time. Forgery
        # retries help nothing and burn partition progress.
        try:
            verify_record_headers(
                record.value, record.headers, self._trusted,
            )
        except UntrustedProducer as exc:
            logger.error(
                "VULN-07: untrusted producer at %s/%d — %s; dead-lettering",
                consumed.topic, consumed.offset, exc,
            )
            self._dead_letter(record, reason=f"untrusted producer: {exc}")
            return {"done": True, "dead_lettered": True, "retried": 0}
        except SignatureError as exc:
            logger.error(
                "VULN-07: signature verification failed at %s/%d — %s; "
                "dead-lettering",
                consumed.topic, consumed.offset, exc,
            )
            self._dead_letter(record, reason=f"bad signature: {exc}")
            return {"done": True, "dead_lettered": True, "retried": 0}

        # ── Decode. A decode failure is POISON — never retried. ─────────────
        try:
            agent_wallet, transaction = deserialize_transaction(record.value)
        except SerializationError as exc:
            logger.error(
                "poison record at %s/%d — %s; dead-lettering",
                consumed.topic, consumed.offset, exc,
            )
            self._dead_letter(record, reason=f"decode failed: {exc}")
            return {"done": True, "dead_lettered": True, "retried": 0}

        # ── Idempotent dedup. ───────────────────────────────────────────────
        if transaction.signature in self._seen_signatures:
            logger.debug("duplicate %s — skipping (idempotent)",
                         transaction.signature[:16])
            return {"done": True, "dead_lettered": False, "retried": 0}

        # ── Process. A processing failure IS retried, up to max_retries. ────
        offset_key = (consumed.partition, consumed.offset)
        try:
            self._processor(agent_wallet, transaction)
        except PoisonMessage as exc:
            logger.error("processor flagged poison: %s; dead-lettering", exc)
            self._dead_letter(record, reason=f"poison: {exc}")
            self._retry_counts.pop(offset_key, None)
            return {"done": True, "dead_lettered": True, "retried": 0}
        except Exception as exc:                       # noqa: BLE001
            attempts = self._retry_counts.get(offset_key, 0) + 1
            if attempts > self._max_retries:
                logger.error(
                    "record at %s/%d exhausted %d retries — %s; dead-lettering",
                    consumed.topic, consumed.offset, self._max_retries, exc,
                )
                self._dead_letter(record, reason=f"max retries: {exc}")
                self._retry_counts.pop(offset_key, None)
                return {"done": True, "dead_lettered": True, "retried": 0}
            # Track the attempt; the record stays uncommitted and will be
            # redelivered (the consumer seeks its partition back).
            self._retry_counts[offset_key] = attempts
            logger.warning(
                "processing failed (retry %d/%d) at %s/%d: %s",
                attempts, self._max_retries, consumed.topic,
                consumed.offset, exc,
            )
            return {"done": False, "dead_lettered": False, "retried": 1}

        # ── Success. ────────────────────────────────────────────────────────
        self._seen_signatures.add(transaction.signature)
        self._retry_counts.pop(offset_key, None)
        return {"done": True, "dead_lettered": False, "retried": 0}

    def _dead_letter(self, record: EventRecord, *, reason: str) -> None:
        """Route a poison record to the dead-letter topic."""
        self._broker.produce(
            self._dlq, record.dead_lettered_from(self._topic, reason),
        )
