"""
tests/test_eventbus_pipeline.py — the Kafka event pipeline.

THE DAY-17 DONE-WHEN
--------------------
"A transaction flows Geyser -> Kafka -> detection consumer with
 at-least-once delivery; killing a consumer mid-stream loses nothing."
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from eventbus import (
    AlertProducer,
    DetectionConsumer,
    Ed25519PayloadSigner,
    InMemoryBroker,
    PoisonMessage,
    Topic,
    TransactionProducer,
    TrustedProducer,
    TrustedProducerSet,
    attach_signature,
)
from eventbus.serialization import (
    SerializationError,
    deserialize_alert,
    deserialize_transaction,
    serialize_transaction,
)
from eventbus.types import EventRecord
from features.types import Transaction


CONF = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
PROG = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"


# VULN-07: every test producer needs a signer + every consumer needs a
# matching trusted-producer set. These helpers build a paired (signer,
# trusted-set) so tests can drop them into the call sites unchanged.
def _make_signer() -> Ed25519PayloadSigner:
    return Ed25519PayloadSigner.from_seed(b"helixor-test-producer-seed-01")


def _trusted_for(signer: Ed25519PayloadSigner) -> TrustedProducerSet:
    return TrustedProducerSet([
        TrustedProducer(name="indexer-test", public_key=signer.public_key),
    ])


def _sign_value_for(broker: InMemoryBroker, value: bytes) -> dict:
    """Build signed headers for a raw payload (used by direct-broker tests)."""
    return attach_signature(value, _make_signer())


def _tx(i: int) -> Transaction:
    return Transaction(
        signature=f"sig{i:08d}".ljust(64, "x"),
        slot=300_000_000 + i,
        block_time=CONF,
        success=(i % 7) != 0,
        program_ids=(PROG,),
        sol_change=-500_000 if i % 2 else 1_000_000,
        fee=5000, priority_fee=100, compute_units=200_000,
        counterparty=f"cp{i % 5}",
    )


def _agent(i: int) -> str:
    return f"agent{i}".ljust(44, "x")


# =============================================================================
# Serialization — the wire format round-trips exactly
# =============================================================================

class TestSerialization:

    def test_transaction_round_trips(self):
        tx = _tx(42)
        data = serialize_transaction(_agent(0), tx)
        agent_wallet, decoded = deserialize_transaction(data)
        assert agent_wallet == _agent(0)
        assert decoded == tx

    def test_round_trip_is_byte_identical(self):
        # Serialise -> deserialise -> re-serialise: identical bytes. The
        # consumer's signature-dedup depends on this stability.
        tx = _tx(7)
        once = serialize_transaction(_agent(0), tx)
        _, decoded = deserialize_transaction(once)
        twice = serialize_transaction(_agent(0), decoded)
        assert once == twice

    def test_serialization_is_deterministic(self):
        tx = _tx(1)
        first = serialize_transaction(_agent(0), tx)
        for _ in range(10):
            assert serialize_transaction(_agent(0), tx) == first

    def test_malformed_bytes_raise(self):
        with pytest.raises(SerializationError):
            deserialize_transaction(b"not json")

    def test_wire_version_mismatch_raises(self):
        import json
        bad = json.dumps({"wire_version": 999}).encode("utf-8")
        with pytest.raises(SerializationError, match="wire version"):
            deserialize_transaction(bad)


# =============================================================================
# Producer
# =============================================================================

class TestProducer:

    def test_produces_to_transactions_topic(self):
        broker = InMemoryBroker()
        producer = TransactionProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        producer.produce(_agent(0), _tx(0))
        assert broker.total_records(Topic.TRANSACTIONS.value) == 1

    def test_produce_count(self):
        broker = InMemoryBroker()
        producer = TransactionProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        for i in range(15):
            producer.produce(_agent(i % 3), _tx(i))
        assert producer.produced_count == 15

    def test_keyed_by_agent_wallet(self):
        # All of one agent's transactions land on a single partition.
        broker = InMemoryBroker()
        producer = TransactionProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        for i in range(20):
            producer.produce(_agent(0), _tx(i))
        topic = Topic.TRANSACTIONS.value
        non_empty = sum(
            1 for p in range(broker.partition_count(topic))
            if broker.high_watermark(topic, p) > 0
        )
        assert non_empty == 1


# =============================================================================
# THE DONE-WHEN — Geyser -> Kafka -> detection consumer, at-least-once
# =============================================================================

class TestDoneWhenBasicFlow:

    def test_transaction_flows_through_the_bus(self):
        """A transaction flows Geyser -> Kafka -> detection consumer."""
        broker = InMemoryBroker()
        producer = TransactionProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        # The "Geyser indexer" produces.
        producer.produce(_agent(0), _tx(0))

        # The "detection pipeline" consumes.
        delivered = []
        consumer = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            trusted_producers=_trusted_for(_make_signer()),
            processor=lambda aw, tx: delivered.append((aw, tx)),
        )
        report = consumer.consume_until_empty()

        assert report.processed == 1
        assert len(delivered) == 1
        assert delivered[0][0] == _agent(0)
        assert delivered[0][1].signature == _tx(0).signature

    def test_all_transactions_delivered(self):
        broker = InMemoryBroker()
        producer = TransactionProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        for i in range(50):
            producer.produce(_agent(i % 5), _tx(i))

        delivered = []
        consumer = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            trusted_producers=_trusted_for(_make_signer()),
            processor=lambda aw, tx: delivered.append(tx.signature),
        )
        consumer.consume_until_empty()
        assert len(set(delivered)) == 50

    def test_idempotent_no_duplicate_processing(self):
        # A record delivered twice (the consumer dedups on signature) is
        # processed once. at-least-once delivery + idempotent consumer.
        broker = InMemoryBroker()
        producer = TransactionProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        tx = _tx(0)
        producer.produce(_agent(0), tx)

        delivered = []
        consumer = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            trusted_producers=_trusted_for(_make_signer()),
            processor=lambda aw, t: delivered.append(t.signature),
        )
        consumer.consume_until_empty()
        # Re-produce the SAME transaction.
        producer.produce(_agent(0), tx)
        consumer.consume_until_empty()

        # Delivered to the processor once — the dedup caught the duplicate.
        assert delivered.count(tx.signature) == 1


# =============================================================================
# THE DONE-WHEN — killing a consumer mid-stream loses nothing
# =============================================================================

class TestDoneWhenConsumerCrash:

    def test_crash_after_commit_loses_nothing(self):
        # c1 processes + commits some, then leaves. c2 processes the rest.
        broker = InMemoryBroker()
        producer = TransactionProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        for i in range(30):
            producer.produce(_agent(i % 3), _tx(i))

        c1_seen = []
        c1 = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            trusted_producers=_trusted_for(_make_signer()),
            processor=lambda aw, t: c1_seen.append(t.signature),
        )
        c1.join()
        c1.consume(max_records=10)               # process + commit a batch
        c1.leave()                               # graceful shutdown

        c2_seen = []
        c2 = DetectionConsumer(
            broker, group="detection", consumer_id="c2",
            trusted_producers=_trusted_for(_make_signer()),
            processor=lambda aw, t: c2_seen.append(t.signature),
        )
        c2.consume_until_empty()

        assert len(set(c1_seen) | set(c2_seen)) == 30

    def test_crash_before_commit_redelivers(self):
        # THE CORE GUARANTEE: c1 polls + processes records but crashes
        # BEFORE committing. c2 must re-receive every uncommitted record —
        # nothing is lost.
        broker = InMemoryBroker()
        broker.create_topic(Topic.TRANSACTIONS.value, 1)   # 1 partition
        producer = TransactionProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        for i in range(10):
            producer.produce(_agent(0), _tx(i))

        # c1 manually polls + processes — but we simulate a crash by
        # NEVER calling consume() (which commits). It just leaves.
        c1 = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            trusted_producers=_trusted_for(_make_signer()),
            processor=lambda aw, t: None,
        )
        c1.join()
        broker.poll(Topic.TRANSACTIONS.value, "detection", "c1", 10)
        # c1 crashes — leaves without ANY commit.
        c1.leave()

        # c2 takes over.
        c2_seen = []
        c2 = DetectionConsumer(
            broker, group="detection", consumer_id="c2",
            trusted_producers=_trusted_for(_make_signer()),
            processor=lambda aw, t: c2_seen.append(t.signature),
        )
        c2.consume_until_empty()

        # All 10 redelivered — the uncommitted reads were not lost.
        assert len(set(c2_seen)) == 10

    def test_partial_commit_redelivers_only_uncommitted(self):
        broker = InMemoryBroker()
        broker.create_topic(Topic.TRANSACTIONS.value, 1)
        producer = TransactionProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        for i in range(10):
            producer.produce(_agent(0), _tx(i))

        c1_seen = []
        c1 = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            trusted_producers=_trusted_for(_make_signer()),
            processor=lambda aw, t: c1_seen.append(t.signature),
        )
        c1.join()
        c1.consume(max_records=4)                # process + commit 4
        c1.leave()

        c2_seen = []
        c2 = DetectionConsumer(
            broker, group="detection", consumer_id="c2",
            trusted_producers=_trusted_for(_make_signer()),
            processor=lambda aw, t: c2_seen.append(t.signature),
        )
        c2.consume_until_empty()

        # c1 committed 4; c2 sees the remaining 6.
        assert len(c1_seen) == 4
        assert len(c2_seen) == 6
        # Together, every transaction exactly once.
        assert set(c1_seen).isdisjoint(set(c2_seen))
        assert len(set(c1_seen) | set(c2_seen)) == 10


# =============================================================================
# Dead-letter routing
# =============================================================================

class TestDeadLetter:

    def test_poison_message_dead_lettered(self):
        # A garbage record (undecodable) is routed to the DLQ, not retried.
        broker = InMemoryBroker()
        broker.create_topic(Topic.TRANSACTIONS.value, 1)
        broker.produce(Topic.TRANSACTIONS.value,
                       EventRecord(key=_agent(0), value=b"garbage not json"))

        consumer = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            trusted_producers=_trusted_for(_make_signer()),
            processor=lambda aw, t: None,
        )
        report = consumer.consume_until_empty()
        assert report.dead_lettered == 1
        assert broker.total_records(Topic.DEAD_LETTER.value) == 1

    def test_poison_does_not_block_partition(self):
        # A poison record between two good ones: the good ones still process.
        broker = InMemoryBroker()
        broker.create_topic(Topic.TRANSACTIONS.value, 1)
        producer = TransactionProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        producer.produce(_agent(0), _tx(0))
        broker.produce(Topic.TRANSACTIONS.value,
                       EventRecord(key=_agent(0), value=b"poison"))
        producer.produce(_agent(0), _tx(1))

        delivered = []
        consumer = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            trusted_producers=_trusted_for(_make_signer()),
            processor=lambda aw, t: delivered.append(t.signature),
        )
        report = consumer.consume_until_empty()
        assert report.processed == 2             # both good txs
        assert report.dead_lettered == 1

    def test_transient_failure_retried_then_succeeds(self):
        broker = InMemoryBroker()
        producer = TransactionProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        producer.produce(_agent(0), _tx(0))

        attempts = {"n": 0}

        def flaky(aw, tx):
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise RuntimeError("transient db blip")

        consumer = DetectionConsumer(
            broker, group="detection", consumer_id="c1", processor=flaky,
            trusted_producers=_trusted_for(_make_signer()),
        )
        report = consumer.consume_until_empty()
        assert attempts["n"] == 3                # failed twice, then succeeded
        assert report.processed == 1
        assert report.dead_lettered == 0

    def test_persistent_failure_exhausts_retries_then_dead_letters(self):
        broker = InMemoryBroker()
        producer = TransactionProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        producer.produce(_agent(0), _tx(0))

        def always_fails(aw, tx):
            raise RuntimeError("permanently broken")

        consumer = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            trusted_producers=_trusted_for(_make_signer()),
            processor=always_fails, max_retries=3,
        )
        report = consumer.consume_until_empty()
        assert report.dead_lettered == 1
        assert broker.total_records(Topic.DEAD_LETTER.value) == 1

    def test_processor_can_flag_poison_directly(self):
        # A processor that raises PoisonMessage skips retries -> straight DLQ.
        broker = InMemoryBroker()
        producer = TransactionProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        producer.produce(_agent(0), _tx(0))

        def reject(aw, tx):
            raise PoisonMessage("business rule: agent is denylisted")

        consumer = DetectionConsumer(
            broker, group="detection", consumer_id="c1", processor=reject,
            trusted_producers=_trusted_for(_make_signer()),
        )
        report = consumer.consume_until_empty()
        assert report.dead_lettered == 1
        assert report.retried == 0               # no retries — straight to DLQ


# =============================================================================
# The alerts topic — the IMMEDIATE_RED fast-path
# =============================================================================

class TestAlertsTopic:

    def test_alert_produced_to_alerts_topic(self):
        broker = InMemoryBroker()
        producer = AlertProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        producer.produce_alert(
            agent_wallet=_agent(0), score=120, alert_tier="RED",
            immediate_red=True, aggregated_flags=0x08,
            reason="CRITICAL attack pattern",
        )
        assert broker.total_records(Topic.ALERTS.value) == 1

    def test_alert_round_trips(self):
        broker = InMemoryBroker()
        producer = AlertProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        producer.produce_alert(
            agent_wallet=_agent(0), score=120, alert_tier="RED",
            immediate_red=True, aggregated_flags=0x08, reason="sybil",
        )
        record = broker.all_records(Topic.ALERTS.value)[0]
        alert = deserialize_alert(record.value)
        assert alert["agent_wallet"] == _agent(0)
        assert alert["immediate_red"] is True
        assert alert["alert_tier"] == "RED"

    def test_alerts_topic_separate_from_transactions(self):
        # The fast-path alerts topic is distinct from the bulk transactions
        # topic — so a slow detection consumer never delays an alert.
        broker = InMemoryBroker()
        tx_producer = TransactionProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        alert_producer = AlertProducer(broker, signer=_make_signer(), clock=lambda: CONF)
        tx_producer.produce(_agent(0), _tx(0))
        alert_producer.produce_alert(
            agent_wallet=_agent(0), score=100, alert_tier="RED",
            immediate_red=True, aggregated_flags=0x08,
        )
        assert broker.total_records(Topic.TRANSACTIONS.value) == 1
        assert broker.total_records(Topic.ALERTS.value) == 1


# =============================================================================
# Determinism
# =============================================================================

class TestDeterminism:

    def test_pipeline_deterministic(self):
        def _run():
            broker = InMemoryBroker()
            producer = TransactionProducer(broker, signer=_make_signer(), clock=lambda: CONF)
            for i in range(40):
                producer.produce(_agent(i % 4), _tx(i))
            delivered = []
            consumer = DetectionConsumer(
                broker, group="detection", consumer_id="c1",
                trusted_producers=_trusted_for(_make_signer()),
                processor=lambda aw, t: delivered.append(t.signature),
            )
            consumer.consume_until_empty()
            return sorted(delivered)

        first = _run()
        for _ in range(8):
            assert _run() == first
