"""
eventbus/confluent_adapter.py — the production confluent-kafka broker.

`ConfluentKafkaBroker` is the production `MessageBroker`: it talks to a
real Kafka cluster via `confluent-kafka`. It satisfies the exact same
interface as `InMemoryBroker`, so the producer, consumer, and the entire
test suite run unchanged against either.

DRIVER INDEPENDENCE
-------------------
`confluent_kafka` is a production dependency with a native (librdkafka)
extension — not something the test suite should require. So this module
does NOT import it at load time; the import is deferred into the
constructor. The eventbus's testable core (broker.py, producer.py,
consumer.py, serialization.py) never transitively pulls in confluent-kafka.

This module is the integration seam. Its semantics map 1:1 onto the
in-memory model the tests exercise:

  in-memory model            confluent-kafka
  ----------------           ---------------
  produce(topic, record)     Producer.produce(...) + poll
  join_group                 Consumer.subscribe([topic])
  poll                       Consumer.poll(timeout)
  commit                     Consumer.commit(offsets, asynchronous=False)
  leave_group                Consumer.close()

The key correspondence: the in-memory broker's "roll uncommitted reads
back to the committed offset on leave_group" IS Kafka's behaviour — a
consumer that dies without committing has its partitions reassigned and
the new owner resumes from the last committed offset. The tests that
prove "kill a consumer mid-stream, lose nothing" against InMemoryBroker
therefore prove the same property for the real broker.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from eventbus.types import ConsumedRecord, DeliveryError, EventRecord

logger = logging.getLogger("helixor.eventbus.confluent")


# =============================================================================
# Connection config
# =============================================================================

class ConfluentKafkaConfig:
    """
    Settings for a real Kafka cluster.

    `bootstrap_servers` is the broker list; `acks='all'` + `enable_idempotence`
    on the producer give the strongest delivery guarantee Kafka offers.
    """

    __slots__ = (
        "bootstrap_servers",
        "client_id",
        "extra",
        "producer_extra",
        "consumer_extra",
        "admin_extra",
        "join_timeout_s",
    )

    def __init__(
        self,
        bootstrap_servers: str,
        *,
        client_id: str = "helixor-eventbus",
        extra: dict[str, Any] | None = None,
        producer_extra: dict[str, Any] | None = None,
        consumer_extra: dict[str, Any] | None = None,
        admin_extra: dict[str, Any] | None = None,
        join_timeout_s: float = 10.0,
    ) -> None:
        self.bootstrap_servers = bootstrap_servers
        self.client_id = client_id
        self.extra = extra or {}
        self.producer_extra = producer_extra or {}
        self.consumer_extra = consumer_extra or {}
        self.admin_extra = admin_extra or {}
        self.join_timeout_s = join_timeout_s

    def producer_config(self) -> dict[str, Any]:
        """confluent-kafka producer config — idempotent, acks=all."""
        return {
            "bootstrap.servers": self.bootstrap_servers,
            "client.id":         self.client_id,
            "acks":              "all",
            "enable.idempotence": True,        # no duplicate produces
            "retries":           10,
            **self.extra,
            **self.producer_extra,
        }

    def consumer_config(self, group: str) -> dict[str, Any]:
        """
        confluent-kafka consumer config.

        `enable.auto.commit=False` is essential: Helixor commits MANUALLY,
        after processing, so a crash never commits past unprocessed work.
        That manual commit-after-process is the at-least-once guarantee.
        """
        return {
            "bootstrap.servers":  self.bootstrap_servers,
            "group.id":           group,
            "client.id":          self.client_id,
            "enable.auto.commit": False,       # Helixor commits manually
            "auto.offset.reset":  "earliest",
            **self.extra,
            **self.consumer_extra,
        }


# =============================================================================
# ConfluentKafkaBroker
# =============================================================================

class ConfluentKafkaBroker:
    """
    A `MessageBroker` over a real Kafka cluster.

    NOT used by the test suite — `InMemoryBroker` is the faithful model the
    tests run against. This is the deployment wiring:

        config = ConfluentKafkaConfig(bootstrap_servers="kafka:9092")
        broker = ConfluentKafkaBroker(config)
        producer = TransactionProducer(broker)
        consumer = DetectionConsumer(broker, group="detection", ...)

    `confluent_kafka` is imported in `__init__`, never at module load.
    """

    def __init__(self, config: ConfluentKafkaConfig) -> None:
        try:
            import confluent_kafka
            from confluent_kafka.admin import AdminClient, NewTopic
        except ImportError as exc:                # pragma: no cover
            raise RuntimeError(
                "ConfluentKafkaBroker needs the 'confluent-kafka' package. "
                "Install it in the deployment environment. The test suite "
                "uses InMemoryBroker — a faithful in-memory model — instead."
            ) from exc
        self._config = config
        self._kafka = confluent_kafka
        self._new_topic = NewTopic
        self._producer = confluent_kafka.Producer(config.producer_config())
        self._admin = AdminClient({
            "bootstrap.servers": config.bootstrap_servers,
            "client.id": f"{config.client_id}-admin",
            **config.admin_extra,
        })
        self._consumers: dict[tuple[str, str, str], Any] = {}
        self._lock = threading.RLock()

    def create_topic(self, topic: str, partitions: int) -> None:
        futures = self._admin.create_topics([
            self._new_topic(topic, num_partitions=partitions, replication_factor=1),
        ])
        future = futures[topic]
        try:
            future.result(timeout=10)
        except Exception as exc:                  # pragma: no cover
            err = exc.args[0] if exc.args else None
            code = err.code() if hasattr(err, "code") else None
            if code != self._kafka.KafkaError.TOPIC_ALREADY_EXISTS:
                raise DeliveryError(f"create_topic({topic}) failed: {exc}") from exc

    def produce(self, topic: str, record: EventRecord) -> int:
        event = threading.Event()
        state: dict[str, Any] = {}

        def on_delivery(err, msg) -> None:
            state["err"] = err
            state["msg"] = msg
            event.set()

        headers = list(record.headers.items()) if record.headers else None
        self._producer.produce(
            topic,
            key=record.key.encode("utf-8"),
            value=record.value,
            headers=headers,
            callback=on_delivery,
        )
        while not event.wait(0.05):
            self._producer.poll(0)
        self._producer.poll(0)
        if state.get("err") is not None:
            raise DeliveryError(f"produce({topic}) failed: {state['err']}")
        return int(state["msg"].offset())

    def join_group(self, topic: str, group: str, consumer_id: str) -> set[int]:
        consumer = self._consumer(topic, group, consumer_id)
        consumer.subscribe([topic])
        deadline = time.monotonic() + self._config.join_timeout_s
        assigned: set[int] = set()
        while time.monotonic() < deadline:
            consumer.poll(0.1)
            assigned = {tp.partition for tp in consumer.assignment()}
            if assigned:
                break
        logger.info(
            "consumer %s joined group %s on %s — partitions %s",
            consumer_id, group, topic, sorted(assigned),
        )
        return assigned

    def leave_group(self, topic: str, group: str, consumer_id: str) -> None:
        key = (topic, group, consumer_id)
        with self._lock:
            consumer = self._consumers.pop(key, None)
        if consumer is not None:
            consumer.close()

    def poll(
        self, topic: str, group: str, consumer_id: str, max_records: int,
    ) -> list[ConsumedRecord]:
        consumer = self._consumer(topic, group, consumer_id)
        messages = consumer.consume(num_messages=max_records, timeout=1.0)
        records: list[ConsumedRecord] = []
        for msg in messages:
            if msg is None:
                continue
            if msg.error():
                raise DeliveryError(f"poll({topic}) failed: {msg.error()}")
            raw_key = msg.key()
            key = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else str(raw_key)
            headers = self._headers_to_dict(msg.headers())
            records.append(ConsumedRecord(
                topic=msg.topic(),
                partition=msg.partition(),
                offset=msg.offset(),
                record=EventRecord(key=key, value=msg.value(), headers=headers),
            ))
        return records

    def commit(
        self, topic: str, group: str, offsets: dict[int, int],
    ) -> None:
        if not offsets:
            return
        consumer = self._any_consumer(topic, group)
        topic_partitions = [
            self._kafka.TopicPartition(topic, partition, offset)
            for partition, offset in offsets.items()
        ]
        consumer.commit(offsets=topic_partitions, asynchronous=False)

    def seek_to_committed(
        self, topic: str, group: str, partitions: set[int],
    ) -> None:
        if not partitions:
            return
        consumer = self._any_consumer(topic, group)
        requested = [
            self._kafka.TopicPartition(topic, partition)
            for partition in partitions
        ]
        committed = consumer.committed(requested, timeout=10)
        for topic_partition in committed:
            consumer.seek(topic_partition)

    def _consumer(self, topic: str, group: str, consumer_id: str):
        key = (topic, group, consumer_id)
        with self._lock:
            if key not in self._consumers:
                cfg = self._config.consumer_config(group)
                cfg["client.id"] = f"{self._config.client_id}-{consumer_id}"
                self._consumers[key] = self._kafka.Consumer(cfg)
            return self._consumers[key]

    def _any_consumer(self, topic: str, group: str):
        with self._lock:
            for (candidate_topic, candidate_group, _), consumer in self._consumers.items():
                if candidate_topic == topic and candidate_group == group:
                    return consumer
        raise DeliveryError(f"no active consumer for group {group} on {topic}")

    @staticmethod
    def _headers_to_dict(headers) -> dict[str, str]:
        if not headers:
            return {}
        out: dict[str, str] = {}
        for key, value in headers:
            if value is None:
                out[key] = ""
            elif isinstance(value, bytes):
                out[key] = value.decode("utf-8", errors="replace")
            else:
                out[key] = str(value)
        return out
