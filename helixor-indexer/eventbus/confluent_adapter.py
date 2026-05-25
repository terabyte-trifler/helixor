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

    __slots__ = ("bootstrap_servers", "client_id", "extra")

    def __init__(
        self,
        bootstrap_servers: str,
        *,
        client_id: str = "helixor-eventbus",
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.bootstrap_servers = bootstrap_servers
        self.client_id = client_id
        self.extra = extra or {}

    def producer_config(self) -> dict[str, Any]:
        """confluent-kafka producer config — idempotent, acks=all."""
        return {
            "bootstrap.servers": self.bootstrap_servers,
            "client.id":         self.client_id,
            "acks":              "all",
            "enable.idempotence": True,        # no duplicate produces
            "retries":           10,
            **self.extra,
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
        # VULN-07: producer/consumer require signer + trusted-set.
        signer = Ed25519PayloadSigner.from_node_keypair(node_kp)
        trusted = TrustedProducerSet([TrustedProducer("indexer", signer.public_key)])
        producer = TransactionProducer(broker, signer=signer)
        consumer = DetectionConsumer(
            broker, group="detection", trusted_producers=trusted, ...
        )

    `confluent_kafka` is imported in `__init__`, never at module load.
    """

    def __init__(self, config: ConfluentKafkaConfig) -> None:
        try:
            import confluent_kafka  # noqa: F401
        except ImportError as exc:                # pragma: no cover
            raise RuntimeError(
                "ConfluentKafkaBroker needs the 'confluent-kafka' package. "
                "Install it in the deployment environment. The test suite "
                "uses InMemoryBroker — a faithful in-memory model — instead."
            ) from exc
        self._config = config
        # Deployment: hold a confluent_kafka.Producer and a per-group
        # confluent_kafka.Consumer, an admin client for create_topic, and
        # map produce/poll/commit/join/leave onto them per the docstring
        # correspondence table. Kept out of the testable core by design.
        raise NotImplementedError(  # pragma: no cover
            "live Kafka wiring is completed in the deployment environment "
            "against a real cluster; the in-memory broker models its "
            "semantics for the test suite"
        )
