"""
helixor-indexer / eventbus — the Kafka event pipeline.

Day 17 inserts Kafka between the Geyser indexer and the detection
pipeline, decoupling ingest speed from scoring speed and giving guaranteed
delivery for sub-epoch adversarial alerts.

Topics:
    agent.transactions  — every ingested transaction (indexer -> detection)
    agent.alerts        — the IMMEDIATE_RED fast-path (sub-epoch)
    agent.deadletter    — poison messages, quarantined

Public API:
    Topic, EventRecord, ConsumedRecord, TopicPartition   the types
    MessageBroker, InMemoryBroker                        the broker
    TransactionProducer, AlertProducer                   the producers
    DetectionConsumer, ConsumeReport, PoisonMessage      the consumer
    serialize_transaction, deserialize_transaction       the wire format
    serialize_alert, deserialize_alert
    ConfluentKafkaBroker, ConfluentKafkaConfig           the production edge
"""

from __future__ import annotations

from eventbus.broker import InMemoryBroker, MessageBroker
from eventbus.confluent_adapter import ConfluentKafkaBroker, ConfluentKafkaConfig
from eventbus.consumer import (
    ConsumeReport,
    DetectionConsumer,
    PoisonMessage,
    RecordProcessor,
)
from eventbus.producer import AlertProducer, TransactionProducer
from eventbus.serialization import (
    SerializationError,
    deserialize_alert,
    deserialize_transaction,
    serialize_alert,
    serialize_transaction,
)
from eventbus.types import (
    ConsumedRecord,
    DeliveryError,
    EventRecord,
    Topic,
    TopicPartition,
)

__all__ = [
    "Topic", "EventRecord", "ConsumedRecord", "TopicPartition", "DeliveryError",
    "MessageBroker", "InMemoryBroker",
    "TransactionProducer", "AlertProducer",
    "DetectionConsumer", "ConsumeReport", "PoisonMessage", "RecordProcessor",
    "serialize_transaction", "deserialize_transaction",
    "serialize_alert", "deserialize_alert", "SerializationError",
    "ConfluentKafkaBroker", "ConfluentKafkaConfig",
]
