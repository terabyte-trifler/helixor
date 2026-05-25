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
    PayloadSigner, Ed25519PayloadSigner                  VULN-07 signing
    TrustedProducer, TrustedProducerSet                  VULN-07 trust
    SignatureError, UntrustedProducer                    VULN-07 errors
"""

from __future__ import annotations

from eventbus.broker import InMemoryBroker, MessageBroker
from eventbus.confluent_adapter import ConfluentKafkaBroker, ConfluentKafkaConfig
from eventbus.kafka_security import (
    KafkaSecurityRefused,
    KafkaSecurityVerdict,
    MissingKafkaCredentials,
    UnsupportedKafkaSecurity,
    enforce_kafka_security,
    evaluate as evaluate_kafka_security,
    is_production_network,
    override_kafka_security,
    password_from_env,
)
from eventbus.consumer import (
    ConsumeReport,
    DetectionConsumer,
    PoisonMessage,
    RecordProcessor,
)
from eventbus.lag_monitor import (
    BrokerIntrospector,
    ConsumerLagMonitor,
    LagSnapshot,
)
from eventbus.producer import AlertProducer, TransactionProducer
from eventbus.serialization import (
    SerializationError,
    deserialize_alert,
    deserialize_transaction,
    serialize_alert,
    serialize_transaction,
)
from eventbus.signing import (
    Ed25519PayloadSigner,
    PayloadSigner,
    SignatureError as PayloadSignatureError,
    TrustedProducer,
    TrustedProducerSet,
    UntrustedProducer,
    attach_signature,
    verify_record_headers,
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
    "KafkaSecurityRefused", "KafkaSecurityVerdict",
    "MissingKafkaCredentials", "UnsupportedKafkaSecurity",
    "enforce_kafka_security", "evaluate_kafka_security",
    "is_production_network", "override_kafka_security", "password_from_env",
    "PayloadSigner", "Ed25519PayloadSigner",
    "TrustedProducer", "TrustedProducerSet",
    "PayloadSignatureError", "UntrustedProducer",
    "attach_signature", "verify_record_headers",
    "BrokerIntrospector", "ConsumerLagMonitor", "LagSnapshot",
]
