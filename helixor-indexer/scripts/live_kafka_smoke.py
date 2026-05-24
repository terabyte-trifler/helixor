"""
scripts/live_kafka_smoke.py — live Kafka/Redpanda smoke for Day 17.

Runs the production ConfluentKafkaBroker path against a real Kafka
protocol broker:

  KAFKA_BOOTSTRAP=127.0.0.1:19092 python scripts/live_kafka_smoke.py

  KAFKA_BOOTSTRAP=pkc-xxxxx.us-east-1.aws.confluent.cloud:9092 \
  KAFKA_SECURITY_PROTOCOL=SASL_SSL \
  KAFKA_SASL_MECHANISM=PLAIN \
  KAFKA_SASL_USERNAME="$CONFLUENT_API_KEY" \
  KAFKA_SASL_PASSWORD="$CONFLUENT_API_SECRET" \
  python scripts/live_kafka_smoke.py

Supported managed-cluster env:
  KAFKA_BOOTSTRAP             host:port list, required for managed runs
  KAFKA_SECURITY_PROTOCOL     PLAINTEXT, SSL, SASL_PLAINTEXT, or SASL_SSL
  KAFKA_SASL_MECHANISM        PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, etc.
  KAFKA_SASL_USERNAME         API key / SASL username
  KAFKA_SASL_PASSWORD         API secret / SASL password
  KAFKA_SSL_CA_LOCATION       optional CA bundle path
  KAFKA_CLIENT_ID             optional client id prefix

It verifies:
  - transaction producer -> broker -> DetectionConsumer
  - crash-before-commit redelivery
  - IMMEDIATE_RED alert topic round-trip
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

_ORACLE_ROOT = Path(__file__).resolve().parents[2] / "helixor-oracle"
if str(_ORACLE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ORACLE_ROOT))

from oracle.network_guard import enforce_network_guard

from eventbus import (
    AlertProducer,
    ConfluentKafkaBroker,
    ConfluentKafkaConfig,
    DetectionConsumer,
    TransactionProducer,
)
from eventbus.serialization import deserialize_alert
from features.types import Transaction


CONFIRMED_AT = datetime(2026, 5, 19, 3, 45, tzinfo=timezone.utc)
PROGRAM_ID = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"


def _kafka_config(run_id: str) -> ConfluentKafkaConfig:
    bootstrap = os.environ.get("KAFKA_BOOTSTRAP", "127.0.0.1:19092")
    security_protocol = os.environ.get("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")
    sasl_mechanism = os.environ.get("KAFKA_SASL_MECHANISM")
    sasl_username = os.environ.get("KAFKA_SASL_USERNAME")
    sasl_password = os.environ.get("KAFKA_SASL_PASSWORD")
    ssl_ca_location = os.environ.get("KAFKA_SSL_CA_LOCATION")
    client_id = os.environ.get("KAFKA_CLIENT_ID", f"helixor-live-{run_id}")

    shared: dict[str, object] = {
        "socket.timeout.ms": int(os.environ.get("KAFKA_SOCKET_TIMEOUT_MS", "10000")),
    }
    if security_protocol:
        shared["security.protocol"] = security_protocol
    if sasl_mechanism:
        shared["sasl.mechanism"] = sasl_mechanism
    if sasl_username:
        shared["sasl.username"] = sasl_username
    if sasl_password:
        shared["sasl.password"] = sasl_password
    if ssl_ca_location:
        shared["ssl.ca.location"] = ssl_ca_location

    needs_sasl = security_protocol.upper().startswith("SASL")
    if needs_sasl and (not sasl_username or not sasl_password):
        raise SystemExit(
            "Managed Kafka smoke needs KAFKA_SASL_USERNAME and "
            "KAFKA_SASL_PASSWORD when KAFKA_SECURITY_PROTOCOL uses SASL."
        )

    return ConfluentKafkaConfig(
        bootstrap,
        client_id=client_id,
        join_timeout_s=float(os.environ.get("KAFKA_JOIN_TIMEOUT_S", "15")),
        extra=shared,
        producer_extra={
            "message.timeout.ms": int(os.environ.get("KAFKA_MESSAGE_TIMEOUT_MS", "10000")),
        },
    )


def _tx(i: int) -> Transaction:
    return Transaction(
        signature=f"live{i:08d}".ljust(64, "x"),
        slot=400_000_000 + i,
        block_time=CONFIRMED_AT,
        success=True,
        program_ids=(PROGRAM_ID,),
        sol_change=1000 + i,
        fee=5000,
        priority_fee=100,
        compute_units=200_000,
        counterparty=f"counterparty{i % 3}",
    )


def _agent(i: int) -> str:
    return f"agent-live-{i}".ljust(44, "x")


def main() -> None:
    enforce_network_guard(service="live-kafka-smoke")
    run_id = str(int(time.time() * 1000))
    config = _kafka_config(run_id)
    bootstrap = config.bootstrap_servers
    tx_topic = f"helixor.day17.{run_id}.transactions"
    dlq_topic = f"helixor.day17.{run_id}.deadletter"
    alert_topic = f"helixor.day17.{run_id}.alerts"

    broker = ConfluentKafkaBroker(config)

    producer = TransactionProducer(broker, topic=tx_topic)
    for i in range(20):
        producer.produce(_agent(i % 5), _tx(i))

    delivered: list[tuple[str, str]] = []
    consumer = DetectionConsumer(
        broker,
        group=f"detection-live-{run_id}",
        consumer_id="c1",
        topic=tx_topic,
        dead_letter_topic=dlq_topic,
        processor=lambda aw, tx: delivered.append((aw, tx.signature)),
    )
    report = consumer.consume_until_empty(max_records=50)
    consumer.leave()
    assert report.processed == 20, report
    assert len({sig for _, sig in delivered}) == 20, delivered

    crash_topic = f"helixor.day17.{run_id}.crash"
    crash_dlq = f"helixor.day17.{run_id}.crash.deadletter"
    crash_group = f"detection-crash-{run_id}"
    crash_producer = TransactionProducer(broker, topic=crash_topic)
    for i in range(10):
        crash_producer.produce(_agent(0), _tx(100 + i))

    c1 = DetectionConsumer(
        broker,
        group=crash_group,
        consumer_id="c1",
        topic=crash_topic,
        dead_letter_topic=crash_dlq,
        processor=lambda aw, tx: None,
    )
    c1.join()
    manually_polled = broker.poll(crash_topic, crash_group, "c1", 10)
    assert len(manually_polled) == 10, len(manually_polled)
    c1.leave()

    redelivered: list[str] = []
    c2 = DetectionConsumer(
        broker,
        group=crash_group,
        consumer_id="c2",
        topic=crash_topic,
        dead_letter_topic=crash_dlq,
        processor=lambda aw, tx: redelivered.append(tx.signature),
    )
    crash_report = c2.consume_until_empty(max_records=20)
    c2.leave()
    assert crash_report.processed == 10, crash_report
    assert len(set(redelivered)) == 10, redelivered

    alert_producer = AlertProducer(broker, topic=alert_topic)
    alert_producer.produce_alert(
        agent_wallet=_agent(0),
        score=90,
        alert_tier="RED",
        immediate_red=True,
        aggregated_flags=0x08,
        reason="live kafka smoke",
    )
    alert_group = f"alerts-live-{run_id}"
    alert_consumer_id = "alerts-reader"
    broker.join_group(alert_topic, alert_group, alert_consumer_id)
    alerts = broker.poll(alert_topic, alert_group, alert_consumer_id, 10)
    assert len(alerts) == 1, len(alerts)
    alert = deserialize_alert(alerts[0].record.value)
    assert alert["immediate_red"] is True, alert
    broker.leave_group(alert_topic, alert_group, alert_consumer_id)

    print("LIVE_KAFKA_OK")
    print(f"bootstrap={bootstrap}")
    print(f"security_protocol={config.extra.get('security.protocol', 'PLAINTEXT')}")
    print(f"tx_topic={tx_topic} produced=20 processed={report.processed}")
    print(
        f"crash_topic={crash_topic} manually_polled=10 "
        f"redelivered={crash_report.processed}"
    )
    print(f"alert_topic={alert_topic} alerts=1 immediate_red={alert['immediate_red']}")


if __name__ == "__main__":
    main()
