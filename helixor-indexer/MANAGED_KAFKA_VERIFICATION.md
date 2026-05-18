# Managed Kafka Verification

Day 17 is verified against a real local Kafka-compatible broker with Redpanda.
Managed Kafka verification is a deployment task to run before production traffic.

Run the same smoke harness against the managed provider:

```bash
cd helixor-indexer

PYTHONPATH=../helixor-oracle:. \
KAFKA_BOOTSTRAP="YOUR_BOOTSTRAP:9092" \
KAFKA_SECURITY_PROTOCOL="SASL_SSL" \
KAFKA_SASL_MECHANISM="SCRAM-SHA-256" \
KAFKA_SASL_USERNAME="YOUR_USERNAME" \
KAFKA_SASL_PASSWORD="YOUR_PASSWORD" \
../helixor-oracle/.venv/bin/python scripts/live_kafka_smoke.py
```

Expected result:

```text
LIVE_KAFKA_OK
produced=20 processed=20
manually_polled=10 redelivered=10
alerts=1 immediate_red=True
```

Do not commit provider secrets. Use shell environment variables or an ignored
local env file.
