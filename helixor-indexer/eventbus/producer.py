"""
eventbus/producer.py — the Kafka producers.

Two producers, both thin wrappers over a `MessageBroker`:

  - `TransactionProducer` — the Geyser indexer produces every ingested
    transaction here, onto `agent.transactions`, keyed by agent_wallet.
    Keying by agent means all of one agent's transactions land on one
    partition and are processed in order by one consumer.

  - `AlertProducer` — the security layer produces IMMEDIATE_RED alerts
    here, onto `agent.alerts`. This is the sub-epoch fast-path: an
    adversarial agent flagged mid-epoch cannot wait 24h for the next
    scoring round.

Producing is fire-and-decoupled: the indexer's write path no longer waits
on the detection pipeline. A scoring slowdown backs up in Kafka, not in
ingestion.

VULN-07 MITIGATION
------------------
Every produced record is SIGNED with the producer's Ed25519 keypair. The
signature plus the producer's pubkey ride in the record headers so the
consumer can authenticate provenance at the bus boundary (see
`eventbus/signing.py`). Both producers REQUIRE a `PayloadSigner` at
construction time — there is no "unsigned" code path, by design: a
producer that cannot prove its identity should not be able to write to
the bus at all.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from eventbus.broker import MessageBroker
from eventbus.serialization import serialize_alert, serialize_transaction
from eventbus.signing import PayloadSigner, attach_signature
from eventbus.types import EventRecord, Topic

_ORACLE_ROOT = Path(__file__).resolve().parents[2] / "helixor-oracle"
if str(_ORACLE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ORACLE_ROOT))

from features.types import Transaction  # noqa: E402

logger = logging.getLogger("helixor.eventbus.producer")


# =============================================================================
# TransactionProducer
# =============================================================================

class TransactionProducer:
    """
    Produces ingested transactions onto `agent.transactions`.

    The Geyser indexer calls `produce` for every transaction it ingests;
    the detection pipeline consumes the topic. This is the seam that
    decouples ingest speed from scoring speed.

    The producer SIGNS every record with its Ed25519 `PayloadSigner` —
    VULN-07 mitigation. The consumer rejects any record whose signature
    is missing, malformed, invalid, or whose pubkey is not in its
    trusted set.
    """

    __slots__ = ("_broker", "_topic", "_produced", "_clock", "_signer")

    def __init__(
        self,
        broker: MessageBroker,
        *,
        signer: PayloadSigner,
        topic:  str = Topic.TRANSACTIONS.value,
        clock=None,
    ) -> None:
        if signer is None:
            raise ValueError(
                "TransactionProducer requires a PayloadSigner — VULN-07 "
                "forbids unsigned records on the bus"
            )
        self._broker = broker
        self._topic = topic
        self._produced = 0
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._signer = signer
        # Create the topic if the broker has not seen it yet.
        self._broker.create_topic(topic, 8)

    @property
    def produced_count(self) -> int:
        return self._produced

    @property
    def public_key(self) -> bytes:
        """The producer's pubkey — what the consumer must trust."""
        return self._signer.public_key

    def produce(
        self,
        agent_wallet: str,
        transaction:  Transaction,
        *,
        slot_hash:    bytes | None = None,
    ) -> int:
        """
        Produce one transaction onto `agent.transactions`, keyed by
        agent_wallet. Returns the partition offset it was written at.

        `slot_hash` (optional, 32 bytes) is the on-chain commitment hash
        for `transaction.slot` — VULN-07 mitigation #2. When present, it
        rides in the signed headers so a deployment-side verifier can
        cross-check the slot against the chain.
        """
        value = serialize_transaction(agent_wallet, transaction)
        headers = attach_signature(
            value,
            self._signer,
            extra_headers={"signature": transaction.signature},
            slot_hash=slot_hash,
        )
        record = EventRecord(
            key=agent_wallet,
            value=value,
            headers=headers,
            produced_at=self._clock(),
        )
        offset = self._broker.produce(self._topic, record)
        self._produced += 1
        return offset

    def produce_batch(
        self, items: list[tuple[str, Transaction]],
    ) -> int:
        """Produce many (agent_wallet, transaction) pairs. Returns the count."""
        for agent_wallet, transaction in items:
            self.produce(agent_wallet, transaction)
        return len(items)


# =============================================================================
# AlertProducer
# =============================================================================

class AlertProducer:
    """
    Produces security alerts onto `agent.alerts` — the IMMEDIATE_RED
    fast-path.

    When the detection engine flags an agent IMMEDIATE_RED, the alert is
    produced here immediately, decoupled from the 24h epoch cycle. A
    downstream responder consumes `agent.alerts` for near-real-time action.
    """

    __slots__ = ("_broker", "_topic", "_produced", "_clock", "_signer")

    def __init__(
        self,
        broker: MessageBroker,
        *,
        signer: PayloadSigner,
        topic:  str = Topic.ALERTS.value,
        clock=None,
    ) -> None:
        if signer is None:
            raise ValueError(
                "AlertProducer requires a PayloadSigner — VULN-07 "
                "forbids unsigned alerts on the bus"
            )
        self._broker = broker
        self._topic = topic
        self._produced = 0
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._signer = signer
        self._broker.create_topic(topic, 4)

    @property
    def produced_count(self) -> int:
        return self._produced

    @property
    def public_key(self) -> bytes:
        """The producer's pubkey — what the consumer must trust."""
        return self._signer.public_key

    def produce_alert(
        self,
        *,
        agent_wallet:     str,
        score:            int,
        alert_tier:       str,
        immediate_red:    bool,
        aggregated_flags: int,
        reason:           str = "",
        slot_hash:        bytes | None = None,
    ) -> int:
        """
        Produce one security alert onto `agent.alerts`. Keyed by
        agent_wallet — an agent's alerts stay ordered.
        """
        value = serialize_alert(
            agent_wallet=agent_wallet,
            score=score,
            alert_tier=alert_tier,
            immediate_red=immediate_red,
            aggregated_flags=aggregated_flags,
            detected_at=self._clock(),
            reason=reason,
        )
        headers = attach_signature(
            value,
            self._signer,
            extra_headers={"immediate_red": str(immediate_red).lower()},
            slot_hash=slot_hash,
        )
        record = EventRecord(
            key=agent_wallet,
            value=value,
            headers=headers,
            produced_at=self._clock(),
        )
        offset = self._broker.produce(self._topic, record)
        self._produced += 1
        logger.info(
            "alert produced for %s: tier=%s immediate_red=%s",
            agent_wallet, alert_tier, immediate_red,
        )
        return offset
