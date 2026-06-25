"""
tests/test_vuln07_signed_pipeline.py — VULN-07 signed-bus invariants.

THE AUDIT FINDING
-----------------
VULN-07 (HIGH) — DATA PIPELINE FEATURE POISONING. Three injection points
into the scoring pipeline: a compromised Geyser endpoint, an
unauthenticated Kafka cluster, an exposed TimescaleDB. A single one of
these gives an attacker the ability to inject synthetic "success"
transactions into an agent's history, poison the baseline over weeks,
and trick scoring into stamping a fraudulent GREEN certificate.

THE MITIGATION
--------------
Authenticated message provenance at the bus boundary:

  * Producers SIGN every record with their Ed25519 keypair; the signature
    plus the producer's pubkey ride in record headers.
  * Consumers hold a `TrustedProducerSet` and verify EVERY consumed
    record BEFORE decoding. The decoder never sees forgery.
  * Tampering with any byte of the payload invalidates the signature.
  * A record signed by a non-trusted key is rejected even if the
    signature is mathematically valid.
  * Forgery is dead-letter-on-first-sight — no retries.

WHAT THIS TEST FILE PINS
------------------------
The full set of provenance invariants:

  * a signed round-trip works end-to-end
  * a producer with a known key produces records the consumer accepts
  * an unsigned record on the bus is dead-lettered (forgery)
  * a record signed by an UNTRUSTED key is dead-lettered (forgery)
  * a TAMPERED payload (same headers, mutated value) is dead-lettered
  * a TAMPERED signature is dead-lettered
  * a record signed by one trusted producer but claiming a DIFFERENT
    trusted producer's pubkey is dead-lettered
  * the `slot_hash` mitigation #2 hook propagates through the headers
  * forgery NEVER reaches the processor — verification runs before decode
  * forgery NEVER retries — the DLQ is the first and only stop

These tests are the contract the on-chain-style attacker faces at the bus.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone

import pytest

from eventbus import (
    DetectionConsumer,
    Ed25519PayloadSigner,
    InMemoryBroker,
    Topic,
    TransactionProducer,
    TrustedProducer,
    TrustedProducerSet,
    attach_signature,
)
from eventbus.serialization import serialize_transaction
from eventbus.signing import (
    HEADER_PUBKEY,
    HEADER_SIGNATURE,
    HEADER_SLOT_HASH,
    SignatureError,
    UntrustedProducer,
    verify_record_headers,
)
from eventbus.types import EventRecord
from features.types import Transaction


CONF = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
PROG = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"


# =============================================================================
# Test fixtures
# =============================================================================

def _tx(i: int = 0) -> Transaction:
    return Transaction(
        signature=f"sig{i:08d}".ljust(64, "x"),
        slot=300_000_000 + i,
        block_time=CONF,
        success=True,
        program_ids=(PROG,),
        sol_change=1_000_000,
        fee=5000, priority_fee=100, compute_units=200_000,
        counterparty="cp",
    )


def _agent(i: int = 0) -> str:
    return f"agent{i}".ljust(44, "x")


def _trusted_oracle_signer() -> Ed25519PayloadSigner:
    """A deterministic trusted producer keypair — stable across tests."""
    return Ed25519PayloadSigner.from_seed(b"vuln07-oracle-trusted")


def _attacker_signer() -> Ed25519PayloadSigner:
    """A producer outside the trust set — every test rejects records from it."""
    return Ed25519PayloadSigner.from_seed(b"vuln07-attacker-evil")


def _make_trusted_set(signers: list[Ed25519PayloadSigner]) -> TrustedProducerSet:
    return TrustedProducerSet([
        TrustedProducer(name=f"trusted-{i}", public_key=s.public_key)
        for i, s in enumerate(signers)
    ])


# =============================================================================
# Producer-side: every record carries a signature + pubkey
# =============================================================================

class TestProducerStampsSignature:

    def test_record_carries_signature_header(self):
        broker = InMemoryBroker()
        producer = TransactionProducer(
            broker, signer=_trusted_oracle_signer(), clock=lambda: CONF,
        )
        producer.produce(_agent(0), _tx(0))
        record = broker.all_records(Topic.TRANSACTIONS.value)[0]
        assert HEADER_SIGNATURE in record.headers
        assert HEADER_PUBKEY in record.headers
        # Ed25519 sig = 64 bytes, base64-encoded.
        sig_bytes = base64.b64decode(record.headers[HEADER_SIGNATURE])
        pub_bytes = base64.b64decode(record.headers[HEADER_PUBKEY])
        assert len(sig_bytes) == 64
        assert len(pub_bytes) == 32

    def test_pubkey_in_header_matches_signer(self):
        broker = InMemoryBroker()
        signer = _trusted_oracle_signer()
        producer = TransactionProducer(broker, signer=signer, clock=lambda: CONF)
        producer.produce(_agent(0), _tx(0))
        record = broker.all_records(Topic.TRANSACTIONS.value)[0]
        pub_bytes = base64.b64decode(record.headers[HEADER_PUBKEY])
        assert pub_bytes == signer.public_key

    def test_signature_verifies_against_payload(self):
        broker = InMemoryBroker()
        signer = _trusted_oracle_signer()
        producer = TransactionProducer(broker, signer=signer, clock=lambda: CONF)
        producer.produce(_agent(0), _tx(0))
        record = broker.all_records(Topic.TRANSACTIONS.value)[0]
        trusted = _make_trusted_set([signer])
        # Round-trip verification — no exception means accepted.
        pub = verify_record_headers(record.value, record.headers, trusted)
        assert pub == signer.public_key

    def test_producer_requires_signer(self):
        broker = InMemoryBroker()
        with pytest.raises((TypeError, ValueError)):
            # Missing required `signer` kwarg.
            TransactionProducer(broker, clock=lambda: CONF)            # type: ignore

    def test_producer_rejects_none_signer(self):
        broker = InMemoryBroker()
        with pytest.raises(ValueError, match="VULN-07"):
            TransactionProducer(broker, signer=None, clock=lambda: CONF)    # type: ignore


# =============================================================================
# Consumer-side: forged records are dead-lettered, never processed
# =============================================================================

class TestConsumerVerifiesProvenance:

    def test_signed_round_trip_processes(self):
        """The happy path — a trusted producer's record is accepted."""
        broker = InMemoryBroker()
        signer = _trusted_oracle_signer()
        producer = TransactionProducer(broker, signer=signer, clock=lambda: CONF)
        producer.produce(_agent(0), _tx(0))

        delivered = []
        consumer = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            trusted_producers=_make_trusted_set([signer]),
            processor=lambda aw, tx: delivered.append((aw, tx.signature)),
        )
        report = consumer.consume_until_empty()

        assert report.processed == 1
        assert report.dead_lettered == 0
        assert len(delivered) == 1

    def test_unsigned_record_is_dead_lettered(self):
        """A record on the bus with NO signature headers is forgery."""
        broker = InMemoryBroker()
        broker.create_topic(Topic.TRANSACTIONS.value, 1)
        # An attacker bypasses the producer and writes directly to the
        # broker (compromised Kafka, no auth).
        broker.produce(
            Topic.TRANSACTIONS.value,
            EventRecord(
                key=_agent(0),
                value=serialize_transaction(_agent(0), _tx(0)),
                # No headers — no signature, no pubkey.
                headers={},
            ),
        )

        delivered = []
        consumer = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            trusted_producers=_make_trusted_set([_trusted_oracle_signer()]),
            processor=lambda aw, tx: delivered.append(tx),
        )
        report = consumer.consume_until_empty()

        # Forgery: rejected at the verify boundary, NEVER decoded, NEVER
        # processed — and dead-lettered on first sight (no retries).
        assert delivered == []
        assert report.processed == 0
        assert report.dead_lettered == 1
        assert report.retried == 0
        assert broker.total_records(Topic.DEAD_LETTER.value) == 1

    def test_untrusted_producer_is_dead_lettered(self):
        """A mathematically valid signature from an untrusted key is forgery."""
        broker = InMemoryBroker()
        attacker = _attacker_signer()
        # The attacker has their own keypair and CAN sign — they just are
        # not in the consumer's trusted set. This is the "compromised
        # Geyser plugin" model: the attacker holds *some* private key, but
        # not one Phylanx authorized.
        producer = TransactionProducer(broker, signer=attacker, clock=lambda: CONF)
        producer.produce(_agent(0), _tx(0))

        delivered = []
        consumer = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            trusted_producers=_make_trusted_set([_trusted_oracle_signer()]),
            processor=lambda aw, tx: delivered.append(tx),
        )
        report = consumer.consume_until_empty()

        assert delivered == []
        assert report.dead_lettered == 1
        assert report.retried == 0

    def test_tampered_payload_is_dead_lettered(self):
        """Mutate even one byte of the value — signature no longer verifies."""
        broker = InMemoryBroker()
        signer = _trusted_oracle_signer()
        producer = TransactionProducer(broker, signer=signer, clock=lambda: CONF)
        producer.produce(_agent(0), _tx(0))

        # Tamper with the value AFTER signing.
        original = broker.all_records(Topic.TRANSACTIONS.value)[0]
        tampered_value = original.value.replace(b"agent0", b"AGENT0")
        # The headers (sig + pubkey) carry over verbatim — only the
        # value bytes change.
        broker = InMemoryBroker()       # fresh broker
        broker.create_topic(Topic.TRANSACTIONS.value, 1)
        broker.produce(
            Topic.TRANSACTIONS.value,
            EventRecord(
                key=original.key,
                value=tampered_value,
                headers=dict(original.headers),
            ),
        )

        delivered = []
        consumer = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            trusted_producers=_make_trusted_set([signer]),
            processor=lambda aw, tx: delivered.append(tx),
        )
        report = consumer.consume_until_empty()

        assert delivered == []
        assert report.dead_lettered == 1
        assert report.retried == 0

    def test_tampered_signature_is_dead_lettered(self):
        """Mutate one byte of the signature — verification fails."""
        broker = InMemoryBroker()
        signer = _trusted_oracle_signer()
        producer = TransactionProducer(broker, signer=signer, clock=lambda: CONF)
        producer.produce(_agent(0), _tx(0))

        # Flip a byte in the signature header.
        original = broker.all_records(Topic.TRANSACTIONS.value)[0]
        sig_bytes = bytearray(base64.b64decode(original.headers[HEADER_SIGNATURE]))
        sig_bytes[0] ^= 0xFF
        bad_headers = dict(original.headers)
        bad_headers[HEADER_SIGNATURE] = base64.b64encode(bytes(sig_bytes)).decode("ascii")

        broker = InMemoryBroker()
        broker.create_topic(Topic.TRANSACTIONS.value, 1)
        broker.produce(
            Topic.TRANSACTIONS.value,
            EventRecord(
                key=original.key, value=original.value, headers=bad_headers,
            ),
        )

        delivered = []
        consumer = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            trusted_producers=_make_trusted_set([signer]),
            processor=lambda aw, tx: delivered.append(tx),
        )
        report = consumer.consume_until_empty()
        assert delivered == []
        assert report.dead_lettered == 1

    def test_swapped_pubkey_is_dead_lettered(self):
        """
        Sign with key A, claim to be key B in the header. Even if B is
        trusted, the signature does not verify under B's pubkey — forgery.
        """
        broker = InMemoryBroker()
        signer_a = _trusted_oracle_signer()
        signer_b_seed = Ed25519PayloadSigner.from_seed(b"vuln07-other-trusted")

        # A produces.
        producer = TransactionProducer(broker, signer=signer_a, clock=lambda: CONF)
        producer.produce(_agent(0), _tx(0))

        # An attacker rewrites the pubkey header to B's key (also trusted!).
        original = broker.all_records(Topic.TRANSACTIONS.value)[0]
        bad_headers = dict(original.headers)
        bad_headers[HEADER_PUBKEY] = base64.b64encode(signer_b_seed.public_key).decode("ascii")

        broker = InMemoryBroker()
        broker.create_topic(Topic.TRANSACTIONS.value, 1)
        broker.produce(
            Topic.TRANSACTIONS.value,
            EventRecord(
                key=original.key, value=original.value, headers=bad_headers,
            ),
        )

        delivered = []
        consumer = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            # Both A and B are trusted — yet still rejected, because the
            # signature does not verify under B's pubkey.
            trusted_producers=_make_trusted_set([signer_a, signer_b_seed]),
            processor=lambda aw, tx: delivered.append(tx),
        )
        report = consumer.consume_until_empty()

        assert delivered == []
        assert report.dead_lettered == 1

    def test_forgery_never_retries(self):
        """Forgery is non-retryable — single dead-letter, never a retry."""
        broker = InMemoryBroker()
        broker.create_topic(Topic.TRANSACTIONS.value, 1)
        # Bypass producer — write an unsigned record straight to the bus.
        broker.produce(
            Topic.TRANSACTIONS.value,
            EventRecord(
                key=_agent(0),
                value=serialize_transaction(_agent(0), _tx(0)),
                headers={},
            ),
        )

        consumer = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            trusted_producers=_make_trusted_set([_trusted_oracle_signer()]),
            processor=lambda aw, tx: None,
            max_retries=5,
        )
        report = consumer.consume_until_empty()

        # max_retries=5, but forgery never enters the retry path.
        assert report.retried == 0
        assert report.dead_lettered == 1

    def test_forgery_does_not_block_partition(self):
        """A forgery between two good records does not stall the partition."""
        broker = InMemoryBroker()
        broker.create_topic(Topic.TRANSACTIONS.value, 1)
        signer = _trusted_oracle_signer()

        producer = TransactionProducer(broker, signer=signer, clock=lambda: CONF)
        producer.produce(_agent(0), _tx(0))
        # An unsigned forgery slips onto the bus.
        broker.produce(
            Topic.TRANSACTIONS.value,
            EventRecord(
                key=_agent(0),
                value=serialize_transaction(_agent(0), _tx(99)),
                headers={},
            ),
        )
        producer.produce(_agent(0), _tx(1))

        delivered = []
        consumer = DetectionConsumer(
            broker, group="detection", consumer_id="c1",
            trusted_producers=_make_trusted_set([signer]),
            processor=lambda aw, tx: delivered.append(tx.signature),
        )
        report = consumer.consume_until_empty()

        # Two good records pass; the forgery is dead-lettered between them.
        assert report.processed == 2
        assert report.dead_lettered == 1
        # And critically, the FORGERY payload (tx 99) never reached the
        # processor — the attack is fully neutralised.
        assert _tx(99).signature not in delivered

    def test_consumer_requires_trusted_set(self):
        broker = InMemoryBroker()
        with pytest.raises((TypeError, ValueError)):
            DetectionConsumer(
                broker, group="detection", consumer_id="c1",
                processor=lambda aw, tx: None,
            )                                                    # type: ignore

    def test_consumer_rejects_none_trusted_set(self):
        broker = InMemoryBroker()
        with pytest.raises(ValueError, match="VULN-07"):
            DetectionConsumer(
                broker, group="detection", consumer_id="c1",
                trusted_producers=None,                          # type: ignore
                processor=lambda aw, tx: None,
            )


# =============================================================================
# Slot-hash mitigation #2 — provenance propagates through headers
# =============================================================================

class TestSlotHashPropagation:

    def test_slot_hash_lands_in_headers_when_provided(self):
        broker = InMemoryBroker()
        signer = _trusted_oracle_signer()
        producer = TransactionProducer(broker, signer=signer, clock=lambda: CONF)
        slot_hash = b"\x11" * 32
        producer.produce(_agent(0), _tx(0), slot_hash=slot_hash)
        record = broker.all_records(Topic.TRANSACTIONS.value)[0]
        assert HEADER_SLOT_HASH in record.headers
        assert base64.b64decode(record.headers[HEADER_SLOT_HASH]) == slot_hash

    def test_slot_hash_absent_when_not_provided(self):
        broker = InMemoryBroker()
        producer = TransactionProducer(
            broker, signer=_trusted_oracle_signer(), clock=lambda: CONF,
        )
        producer.produce(_agent(0), _tx(0))
        record = broker.all_records(Topic.TRANSACTIONS.value)[0]
        assert HEADER_SLOT_HASH not in record.headers

    def test_slot_hash_wrong_length_rejected(self):
        # A 32-byte hash is required; anything else is a programming error,
        # not a runtime poison case — fail fast at produce time.
        broker = InMemoryBroker()
        producer = TransactionProducer(
            broker, signer=_trusted_oracle_signer(), clock=lambda: CONF,
        )
        with pytest.raises(ValueError, match="slot_hash must be 32 bytes"):
            producer.produce(_agent(0), _tx(0), slot_hash=b"\x00" * 16)


# =============================================================================
# TrustedProducerSet — construction invariants
# =============================================================================

class TestTrustedProducerSet:

    def test_empty_set_refused(self):
        # A consumer that trusts no producer is a misconfiguration — refused.
        with pytest.raises(ValueError, match="non-empty"):
            TrustedProducerSet([])

    def test_duplicate_pubkey_refused(self):
        signer = _trusted_oracle_signer()
        with pytest.raises(ValueError, match="duplicate"):
            TrustedProducerSet([
                TrustedProducer(name="a", public_key=signer.public_key),
                TrustedProducer(name="b", public_key=signer.public_key),
            ])

    def test_membership_check(self):
        s1 = _trusted_oracle_signer()
        s2 = Ed25519PayloadSigner.from_seed(b"vuln07-other-trusted")
        trusted = _make_trusted_set([s1, s2])
        assert trusted.is_trusted(s1.public_key)
        assert trusted.is_trusted(s2.public_key)
        assert not trusted.is_trusted(_attacker_signer().public_key)

    def test_verify_raises_on_attacker(self):
        trusted = _make_trusted_set([_trusted_oracle_signer()])
        attacker = _attacker_signer()
        payload = b"some-payload"
        sig = attacker.sign(payload)
        with pytest.raises(UntrustedProducer):
            trusted.verify(payload, sig, attacker.public_key)

    def test_verify_raises_on_bad_signature_length(self):
        trusted = _make_trusted_set([_trusted_oracle_signer()])
        with pytest.raises(SignatureError, match="64 bytes"):
            trusted.verify(b"msg", b"\x00" * 32, _trusted_oracle_signer().public_key)

    def test_verify_raises_on_bad_pubkey_length(self):
        trusted = _make_trusted_set([_trusted_oracle_signer()])
        with pytest.raises(SignatureError, match="32 bytes"):
            trusted.verify(b"msg", b"\x00" * 64, b"\x00" * 16)
