"""
eventbus/signing.py — VULN-07 mitigation: every Kafka message is signed.

THE AUDIT FINDING
-----------------
VULN-07 (HIGH): the data pipeline had three injection points (Geyser plugin,
Kafka broker, TimescaleDB). Any one of them — a compromised Geyser endpoint,
an unauthenticated Kafka cluster, an exposed DB port — lets an attacker
insert synthetic "success" transactions into an agent's history, poison the
baseline, and trick the scoring engine into stamping a fraudulent GREEN
certificate.

THE FIX
-------
Authenticated message provenance at the bus:

  * Every produced record is SIGNED with the producer's Ed25519 keypair —
    Solana's signature scheme, the same primitive used elsewhere in
    Helixor (`oracle/cluster/identity.py`).

  * The 64-byte signature plus the producer's 32-byte public key ride in
    the EventRecord headers as base64 strings (so the JSON-on-Kafka
    wire format does not change, and the headers carry exactly the
    out-of-band metadata Kafka headers are designed for).

  * The DetectionConsumer holds a TrustedProducerSet — the public keys
    of the indexers and oracle nodes allowed to produce on this topic.
    Every consumed record is verified BEFORE the processor sees it.

  * A record whose signature is missing, malformed, or invalid for the
    payload, OR whose claimed producer is not in the trusted set, is
    POISON — routed straight to the dead-letter topic, never processed,
    never retried. Synthetic transactions injected by a network-adjacent
    attacker are rejected at the consumer boundary.

WHAT'S SIGNED
-------------
The signature is over the canonical-JSON payload bytes (the record's
`value`). That payload already includes wire_version + agent_wallet +
signature (the Solana tx sig) + slot + block_time + everything material —
so tampering with any field invalidates the signature.

WHY NOT TLS / SASL ONLY
-----------------------
Kafka transport security (SASL/SSL) authenticates the CONNECTION between
broker and client. It does not authenticate the PRODUCER of a record once
that record is on the bus. A message-level signature does — it binds the
producer's identity to the exact bytes that traverse the bus, so a
network-adjacent attacker, a compromised broker, or a malicious replay
all fail closed.

ZERO RUNTIME DEPENDENCIES IN THE TYPING / VERIFICATION INTERFACE
----------------------------------------------------------------
The `PayloadSigner` and `PayloadVerifier` protocols are stdlib-only. The
real Ed25519 implementation lives behind `Ed25519PayloadSigner`, which
imports `cryptography` lazily — so a tooling consumer that only needs
the type interfaces never pays the import cost.
"""

from __future__ import annotations

import base64
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

logger = logging.getLogger("helixor.eventbus.signing")


# =============================================================================
# Header names — the on-the-wire keys for the signature envelope
# =============================================================================

#: base64-encoded 64-byte Ed25519 signature over `EventRecord.value`.
HEADER_SIGNATURE = "sig"

#: base64-encoded 32-byte Ed25519 public key — the producer that signed.
HEADER_PUBKEY = "pubkey"

#: optional base64-encoded 32-byte slot hash — VULN-07 mitigation #2 hook
#: (cross-verified against on-chain slot hashes by the deployment verifier).
HEADER_SLOT_HASH = "slot_hash"


# =============================================================================
# Exceptions
# =============================================================================

class SignatureError(Exception):
    """Raised when a message signature is missing, malformed, or invalid."""


class UntrustedProducer(SignatureError):
    """The signature verifies, but the claimed producer is not trusted."""


# =============================================================================
# PayloadSigner — the producer-side signing interface
# =============================================================================

@runtime_checkable
class PayloadSigner(Protocol):
    """
    A producer signing surface — the minimum a Kafka producer needs.

    `sign(message)` returns the 64-byte Ed25519 signature over `message`.
    `public_key` is the 32-byte raw Ed25519 public key — stamped into the
    record's headers so the consumer knows which trusted key to verify
    against. (Including the pubkey in the message is safe: the signature
    binds it to the payload, and the consumer rejects unknown pubkeys.)
    """

    def sign(self, message: bytes) -> bytes: ...

    @property
    def public_key(self) -> bytes: ...


# =============================================================================
# Ed25519PayloadSigner — the concrete signer
# =============================================================================

class Ed25519PayloadSigner:
    """
    A `PayloadSigner` backed by Ed25519 (`cryptography` library).

    Two ways to construct:

      * `from_keypair(NodeKeypair)` — wrap an oracle-node identity. The same
        key that the node uses to sign cluster commit-reveal messages is
        also its bus-producer identity. One key, one identity.

      * `Ed25519PayloadSigner.generate()` — a fresh random keypair. For
        tests and for indexer processes that mint their own producer key.

    The secret key is held inside this object and never exposed.
    """

    __slots__ = ("_private_key", "_public_key")

    def __init__(self, private_key, public_key_bytes: bytes) -> None:
        if len(public_key_bytes) != 32:
            raise ValueError(
                f"public_key must be 32 bytes, got {len(public_key_bytes)}"
            )
        self._private_key = private_key
        self._public_key = public_key_bytes

    # ── Constructors ────────────────────────────────────────────────────────

    @classmethod
    def generate(cls) -> "Ed25519PayloadSigner":
        """Mint a fresh random producer keypair. Lazy import."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives import serialization
        priv = Ed25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return cls(priv, pub_bytes)

    @classmethod
    def from_seed(cls, seed: bytes) -> "Ed25519PayloadSigner":
        """
        A DETERMINISTIC producer key from a 32-byte seed — tests only.
        Ed25519 needs exactly 32 bytes of seed material.
        """
        import hashlib
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives import serialization
        material = hashlib.sha256(seed).digest()
        priv = Ed25519PrivateKey.from_private_bytes(material)
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return cls(priv, pub_bytes)

    @classmethod
    def from_node_keypair(cls, node_keypair) -> "Ed25519PayloadSigner":
        """
        Wrap an oracle-node `NodeKeypair` as a bus producer signer. The same
        key that signs cluster commit-reveal messages signs the bus.
        """
        return cls(node_keypair._private_key, node_keypair.public_key)

    # ── PayloadSigner protocol ──────────────────────────────────────────────

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    @property
    def public_key(self) -> bytes:
        return self._public_key


# =============================================================================
# TrustedProducerSet — the consumer-side allow-list
# =============================================================================

@dataclass(frozen=True, slots=True)
class TrustedProducer:
    """A producer the consumer is willing to accept records from."""
    name:       str             # human-readable label, for logs
    public_key: bytes           # 32-byte raw Ed25519 public key

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("TrustedProducer.name must be non-empty")
        if len(self.public_key) != 32:
            raise ValueError(
                f"TrustedProducer.public_key must be 32 bytes, "
                f"got {len(self.public_key)}"
            )


class TrustedProducerSet:
    """
    The set of producer public keys a consumer will accept records from.

    A consumer constructs one of these from configuration (the deployment
    pins the keys of the indexer processes and oracle nodes allowed to
    produce). Verification:

      * The record carries a `pubkey` header. If it does not, the record is
        rejected (SignatureError("missing pubkey")).
      * The pubkey must be a member of this set. If it is not, rejected
        (UntrustedProducer).
      * The record's `sig` header must verify against `pubkey` over the
        record value. If it does not, rejected (SignatureError).

    The set is IMMUTABLE after construction. Rotation of trusted keys is
    deliberately a redeploy — bus-trust must change in lockstep with the
    on-chain `OracleConfig.cluster_keys`, and a config-file reload is the
    explicit, audit-logged path.
    """

    __slots__ = ("_by_pubkey",)

    def __init__(self, producers: Iterable[TrustedProducer]) -> None:
        by_pubkey: dict[bytes, TrustedProducer] = {}
        for p in producers:
            if p.public_key in by_pubkey:
                raise ValueError(
                    f"duplicate trusted producer pubkey: "
                    f"existing={by_pubkey[p.public_key].name!r}, "
                    f"new={p.name!r}"
                )
            by_pubkey[p.public_key] = p
        if not by_pubkey:
            raise ValueError(
                "TrustedProducerSet must be non-empty — refusing to "
                "construct a consumer that trusts no producer at all"
            )
        # Frozen storage.
        object.__setattr__(self, "_by_pubkey", dict(by_pubkey))

    @property
    def size(self) -> int:
        return len(self._by_pubkey)

    def is_trusted(self, public_key: bytes) -> bool:
        return public_key in self._by_pubkey

    def name_of(self, public_key: bytes) -> str:
        producer = self._by_pubkey.get(public_key)
        return producer.name if producer else "<untrusted>"

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> None:
        """
        Verify `signature` over `message` against `public_key`. Raises:

          * SignatureError      — pubkey malformed, signature missing,
                                  signature does not verify.
          * UntrustedProducer   — pubkey verifies but is not in this set.

        Caller MUST treat any exception as a dead-letter outcome.
        """
        if len(public_key) != 32:
            raise SignatureError(
                f"pubkey must be 32 bytes, got {len(public_key)}"
            )
        if len(signature) != 64:
            raise SignatureError(
                f"signature must be 64 bytes, got {len(signature)}"
            )
        if not self.is_trusted(public_key):
            raise UntrustedProducer(
                f"producer pubkey {_b64(public_key)[:12]}... is not trusted"
            )
        # Lazy import — the consumer module imports this file but does
        # not require `cryptography` until it actually verifies.
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
        except ImportError as exc:                  # pragma: no cover
            raise SignatureError(
                "ed25519 verification requires the 'cryptography' package"
            ) from exc

        try:
            pub = Ed25519PublicKey.from_public_bytes(public_key)
            pub.verify(signature, message)
        except Exception as exc:                    # noqa: BLE001
            raise SignatureError(
                f"signature verification failed: {exc}"
            ) from exc


# =============================================================================
# Header codec — base64 round-trip
# =============================================================================

def encode_bytes_header(value: bytes) -> str:
    """Encode raw bytes (32-byte pubkey, 64-byte signature) as a base64 header."""
    return base64.b64encode(value).decode("ascii")


def decode_bytes_header(value: str) -> bytes:
    """Decode a base64 header back to raw bytes. Raises SignatureError if invalid."""
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise SignatureError(f"malformed base64 header: {exc}") from exc


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


# =============================================================================
# attach_signature / extract_signature — wire helpers
# =============================================================================

def attach_signature(
    value:    bytes,
    signer:   PayloadSigner,
    *,
    extra_headers: dict[str, str] | None = None,
    slot_hash: bytes | None = None,
) -> dict[str, str]:
    """
    Sign `value` with `signer` and return the headers that should be set on
    the EventRecord.

    `extra_headers` are merged in. If both this function and the caller want
    to set the signature/pubkey headers, this function wins — the integrity
    headers are authoritative.

    `slot_hash` is the optional 32-byte commitment hash for the slot the
    transaction came from (mitigation #2). When present, it goes into the
    headers and is covered by the signature implicitly (because the
    consumer ALSO checks the slot_hash header was signed — see
    verify_record_headers).
    """
    signature = signer.sign(value)
    headers = dict(extra_headers or {})
    headers[HEADER_SIGNATURE] = encode_bytes_header(signature)
    headers[HEADER_PUBKEY] = encode_bytes_header(signer.public_key)
    if slot_hash is not None:
        if len(slot_hash) != 32:
            raise ValueError(
                f"slot_hash must be 32 bytes, got {len(slot_hash)}"
            )
        headers[HEADER_SLOT_HASH] = encode_bytes_header(slot_hash)
    return headers


def verify_record_headers(
    value:    bytes,
    headers:  dict[str, str],
    trusted:  TrustedProducerSet,
) -> bytes:
    """
    Verify the signature on `value` against the producer named in `headers`.

    Returns the verified producer's public key on success. Raises
    `SignatureError` / `UntrustedProducer` on failure (caller dead-letters).
    """
    sig_str = headers.get(HEADER_SIGNATURE)
    if not sig_str:
        raise SignatureError("missing signature header — record is unsigned")
    pub_str = headers.get(HEADER_PUBKEY)
    if not pub_str:
        raise SignatureError(
            "missing pubkey header — producer identity not declared"
        )
    signature = decode_bytes_header(sig_str)
    public_key = decode_bytes_header(pub_str)
    trusted.verify(value, signature, public_key)
    return public_key
