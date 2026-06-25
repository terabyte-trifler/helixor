"""
indexer/auth.py — VULN-11 mitigation #1 + #2 substrate.

THE AUDIT FINDING
-----------------
VULN-11 (HIGH) — the Geyser / Yellowstone gRPC stream into the indexer
lacks message authentication. A network-adjacent attacker (MITM, a
compromised Geyser endpoint, a supply-chain'd plugin binary running
inside a validator) can inject synthetic transactions:

    Validator -> [ATTACKER] -> Phylanx Indexer
                 injects "Agent X succeeded 1000/1000"

The indexer trusts the stream, writes it to TimescaleDB, the scoring
engine grades Agent X as perfect, a GREEN certificate is issued, a DeFi
protocol lends to a fraudulent agent.

THE MITIGATION (this file)
--------------------------
EVERY Geyser update must be wrapped in a `SignedGeyserUpdate` envelope
carrying:

    1. The plain `GeyserTransactionUpdate` payload.
    2. The 32-byte commitment hash sha256(slot_hash || canonical_payload).
       (The audit-mandated formula. The slot_hash is the validator's
       on-chain hash for the slot the transaction landed in — a value
       only a node observing the SAME chain history can know.)
    3. The Ed25519 signature over that commitment, produced by the
       Geyser endpoint operator's key (the SOURCE identity, distinct
       from the bus producer identity used by VULN-07).
    4. The 32-byte public key of the endpoint operator.

The indexer holds a `TrustedGeyserSourceSet` — the public keys of the
Geyser endpoints it is willing to ingest from. Any update whose:

    * commitment does not recompute exactly, OR
    * signature does not verify, OR
    * signer is not in the trusted set, OR
    * slot_hash is the wrong length

is REJECTED with a `GeyserAuthError`. Rejected updates never reach the
writer, never hit the DB, never poison features.

WHY A SEPARATE TRUST SURFACE FROM VULN-07
-----------------------------------------
VULN-07's `TrustedProducerSet` authenticates bus PRODUCERS — the
indexer process and the oracle nodes. VULN-11's `TrustedGeyserSourceSet`
authenticates STREAM SOURCES — the Geyser endpoint operators (e.g. a
specific Helius cluster's identity). They are different parties at
different layers; conflating them would mean a bus-producer compromise
forges a stream signature, or vice versa. Distinct sets, distinct
rotation policies.

CANONICAL SERIALIZATION
-----------------------
The commitment binds the signature to EVERY trust-relevant field of the
update — signature, slot, success, fees, account keys, pre/post lamports,
program ids. Any mutation by an attacker invalidates the commitment.
Serialization is deterministic (sorted tuples, fixed-width ints, no
floats) so producer and verifier always compute identical bytes.

ZERO RUNTIME DEPENDENCIES IN THE TYPING SURFACE
-----------------------------------------------
The Ed25519 primitives reuse `eventbus.signing.Ed25519PayloadSigner`,
which imports `cryptography` lazily — a tooling consumer that only
needs the types never pays the import cost.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from eventbus.signing import (
    Ed25519PayloadSigner,
    PayloadSigner,
    SignatureError,
    UntrustedProducer,
)
from indexer.types import GeyserTransactionUpdate


# =============================================================================
# Constants — the audit formula
# =============================================================================

#: Length in bytes of a Solana slot hash (and of the resulting commitment,
#: since both are SHA-256). The verifier rejects anything else as malformed
#: rather than padding/truncating — silent normalization would let an
#: attacker submit a short prefix that collides with the real slot hash.
SLOT_HASH_LEN = 32

#: Length of an Ed25519 signature.
SIGNATURE_LEN = 64

#: Length of an Ed25519 public key (raw, not DER-wrapped).
PUBKEY_LEN = 32


# =============================================================================
# Exceptions
# =============================================================================

class GeyserAuthError(Exception):
    """Raised when a streamed Geyser update fails source authentication."""


class UntrustedSource(GeyserAuthError):
    """The signature verifies but the signer is not a trusted source."""


# =============================================================================
# Canonical serialization — the bytes the commitment is computed over
# =============================================================================

def canonical_update_bytes(update: GeyserTransactionUpdate) -> bytes:
    """
    Deterministic byte serialization of a `GeyserTransactionUpdate`.

    The commitment binds the signature to every trust-relevant field. Any
    mutation by an attacker — flipping `is_successful`, swapping an
    `account_key`, padding a balance change — produces different canonical
    bytes and therefore a different commitment, which the verifier rejects.

    Format (little-endian, length-prefixed):

        u32  len(signature)
        ...  signature.utf-8
        u64  slot
        u8   is_successful
        u64  fee_lamports
        u64  compute_units
        u64  priority_fee_lamports
        u32  len(account_keys)
        for each key:
            u32 len(key) | key.utf-8
        u32  len(account_changes)
        for each change:
            u32 len(pubkey) | pubkey.utf-8 | i64 pre | i64 post
        u32  len(instr_program_ids)
        for each program_id:
            u32 len(program_id) | program_id.utf-8

    `block_time` and `received_at` are deliberately NOT serialized —
    they are observation timestamps, not on-chain truth. The slot hash
    (separate input to the commitment) is the time-of-truth anchor.
    """
    out = bytearray()
    _write_str(out, update.signature)
    out += struct.pack("<Q", _u64(update.slot, "slot"))
    out += struct.pack("<B", 1 if update.is_successful else 0)
    out += struct.pack("<Q", _u64(update.fee_lamports, "fee_lamports"))
    out += struct.pack("<Q", _u64(update.compute_units, "compute_units"))
    out += struct.pack(
        "<Q", _u64(update.priority_fee_lamports, "priority_fee_lamports")
    )

    out += struct.pack("<I", len(update.account_keys))
    for key in update.account_keys:
        _write_str(out, key)

    out += struct.pack("<I", len(update.account_changes))
    for change in update.account_changes:
        _write_str(out, change.pubkey)
        out += struct.pack("<q", _i64(change.pre_lamports, "pre_lamports"))
        out += struct.pack("<q", _i64(change.post_lamports, "post_lamports"))

    out += struct.pack("<I", len(update.instr_program_ids))
    for program_id in update.instr_program_ids:
        _write_str(out, program_id)

    return bytes(out)


def _write_str(buf: bytearray, value: str) -> None:
    encoded = value.encode("utf-8")
    buf += struct.pack("<I", len(encoded))
    buf += encoded


def _u64(value: int, name: str) -> int:
    if value < 0 or value > 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError(f"{name} out of u64 range: {value}")
    return value


def _i64(value: int, name: str) -> int:
    if value < -0x8000_0000_0000_0000 or value > 0x7FFF_FFFF_FFFF_FFFF:
        raise ValueError(f"{name} out of i64 range: {value}")
    return value


# =============================================================================
# Commitment — sha256(slot_hash || canonical_update_bytes)
# =============================================================================

def commitment(slot_hash: bytes, payload_bytes: bytes) -> bytes:
    """
    The audit-mandated commitment: sha256(slot_hash || canonical_payload).

    Anchors the streamed payload to the on-chain slot hash. An attacker
    who does not observe the real chain cannot produce the slot hash and
    therefore cannot forge a matching commitment.
    """
    if len(slot_hash) != SLOT_HASH_LEN:
        raise GeyserAuthError(
            f"slot_hash must be {SLOT_HASH_LEN} bytes, got {len(slot_hash)}"
        )
    h = hashlib.sha256()
    h.update(slot_hash)
    h.update(payload_bytes)
    return h.digest()


# =============================================================================
# SignedGeyserUpdate — the wire envelope
# =============================================================================

@dataclass(frozen=True, slots=True)
class SignedGeyserUpdate:
    """
    A `GeyserTransactionUpdate` wrapped with the source's authentication
    envelope. This is what flows across the trust boundary.

    `commitment_hash` is redundant with `update` + `slot_hash` (the
    verifier recomputes it) but is carried so that downstream consumers
    can index/log by commitment without resialiazing.
    """
    update:          GeyserTransactionUpdate
    slot_hash:       bytes                  # 32-byte on-chain slot hash
    commitment_hash: bytes                  # 32-byte sha256 commitment
    signature:       bytes                  # 64-byte Ed25519 over commitment
    source_pubkey:   bytes                  # 32-byte source public key

    def __post_init__(self) -> None:
        if len(self.slot_hash) != SLOT_HASH_LEN:
            raise ValueError(
                f"slot_hash must be {SLOT_HASH_LEN} bytes, "
                f"got {len(self.slot_hash)}"
            )
        if len(self.commitment_hash) != SLOT_HASH_LEN:
            raise ValueError(
                f"commitment_hash must be {SLOT_HASH_LEN} bytes, "
                f"got {len(self.commitment_hash)}"
            )
        if len(self.signature) != SIGNATURE_LEN:
            raise ValueError(
                f"signature must be {SIGNATURE_LEN} bytes, "
                f"got {len(self.signature)}"
            )
        if len(self.source_pubkey) != PUBKEY_LEN:
            raise ValueError(
                f"source_pubkey must be {PUBKEY_LEN} bytes, "
                f"got {len(self.source_pubkey)}"
            )


# =============================================================================
# Signing — the source-side helper
# =============================================================================

def sign_update(
    update:    GeyserTransactionUpdate,
    slot_hash: bytes,
    signer:    PayloadSigner,
) -> SignedGeyserUpdate:
    """
    Wrap `update` in a `SignedGeyserUpdate` produced by `signer`.

    Used in tests and in the source-side adapter (when Phylanx itself
    operates a Geyser endpoint). When ingesting from a third-party
    endpoint, the endpoint operator runs the equivalent of this signer.
    """
    payload = canonical_update_bytes(update)
    digest = commitment(slot_hash, payload)
    signature = signer.sign(digest)
    return SignedGeyserUpdate(
        update=update,
        slot_hash=slot_hash,
        commitment_hash=digest,
        signature=signature,
        source_pubkey=signer.public_key,
    )


# =============================================================================
# TrustedGeyserSourceSet — the indexer-side allow-list
# =============================================================================

@dataclass(frozen=True, slots=True)
class TrustedGeyserSource:
    """A Geyser endpoint operator the indexer accepts updates from."""
    name:       str            # human-readable label (e.g. "helius-mainnet-1")
    public_key: bytes          # 32-byte raw Ed25519 public key

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("TrustedGeyserSource.name must be non-empty")
        if len(self.public_key) != PUBKEY_LEN:
            raise ValueError(
                f"TrustedGeyserSource.public_key must be {PUBKEY_LEN} bytes, "
                f"got {len(self.public_key)}"
            )


class TrustedGeyserSourceSet:
    """
    The set of Geyser endpoint pubkeys the indexer trusts.

    Distinct from `eventbus.signing.TrustedProducerSet` — see this module's
    docstring for why. Rotation is a redeploy.
    """

    __slots__ = ("_by_pubkey",)

    def __init__(self, sources: Iterable[TrustedGeyserSource]) -> None:
        by_pubkey: dict[bytes, TrustedGeyserSource] = {}
        for s in sources:
            if s.public_key in by_pubkey:
                raise ValueError(
                    f"duplicate trusted source pubkey: "
                    f"existing={by_pubkey[s.public_key].name!r}, "
                    f"new={s.name!r}"
                )
            by_pubkey[s.public_key] = s
        if not by_pubkey:
            raise ValueError(
                "TrustedGeyserSourceSet must be non-empty — refusing to "
                "construct a verifier that trusts no source at all"
            )
        object.__setattr__(self, "_by_pubkey", dict(by_pubkey))

    @property
    def size(self) -> int:
        return len(self._by_pubkey)

    def is_trusted(self, public_key: bytes) -> bool:
        return public_key in self._by_pubkey

    def name_of(self, public_key: bytes) -> str:
        source = self._by_pubkey.get(public_key)
        return source.name if source else "<untrusted>"


# =============================================================================
# Verification — the indexer-side gate
# =============================================================================

def verify_signed_update(
    signed:  SignedGeyserUpdate,
    trusted: TrustedGeyserSourceSet,
) -> None:
    """
    Verify a `SignedGeyserUpdate` against the trusted source set.

    Order of checks (cheapest first; do not leak why we rejected):

      1. source_pubkey must be in `trusted`.
         (Rejected before any cryptographic work — bounds CPU for
         flooding attacks.)
      2. Recompute `commitment(slot_hash, canonical_update_bytes(update))`
         and require byte-equality with `commitment_hash`.
         (Catches tampering with update fields OR with commitment_hash
         itself.)
      3. Verify `signature` over `commitment_hash` against `source_pubkey`.

    Raises `UntrustedSource` for (1) and `GeyserAuthError` for (2)+(3).
    The caller MUST treat any exception as "do not ingest".
    """
    if not trusted.is_trusted(signed.source_pubkey):
        raise UntrustedSource(
            f"source pubkey {_short_b16(signed.source_pubkey)} "
            "is not in the trusted source set"
        )

    expected = commitment(signed.slot_hash, canonical_update_bytes(signed.update))
    if expected != signed.commitment_hash:
        raise GeyserAuthError(
            "commitment hash mismatch — payload, slot_hash, or commitment "
            "was tampered with in transit"
        )

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:                       # pragma: no cover
        raise GeyserAuthError(
            "ed25519 verification requires the 'cryptography' package"
        ) from exc

    try:
        pub = Ed25519PublicKey.from_public_bytes(signed.source_pubkey)
        pub.verify(signed.signature, signed.commitment_hash)
    except Exception as exc:                          # noqa: BLE001
        raise GeyserAuthError(
            f"signature verification failed: {exc}"
        ) from exc


def _short_b16(value: bytes) -> str:
    return value.hex()[:16] + "..."


# =============================================================================
# VerifyingStreamSource — drop-in wrapper around a SignedGeyserUpdate source
# =============================================================================

@runtime_checkable
class SignedStreamSource(Protocol):
    """A source of `SignedGeyserUpdate`s (the authenticated wire form)."""

    def signed_updates(self) -> Iterator[SignedGeyserUpdate]:
        ...


class VerifyingStreamSource:
    """
    Wraps a `SignedStreamSource` and yields plain `GeyserTransactionUpdate`s
    AFTER they pass `verify_signed_update`. Rejected updates are counted
    and silently dropped — the runner observes them via `rejected_count`,
    and the deployment alerts on a non-zero count.

    Silent drop is the right behaviour: raising would let a single forged
    update tear down the indexer (a DoS). Counting + alerting keeps the
    pipeline live while making the attack visible.
    """

    __slots__ = ("_source", "_trusted", "_accepted", "_rejected", "_last_error")

    def __init__(
        self,
        source:  SignedStreamSource,
        trusted: TrustedGeyserSourceSet,
    ) -> None:
        self._source = source
        self._trusted = trusted
        self._accepted = 0
        self._rejected = 0
        self._last_error: str | None = None

    @property
    def accepted_count(self) -> int:
        return self._accepted

    @property
    def rejected_count(self) -> int:
        return self._rejected

    @property
    def last_error(self) -> str | None:
        return self._last_error

    def updates(self) -> Iterator[GeyserTransactionUpdate]:
        for signed in self._source.signed_updates():
            try:
                verify_signed_update(signed, self._trusted)
            except GeyserAuthError as exc:
                self._rejected += 1
                self._last_error = str(exc)
                continue
            self._accepted += 1
            yield signed.update


__all__ = [
    "SLOT_HASH_LEN", "SIGNATURE_LEN", "PUBKEY_LEN",
    "GeyserAuthError", "UntrustedSource",
    "canonical_update_bytes", "commitment",
    "SignedGeyserUpdate", "sign_update",
    "TrustedGeyserSource", "TrustedGeyserSourceSet",
    "verify_signed_update",
    "SignedStreamSource", "VerifyingStreamSource",
]
