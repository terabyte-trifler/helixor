"""
oracle/cluster/input_commitment.py — AW-01 INPUT-PROVENANCE COMMITMENT.

The fix for architectural weakness AW-01 "Trust Transitivity":

    DeFi → on-chain HealthCertificate → cluster signature → ORACLE NODES
                                                              ↑↑↑
                                                  THIS IS THE GAP
                                                              ↓↓↓
        scoring  ← features ← transactions ← indexer ← Kafka ← Geyser ← validator

Before AW-01 the on-chain Ed25519 signature proved "≥threshold cluster nodes
agreed on this score" — but said NOTHING about whether those nodes were fed
the same, correct inputs. An attacker that poisoned the Geyser plugin, the
Kafka topic, or the indexer could feed FALSE transactions to every node;
all nodes would honestly agree on the resulting (false) score; the
threshold sig would pass; the on-chain cert would lock in a lie.

This module is the per-node primitive that closes the loop:

    input_commitment = sha256( canonical( agent_wallet,
                                          baseline_window,
                                          current_window,
                                          sorted(transactions),
                                          baseline_hash ) )

Three guarantees this enables:

  1. **Per-node binding.** A node folds its `input_commitment` into the
     Day-25 commit hash. A node that wants to swap inputs after seeing
     peers' commits cannot — its reveal would fail hash verification.

  2. **Cross-node agreement.** During aggregation, the cluster only issues
     a cert if a quorum of nodes agree on the input commitment. A node
     fed bad data by a poisoned indexer sits in the minority and is
     surfaced via the INPUT_DIVERGENCE flag bit.

  3. **On-chain attestation of INPUTS.** The 32-byte commitment is folded
     into `cert_payload_digest`, so the on-chain Ed25519 signature
     cryptographically attests to the inputs — not just to cluster
     agreement. DeFi consumers re-derive the commitment from the
     observable transactions and refuse certs whose declared inputs do
     not match what they see on-chain.

DETERMINISM
-----------
Two oracle nodes given byte-identical inputs MUST produce the byte-identical
commitment. The implementation is pure stdlib (sha256 + struct), no
floating-point, no Vec ordering ambiguity. Transactions are sorted by
(slot, signature) so the input order from the Kafka topic does not change
the commitment. Every variable-length field is length-prefixed so two
distinct payloads cannot collide.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timezone

from features import ExtractionWindow, Transaction


# 32-byte SHA-256 digest output.
COMMITMENT_BYTES = 32

# Schema-version tag — folded in so a future canonical-form change is
# detectable on chain (a v1 commitment never collides with a v2 commitment).
#
# v1 → v2 (AW-01-EXT): appended a SlotAnchor (8-byte slot + 32-byte block
# hash) so the commitment is now bound to a SPECIFIC point in Solana's own
# ledger. An attacker would have to forge Solana's history to coax the
# cluster into committing over inputs from a slot that does not exist.
INPUT_COMMITMENT_VERSION: int = 2

# Number of bytes the canonical-anchor payload contributes:
#   u64 BE slot           (8)
# + 32-byte block hash    (32)
SLOT_ANCHOR_BYTES: int = 40


# =============================================================================
# Solana slot anchor (AW-01-EXT)
# =============================================================================

@dataclass(frozen=True, slots=True)
class SlotAnchor:
    """
    A point in Solana's own ledger that the cluster commits to as part of
    the input-provenance bind. The on-chain handler later verifies (slot,
    block_hash) is present in the `SlotHashes` sysvar — so an attacker
    that wants to poison the upstream inputs would also need to forge
    Solana's recent block history.

    Fields:
      - `slot` is the absolute Solana slot number (u64).
      - `block_hash` is the 32-byte SHA-256 (Solana "Hash") of that slot's
        finalised bank. Both nodes and consumers can fetch this from any
        Solana RPC via `getBlock(slot)` / `getSlotHashes()`.

    The on-chain `SlotHashes` sysvar retains the last ~512 slots, so an
    anchor older than that cannot be verified. The cluster therefore
    captures a fresh anchor at the moment of scoring and submits the cert
    quickly enough that the slot is still in the sysvar window.
    """
    slot:       int
    block_hash: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.slot, int) or isinstance(self.slot, bool):
            raise TypeError(
                f"slot must be int, got {type(self.slot).__name__}"
            )
        if not (0 <= self.slot <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError(f"slot out of u64 range: {self.slot}")
        if not isinstance(self.block_hash, (bytes, bytearray)):
            raise TypeError("block_hash must be bytes")
        if len(self.block_hash) != 32:
            raise ValueError(
                f"block_hash must be 32 bytes, got {len(self.block_hash)}"
            )
        # Normalise to immutable bytes so `==` and hashing are stable
        # across bytes/bytearray inputs.
        object.__setattr__(self, "block_hash", bytes(self.block_hash))

    def to_bytes(self) -> bytes:
        """The canonical 40-byte serialisation: u64 BE slot + 32B hash.
        Matches the on-chain `cert_payload_digest` byte order exactly."""
        return self.slot.to_bytes(8, "big") + self.block_hash

    @staticmethod
    def zero() -> "SlotAnchor":
        """A sentinel anchor used by tests + the audit scanner. The
        on-chain handler refuses a zero anchor at issuance time — the same
        defence-in-depth pattern as the zero `input_commitment` refusal."""
        return SlotAnchor(slot=0, block_hash=b"\x00" * 32)


# =============================================================================
# Canonical per-transaction bytes
# =============================================================================

def _encode_str(value: str) -> bytes:
    """Length-prefix (u16 big-endian) + UTF-8 bytes. Prevents concatenation
    ambiguity — two distinct strings cannot run together and collide."""
    encoded = value.encode("utf-8")
    if len(encoded) > 0xFFFF:
        raise ValueError(
            f"string field too long for u16 length prefix: {len(encoded)}"
        )
    return len(encoded).to_bytes(2, "big") + encoded


def _encode_optional_str(value: str | None) -> bytes:
    """A 1-byte present-flag (0/1) followed by the length-prefixed string if
    present. Distinguishes empty-string from absent — both real possibilities
    for `counterparty`."""
    if value is None:
        return b"\x00"
    return b"\x01" + _encode_str(value)


def _encode_block_time_micros(when) -> bytes:
    """Encode `block_time` as i64 big-endian unix microseconds (UTC). The
    Transaction dataclass guarantees tz-aware UTC at construction; we
    re-assert here to keep this primitive self-defending.

    Microseconds (not nanoseconds) — Python's datetime resolution caps at
    microseconds, and a Kafka pipeline that round-trips through `datetime`
    cannot deliver nanos."""
    if when.tzinfo is None:
        raise ValueError("Transaction.block_time must be timezone-aware UTC")
    # Normalise to UTC even if a caller passed a non-UTC tz.
    if when.utcoffset() != timezone.utc.utcoffset(None):
        when = when.astimezone(timezone.utc)
    epoch_us = int(when.timestamp() * 1_000_000)
    # Two's-complement i64 wrap via signed conversion.
    return epoch_us.to_bytes(8, "big", signed=True)


def _encode_transaction(tx: Transaction) -> bytes:
    """The canonical byte form of one transaction. Every field included; no
    floats; fixed-width integers; length-prefixed strings. Same on every
    node."""
    parts: list[bytes] = [
        _encode_str(tx.signature),
        tx.slot.to_bytes(8, "big"),
        _encode_block_time_micros(tx.block_time),
        b"\x01" if tx.success else b"\x00",
        # program_ids: u16 count + length-prefixed strings.
        len(tx.program_ids).to_bytes(2, "big"),
    ]
    for pid in tx.program_ids:
        parts.append(_encode_str(pid))
    parts.extend([
        tx.sol_change.to_bytes(8, "big", signed=True),
        tx.fee.to_bytes(8, "big"),
        tx.priority_fee.to_bytes(8, "big"),
        tx.compute_units.to_bytes(8, "big"),
        _encode_optional_str(tx.counterparty),
    ])
    return b"".join(parts)


def _encode_window(window: ExtractionWindow) -> bytes:
    """An ExtractionWindow as two i64 big-endian unix microseconds (start,
    end). Aware of the timezone contract."""
    return (
        _encode_block_time_micros(window.start)
        + _encode_block_time_micros(window.end)
    )


def _canonical_transactions(txs: Sequence[Transaction]) -> bytes:
    """Sort transactions by (slot, signature) and concatenate their
    canonical bytes. Sorting kills any Kafka-/replay-order dependence: the
    same transaction set always produces the same bytes.

    A u32 count prefix binds the cardinality — two distinct multisets
    cannot collide via prefix-extension."""
    ordered = sorted(txs, key=lambda t: (t.slot, t.signature))
    parts: list[bytes] = [len(ordered).to_bytes(4, "big")]
    for tx in ordered:
        encoded = _encode_transaction(tx)
        # Per-tx length prefix so a malformed-canonicalisation in one field
        # cannot bleed into the next transaction's bytes.
        parts.append(len(encoded).to_bytes(4, "big"))
        parts.append(encoded)
    return b"".join(parts)


# =============================================================================
# The commitment
# =============================================================================

def compute_input_commitment(
    agent_wallet:          str,
    baseline_window:       ExtractionWindow,
    current_window:        ExtractionWindow,
    baseline_transactions: Sequence[Transaction],
    current_transactions:  Sequence[Transaction],
    baseline_hash:         bytes,
    slot_anchor:           SlotAnchor,
) -> bytes:
    """
    The 32-byte input-provenance commitment for ONE agent's scoring input.

    A node binds this commitment into its Day-25 commit hash AND into the
    cert-payload digest. An attacker that poisons inputs at ANY upstream
    layer (Geyser, Kafka, indexer, score-time data fetch) produces a
    different commitment — and is rejected by both the cross-node agreement
    check and any SDK consumer re-deriving the commitment from on-chain
    observable transactions.

    The commitment covers:
      - the agent wallet (so cross-agent input swaps are caught),
      - both extraction windows (start + end, as i64 µs UTC),
      - both transaction sets (canonically sorted by (slot, signature)),
      - the baseline_hash (so a swap of baseline-vs-current doesn't slip
        through; redundant with the cert digest's baseline_hash but binds
        it INTO the input commitment too so the agreement check covers
        it),
      - the SlotAnchor (AW-01-EXT) — `(slot u64 BE, block_hash 32B)`.
        Binds the commitment to Solana's own ledger so an attacker that
        poisons every upstream RPC the cluster reads from STILL cannot
        produce a commitment that matches a slot Solana itself recorded.
        The on-chain handler verifies the same `slot_anchor` against the
        `SlotHashes` sysvar at cert-issue time.

    Determinism: pure stdlib SHA-256 over canonical bytes. Two nodes given
    the same inputs produce byte-identical output.
    """
    if not agent_wallet:
        raise ValueError("agent_wallet must be non-empty")
    if len(baseline_hash) != 32:
        raise ValueError(
            f"baseline_hash must be 32 bytes, got {len(baseline_hash)}"
        )
    if not isinstance(slot_anchor, SlotAnchor):
        raise TypeError(
            f"slot_anchor must be SlotAnchor, got {type(slot_anchor).__name__}"
        )

    payload = (
        # Schema version — bumped if the canonical form ever changes.
        INPUT_COMMITMENT_VERSION.to_bytes(2, "big")
        + _encode_str(agent_wallet)
        + _encode_window(baseline_window)
        + _encode_window(current_window)
        + _canonical_transactions(baseline_transactions)
        + _canonical_transactions(current_transactions)
        + bytes(baseline_hash)
        + slot_anchor.to_bytes()              # AW-01-EXT (40 bytes)
    )
    return hashlib.sha256(payload).digest()


def commitments_agree(
    commitments: Sequence[bytes],
    quorum:      int,
) -> tuple[bytes | None, frozenset[int]]:
    """
    Given a sequence of per-node `input_commitment` bytes (one per node),
    return:
      - the MAJORITY commitment that meets `quorum`, or None if no group
        does;
      - the set of indices in `commitments` whose commitment differs from
        the majority (the "divergent minority" — surfaced via
        INPUT_DIVERGENCE so the watchdog can attribute strikes).

    Ties: the first commitment to reach `quorum` wins. With a strict
    majority quorum (>n/2) ties are impossible by construction.

    Pure + deterministic.
    """
    if quorum < 1:
        raise ValueError("quorum must be >= 1")

    counts: dict[bytes, int] = {}
    for c in commitments:
        if len(c) != COMMITMENT_BYTES:
            raise ValueError(
                f"commitment must be {COMMITMENT_BYTES} bytes, got {len(c)}"
            )
        counts[c] = counts.get(c, 0) + 1

    majority: bytes | None = None
    for c, n in counts.items():
        if n >= quorum:
            majority = c
            break

    if majority is None:
        return None, frozenset(range(len(commitments)))

    divergent = frozenset(
        i for i, c in enumerate(commitments) if c != majority
    )
    return majority, divergent
