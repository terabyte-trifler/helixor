"""
oracle/cluster/cert_signing.py — off-chain threshold signing for cert writes.

Day 27's on-chain `issue_certificate` rejects any cert write that does
not carry `threshold` valid cluster-key Ed25519 signatures over the
canonical certificate payload. This module is the off-chain half: it
computes the same canonical digest the on-chain `signing.rs` does, lets
each node sign it, aggregates the signatures, and builds the Ed25519
precompile instructions the transaction must include.

WHY THIS LIVES OFF-CHAIN
------------------------
Solana's Ed25519 verification happens inside a precompile, NOT inside our
program. To use it, the transaction is constructed with N pre-attached
`Ed25519Program` instructions (one per signature) BEFORE our cert ix; the
runtime verifies them natively (cheap, ~1500 CU each), and our handler
reads them out of the Instructions sysvar to confirm the signed message
matches our digest and the signer is a cluster key. So the off-chain
builder is the one that constructs those precompile instructions — they
are part of the transaction the cluster submits.

DETERMINISM
-----------
The canonical digest is pure stdlib (sha256, fixed byte layout) — every
node computes the byte-identical hash, and so does the on-chain code.
Signing itself is Ed25519: the SIGNATURE BYTES depend on the keypair (and
in Ed25519 are even deterministic given the same key + message), but the
*verification* is purely a check, and the threshold count is a pure
integer comparison. So the cluster's decision to submit (or not to) is
deterministic given the signature set.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence
from dataclasses import dataclass

from oracle.cluster.identity import NodeIdentity, NodeKeypair


# =============================================================================
# Canonical cert-payload digest
# =============================================================================

def cert_payload_digest(
    agent_wallet_bytes: bytes,
    epoch:              int,
    score:              int,
    alert_tier:         int,
    flags:              int,
    immediate_red:      bool,
) -> bytes:
    """
    The 32-byte canonical cert-payload digest — byte-identical to the
    on-chain `signing::cert_payload_digest`. Each cluster node signs THIS
    digest; the on-chain handler recomputes it and verifies the signed
    message matches.

    `agent_wallet_bytes` is the 32-byte Solana pubkey of the agent.
    """
    import hashlib

    if len(agent_wallet_bytes) != 32:
        raise ValueError("agent_wallet_bytes must be 32 bytes")
    if not (0 <= score <= 0xFFFF):
        raise ValueError(f"score out of u16 range: {score}")
    if not (0 <= alert_tier <= 0xFF):
        raise ValueError(f"alert_tier out of u8 range: {alert_tier}")
    if not (0 <= flags <= 0xFFFFFFFF):
        raise ValueError(f"flags out of u32 range: {flags}")
    if not (0 <= epoch <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError(f"epoch out of u64 range: {epoch}")

    immediate_red_byte = b"\x01" if immediate_red else b"\x00"
    payload = (
        agent_wallet_bytes                              # 32
        + epoch.to_bytes(8, "big")                      #  8
        + score.to_bytes(2, "big")                      #  2
        + alert_tier.to_bytes(1, "big")                 #  1
        + flags.to_bytes(4, "big")                      #  4
        + immediate_red_byte                            #  1
    )
    return hashlib.sha256(payload).digest()


# =============================================================================
# A single cluster signature
# =============================================================================

@dataclass(frozen=True, slots=True)
class ClusterSignature:
    """
    One node's Ed25519 signature over a cert-payload digest.

    `signer_pubkey` is the node's 32-byte Ed25519 public key (its on-chain
    cluster key); `signature` is the 64-byte Ed25519 signature.
    """
    signer_pubkey: bytes
    signature:     bytes
    digest:        bytes        # the 32-byte message that was signed

    def __post_init__(self) -> None:
        if len(self.signer_pubkey) != 32:
            raise ValueError("signer_pubkey must be 32 bytes")
        if len(self.signature) != 64:
            raise ValueError("signature must be 64 bytes")
        if len(self.digest) != 32:
            raise ValueError("digest must be 32 bytes")


# =============================================================================
# Node signs the cert digest
# =============================================================================

def sign_cert_digest(
    keypair: NodeKeypair,
    digest:  bytes,
) -> ClusterSignature:
    """
    Have `keypair` sign the cert digest. Returns the ClusterSignature
    record other nodes can aggregate.
    """
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    signature = keypair.sign(digest)
    return ClusterSignature(
        signer_pubkey=keypair.public_key,
        signature=signature,
        digest=digest,
    )


# =============================================================================
# Aggregate signatures to threshold
# =============================================================================

class InsufficientSignatures(Exception):
    """Raised when the aggregator has fewer than `threshold` distinct
    cluster-key signatures over the same digest."""

    def __init__(self, got: int, needed: int) -> None:
        super().__init__(
            f"only {got} distinct cluster signatures; threshold is {needed}"
        )
        self.got = got
        self.needed = needed


@dataclass(frozen=True, slots=True)
class AggregatedSignatures:
    """A threshold-satisfying set of cluster signatures over a digest."""
    digest:     bytes
    signatures: tuple[ClusterSignature, ...]

    @property
    def count(self) -> int:
        return len(self.signatures)


def aggregate_signatures(
    digest:        bytes,
    signatures:    Sequence[ClusterSignature],
    *,
    cluster_keys:  Sequence[bytes],
    threshold:     int,
) -> AggregatedSignatures:
    """
    Aggregate `signatures` into a threshold-satisfying set.

    Filters:
      - signatures must be over THIS `digest` (different digest -> ignored,
        a node signing the wrong thing does not count),
      - signer must be one of `cluster_keys`,
      - each distinct signer counts only once (dedup),
      - signature bytes must verify against the signer's public key (the
        precompile would otherwise reject the transaction, but we screen
        client-side so a bad signature is caught before the tx is even
        submitted).

    Raises `InsufficientSignatures` if the post-filter count is below
    `threshold`. Otherwise returns the first `threshold` valid signatures
    in pubkey-sorted order — deterministic, so two honest aggregators
    produce the same set.
    """
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    if threshold < 1:
        raise ValueError("threshold must be >= 1")

    cluster_set = {bytes(k) for k in cluster_keys}
    seen_signers: set[bytes] = set()
    valid: list[ClusterSignature] = []

    for sig in signatures:
        if sig.digest != digest:
            continue
        if sig.signer_pubkey not in cluster_set:
            continue
        if sig.signer_pubkey in seen_signers:
            continue
        if not _verify_ed25519(sig.signer_pubkey, sig.signature, digest):
            continue
        seen_signers.add(sig.signer_pubkey)
        valid.append(sig)

    if len(valid) < threshold:
        raise InsufficientSignatures(got=len(valid), needed=threshold)

    # Deterministic order — sort by signer pubkey, take the first `threshold`.
    valid.sort(key=lambda s: s.signer_pubkey)
    return AggregatedSignatures(
        digest=digest, signatures=tuple(valid[:threshold]),
    )


def _verify_ed25519(pubkey: bytes, signature: bytes, message: bytes) -> bool:
    """
    Verify an Ed25519 signature off-chain. The on-chain precompile does
    its own verification (or the transaction aborts); this is a
    pre-submission screen so a malformed signature is caught locally.
    """
    return NodeIdentity(node_id="verifier", public_key=pubkey).verify(
        message, signature,
    )


# =============================================================================
# Building Ed25519 precompile instructions
# =============================================================================
#
# The Ed25519Program instruction layout for a single signature record we
# emit (16-byte header + pubkey + signature + message):
#
#   offset  size  field
#   0       1     num_signatures (= 1)
#   1       1     padding (0)
#   2       2     signature_offset       (LE u16)
#   4       2     signature_ix_index     (LE u16, 0xFFFF = "this ix")
#   6       2     public_key_offset      (LE u16)
#   8       2     public_key_ix_index    (LE u16, 0xFFFF)
#   10      2     message_data_offset    (LE u16)
#   12      2     message_data_size      (LE u16)
#   14      2     message_ix_index       (LE u16, 0xFFFF)
#   16      32    public key
#   48      64    signature
#   112     32    message
#
# Total: 144 bytes.

ED25519_PROGRAM_ID = "Ed25519SigVerify111111111111111111111111111"
THIS_IX_SENTINEL = 0xFFFF
HEADER_LEN = 16
PUBKEY_LEN = 32
SIGNATURE_LEN = 64
MESSAGE_LEN = 32     # our digest is always 32 bytes


def build_ed25519_ix_data(sig: ClusterSignature) -> bytes:
    """
    Build the 144-byte data blob for an Ed25519Program instruction that
    verifies one `ClusterSignature`. The on-chain handler's
    `parse_ed25519_ix` reads this exact layout.
    """
    pk_offset  = HEADER_LEN
    sig_offset = pk_offset + PUBKEY_LEN
    msg_offset = sig_offset + SIGNATURE_LEN

    header = struct.pack(
        "<BBHHHHHHH",
        1,                          # num_signatures
        0,                          # padding
        sig_offset,                 # signature_offset
        THIS_IX_SENTINEL,           # signature_ix_index
        pk_offset,                  # public_key_offset
        THIS_IX_SENTINEL,           # public_key_ix_index
        msg_offset,                 # message_data_offset
        MESSAGE_LEN,                # message_data_size
        THIS_IX_SENTINEL,           # message_ix_index
    )
    return header + sig.signer_pubkey + sig.signature + sig.digest


def build_ed25519_instructions(
    aggregated: AggregatedSignatures,
) -> list[dict]:
    """
    Build a list of Ed25519 precompile-instruction descriptors — one per
    signature — for inclusion in a transaction before the cert ix.

    Each descriptor is `{"program_id": ED25519_PROGRAM_ID, "data": bytes,
    "accounts": []}` — the precompile takes no accounts. A real tx builder
    (the helixor-sdk Day-27 work, or the harness Anchor test) turns this
    into a `TransactionInstruction`.
    """
    return [
        {
            "program_id": ED25519_PROGRAM_ID,
            "data": build_ed25519_ix_data(sig),
            "accounts": [],
        }
        for sig in aggregated.signatures
    ]
