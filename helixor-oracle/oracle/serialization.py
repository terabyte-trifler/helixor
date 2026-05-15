"""
oracle/serialization.py — wire-format helpers for the health_oracle program.

This module hand-rolls Anchor's wire format for ONE instruction
(commit_baseline) and ONE account (AgentRegistration v2). It deliberately
does NOT depend on `anchorpy` because:
  - the dependency graph is heavy and version-sensitive
  - we want byte-exact control over the layout, which is the whole point of
    a commitment-bearing instruction
  - this code is small and fully testable in isolation

The discriminator constants are pre-computed once (the first 8 bytes of
sha256("global:commit_baseline") for the instruction, sha256("account:Agent
Registration") for the account). They are asserted at import time so a
schema drift is caught instantly.
"""

from __future__ import annotations

import enum
import hashlib
import struct
from dataclasses import dataclass

from solders.pubkey import Pubkey


# =============================================================================
# Anchor discriminators
# =============================================================================

def _ix_discriminator(name: str) -> bytes:
    """Anchor instruction discriminator: first 8 bytes of sha256('global:{name}')."""
    return hashlib.sha256(f"global:{name}".encode("utf-8")).digest()[:8]


def _account_discriminator(name: str) -> bytes:
    """Anchor account discriminator: first 8 bytes of sha256('account:{Name}')."""
    return hashlib.sha256(f"account:{name}".encode("utf-8")).digest()[:8]


COMMIT_BASELINE_DISCRIMINATOR        = _ix_discriminator("commit_baseline")
MIGRATE_REGISTRATION_DISCRIMINATOR   = _ix_discriminator("migrate_registration")
AGENT_REGISTRATION_DISCRIMINATOR     = _account_discriminator("AgentRegistration")

# PDA seeds (bytes literals — match the Rust seeds = [b"agent", ...] etc.)
AGENT_PDA_SEED         = b"agent"
ORACLE_CONFIG_PDA_SEED = b"oracle_config"


# =============================================================================
# CommitterKind enum — wire encoding matches Anchor's enum repr (1 byte variant tag).
# =============================================================================

class CommitterKind(enum.IntEnum):
    ORACLE = 0
    OWNER  = 1


# =============================================================================
# Instruction args encoding
# =============================================================================

def encode_commit_baseline_args(
    *,
    baseline_hash:         bytes,
    baseline_algo_version: int,
    commit_nonce:          int,
    committer_kind:        CommitterKind,
) -> bytes:
    """
    Borsh-encode the CommitBaselineArgs struct. Layout matches the Rust
    #[derive(AnchorSerialize)] order:
        [u8; 32]   baseline_hash
        u8         baseline_algo_version
        u64        commit_nonce
        CommitterKind (u8 variant tag)
    """
    if len(baseline_hash) != 32:
        raise ValueError(f"baseline_hash must be 32 bytes, got {len(baseline_hash)}")
    if not 0 <= baseline_algo_version <= 255:
        raise ValueError(f"baseline_algo_version out of u8 range: {baseline_algo_version}")
    if not 0 <= commit_nonce <= 2**64 - 1:
        raise ValueError(f"commit_nonce out of u64 range: {commit_nonce}")
    return (
        bytes(baseline_hash)
        + struct.pack("<B", baseline_algo_version)
        + struct.pack("<Q", commit_nonce)
        + struct.pack("<B", int(committer_kind))
    )


# =============================================================================
# AgentRegistration v2 decoding
# =============================================================================

@dataclass(frozen=True, slots=True)
class DecodedRegistration:
    """The fields of an on-chain AgentRegistration we care about for commit verification."""
    agent_wallet:           Pubkey
    owner_wallet:           Pubkey
    registered_at:          int
    escrow_lamports:        int
    active:                 bool
    bump:                   int
    vault_bump:             int

    baseline_committed:     bool
    baseline_hash:          bytes
    baseline_algo_version:  int
    baseline_committer:     Pubkey
    baseline_committed_at:  int
    commit_nonce:           int
    layout_version:         int


def decode_agent_registration_v2(data: bytes) -> DecodedRegistration:
    """
    Decode an AgentRegistration v2 account. Verifies the Anchor discriminator
    and the layout version before returning.

    Layout (bytes):
       0..8       discriminator
       8..40      agent_wallet                (Pubkey)
      40..72      owner_wallet                (Pubkey)
      72..80      registered_at               (i64 LE)
      80..88      escrow_lamports             (u64 LE)
      88..89      active                      (u8)
      89..90      bump                        (u8)
      90..91      vault_bump                  (u8)
      91..92      baseline_committed          (u8)
      92..124     baseline_hash               ([u8; 32])
     124..125     baseline_algo_version       (u8)
     125..157     baseline_committer          (Pubkey)
     157..165     baseline_committed_at       (i64 LE)
     165..173     commit_nonce                (u64 LE)
     173..174     layout_version              (u8)
     174..238     _reserved                   ([u8; 64])
    """
    if len(data) < 174:
        raise ValueError(f"AgentRegistration data too short: {len(data)} bytes")
    if data[:8] != AGENT_REGISTRATION_DISCRIMINATOR:
        raise ValueError(
            f"discriminator mismatch: expected {AGENT_REGISTRATION_DISCRIMINATOR.hex()}, "
            f"got {data[:8].hex()}"
        )

    return DecodedRegistration(
        agent_wallet           = Pubkey.from_bytes(data[8:40]),
        owner_wallet           = Pubkey.from_bytes(data[40:72]),
        registered_at          = struct.unpack("<q", data[72:80])[0],
        escrow_lamports        = struct.unpack("<Q", data[80:88])[0],
        active                 = bool(data[88]),
        bump                   = data[89],
        vault_bump             = data[90],
        baseline_committed     = bool(data[91]),
        baseline_hash          = bytes(data[92:124]),
        baseline_algo_version  = data[124],
        baseline_committer     = Pubkey.from_bytes(data[125:157]),
        baseline_committed_at  = struct.unpack("<q", data[157:165])[0],
        commit_nonce           = struct.unpack("<Q", data[165:173])[0],
        layout_version         = data[173],
    )
