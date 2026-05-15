"""
tests/oracle/test_serialization.py — wire-format unit tests.

These don't need a validator. They verify the bytes we hand to the program
match Anchor's expectations, and the bytes we read back parse correctly.
"""

from __future__ import annotations

import hashlib
import struct

import pytest
from solders.pubkey import Pubkey

from oracle.serialization import (
    AGENT_REGISTRATION_DISCRIMINATOR,
    COMMIT_BASELINE_DISCRIMINATOR,
    MIGRATE_REGISTRATION_DISCRIMINATOR,
    CommitterKind,
    decode_agent_registration_v2,
    encode_commit_baseline_args,
)


# =============================================================================
# Discriminators — Anchor convention checks
# =============================================================================

class TestDiscriminators:

    def test_commit_baseline_discriminator(self):
        expected = hashlib.sha256(b"global:commit_baseline").digest()[:8]
        assert COMMIT_BASELINE_DISCRIMINATOR == expected
        assert len(COMMIT_BASELINE_DISCRIMINATOR) == 8

    def test_migrate_registration_discriminator(self):
        expected = hashlib.sha256(b"global:migrate_registration").digest()[:8]
        assert MIGRATE_REGISTRATION_DISCRIMINATOR == expected

    def test_agent_registration_account_discriminator(self):
        expected = hashlib.sha256(b"account:AgentRegistration").digest()[:8]
        assert AGENT_REGISTRATION_DISCRIMINATOR == expected

    def test_different_names_distinct_discriminators(self):
        assert COMMIT_BASELINE_DISCRIMINATOR != MIGRATE_REGISTRATION_DISCRIMINATOR
        assert COMMIT_BASELINE_DISCRIMINATOR != AGENT_REGISTRATION_DISCRIMINATOR


# =============================================================================
# encode_commit_baseline_args
# =============================================================================

class TestEncodeCommitBaselineArgs:

    def _kwargs(self, **overrides):
        kw = dict(
            baseline_hash=b"\xab" * 32,
            baseline_algo_version=2,
            commit_nonce=1,
            committer_kind=CommitterKind.ORACLE,
        )
        kw.update(overrides)
        return kw

    def test_total_length(self):
        data = encode_commit_baseline_args(**self._kwargs())
        # 32 hash + 1 algo_version + 8 nonce + 1 committer_kind = 42
        assert len(data) == 32 + 1 + 8 + 1

    def test_field_layout(self):
        data = encode_commit_baseline_args(**self._kwargs(
            baseline_hash=b"\x11" * 32,
            baseline_algo_version=2,
            commit_nonce=42,
            committer_kind=CommitterKind.ORACLE,
        ))
        assert data[0:32] == b"\x11" * 32
        assert data[32] == 2
        assert struct.unpack("<Q", data[33:41])[0] == 42
        assert data[41] == 0  # ORACLE = 0

    def test_committer_kind_owner_is_one(self):
        data = encode_commit_baseline_args(**self._kwargs(committer_kind=CommitterKind.OWNER))
        assert data[41] == 1

    def test_max_nonce(self):
        data = encode_commit_baseline_args(**self._kwargs(commit_nonce=2**64 - 1))
        assert struct.unpack("<Q", data[33:41])[0] == 2**64 - 1

    def test_bad_hash_length_rejected(self):
        with pytest.raises(ValueError, match="32 bytes"):
            encode_commit_baseline_args(**self._kwargs(baseline_hash=b"\xab" * 31))

    def test_algo_version_overflow_rejected(self):
        with pytest.raises(ValueError, match="u8 range"):
            encode_commit_baseline_args(**self._kwargs(baseline_algo_version=256))

    def test_negative_nonce_rejected(self):
        with pytest.raises(ValueError, match="u64 range"):
            encode_commit_baseline_args(**self._kwargs(commit_nonce=-1))


# =============================================================================
# decode_agent_registration_v2
# =============================================================================

def _make_account_bytes(
    *,
    agent_wallet=b"\xa1" * 32,
    owner_wallet=b"\xb2" * 32,
    registered_at=1714566000,
    escrow_lamports=10_000_000,
    active=True,
    bump=254,
    vault_bump=253,
    baseline_committed=True,
    baseline_hash=b"\xcd" * 32,
    baseline_algo_version=2,
    baseline_committer=b"\xee" * 32,
    baseline_committed_at=1714607200,
    commit_nonce=7,
    layout_version=2,
) -> bytes:
    """Hand-roll the exact byte layout the Rust account would produce."""
    out  = AGENT_REGISTRATION_DISCRIMINATOR
    out += agent_wallet
    out += owner_wallet
    out += struct.pack("<q", registered_at)
    out += struct.pack("<Q", escrow_lamports)
    out += bytes([1 if active else 0])
    out += bytes([bump])
    out += bytes([vault_bump])
    out += bytes([1 if baseline_committed else 0])
    out += baseline_hash
    out += bytes([baseline_algo_version])
    out += baseline_committer
    out += struct.pack("<q", baseline_committed_at)
    out += struct.pack("<Q", commit_nonce)
    out += bytes([layout_version])
    out += b"\x00" * 64   # _reserved
    return out


class TestDecodeAgentRegistrationV2:

    def test_round_trip_all_fields(self):
        raw = _make_account_bytes(
            agent_wallet=b"\xa1" * 32,
            owner_wallet=b"\xb2" * 32,
            registered_at=1714566000,
            escrow_lamports=10_000_000,
            active=True,
            bump=254,
            vault_bump=253,
            baseline_committed=True,
            baseline_hash=b"\xcd" * 32,
            baseline_algo_version=2,
            baseline_committer=b"\xee" * 32,
            baseline_committed_at=1714607200,
            commit_nonce=7,
            layout_version=2,
        )
        d = decode_agent_registration_v2(raw)
        assert bytes(d.agent_wallet) == b"\xa1" * 32
        assert bytes(d.owner_wallet) == b"\xb2" * 32
        assert d.registered_at == 1714566000
        assert d.escrow_lamports == 10_000_000
        assert d.active is True
        assert d.bump == 254
        assert d.vault_bump == 253
        assert d.baseline_committed is True
        assert d.baseline_hash == b"\xcd" * 32
        assert d.baseline_algo_version == 2
        assert bytes(d.baseline_committer) == b"\xee" * 32
        assert d.baseline_committed_at == 1714607200
        assert d.commit_nonce == 7
        assert d.layout_version == 2

    def test_pre_commit_state_decodes_with_zeros(self):
        raw = _make_account_bytes(
            baseline_committed=False,
            baseline_hash=b"\x00" * 32,
            baseline_algo_version=0,
            baseline_committer=b"\x00" * 32,
            baseline_committed_at=0,
            commit_nonce=0,
        )
        d = decode_agent_registration_v2(raw)
        assert d.baseline_committed is False
        assert d.baseline_hash == b"\x00" * 32
        assert d.commit_nonce == 0

    def test_discriminator_mismatch_rejected(self):
        raw = _make_account_bytes()
        broken = b"\xff" * 8 + raw[8:]
        with pytest.raises(ValueError, match="discriminator mismatch"):
            decode_agent_registration_v2(broken)

    def test_truncated_data_rejected(self):
        raw = _make_account_bytes()
        with pytest.raises(ValueError, match="too short"):
            decode_agent_registration_v2(raw[:100])
