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
        # The encoder pins `sha256(payload) == baseline_hash`, so the
        # default kwargs ship a real payload + its real hash. Per-test
        # overrides may swap either side.
        default_payload = b"baseline-test-payload"
        default_hash    = hashlib.sha256(default_payload).digest()
        kw = dict(
            baseline_hash=default_hash,
            baseline_algo_version=2,
            commit_nonce=1,
            committer_kind=CommitterKind.ORACLE,
            payload=default_payload,
        )
        kw.update(overrides)
        return kw

    def test_total_length(self):
        data = encode_commit_baseline_args(**self._kwargs())
        # 32 hash + 1 algo + 8 nonce + 1 committer_kind + 4 vec_len + N payload
        expected = 32 + 1 + 8 + 1 + 4 + len(b"baseline-test-payload")
        assert len(data) == expected

    def test_field_layout(self):
        payload = b"a-canonical-stats-payload"
        h = hashlib.sha256(payload).digest()
        data = encode_commit_baseline_args(**self._kwargs(
            baseline_hash=h,
            baseline_algo_version=2,
            commit_nonce=42,
            committer_kind=CommitterKind.ORACLE,
            payload=payload,
        ))
        assert data[0:32] == h
        assert data[32] == 2
        assert struct.unpack("<Q", data[33:41])[0] == 42
        assert data[41] == 0  # ORACLE = 0
        # AW-03: borsh Vec<u8> = u32 LE length prefix + bytes
        assert struct.unpack("<I", data[42:46])[0] == len(payload)
        assert data[46:46 + len(payload)] == payload

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

    # ── AW-03 payload-binding tests ─────────────────────────────────────────

    def test_empty_payload_rejected(self):
        with pytest.raises(ValueError, match="empty"):
            encode_commit_baseline_args(**self._kwargs(
                payload=b"",
                baseline_hash=hashlib.sha256(b"").digest(),
            ))

    def test_oversize_payload_rejected(self):
        # 8 KB + 1 byte
        big = b"\xff" * (8 * 1024 + 1)
        with pytest.raises(ValueError, match="too large"):
            encode_commit_baseline_args(**self._kwargs(
                payload=big,
                baseline_hash=hashlib.sha256(big).digest(),
            ))

    def test_payload_hash_mismatch_rejected(self):
        # AW-03: the off-chain encoder pins `sha256(payload) == baseline_hash`
        # so a forged hash + a real payload fails BEFORE the tx is sent.
        with pytest.raises(ValueError, match="does not match sha256"):
            encode_commit_baseline_args(**self._kwargs(
                payload=b"genuine-payload",
                baseline_hash=b"\x99" * 32,
            ))


# =============================================================================
# decode_agent_registration_v2
# =============================================================================

def _make_account_bytes(
    *,
    agent_wallet=b"\xa1" * 32,
    owner_wallet=b"\xb2" * 32,
    registered_at=1714566000,
    active=True,
    bump=254,
    baseline_committed=True,
    baseline_hash=b"\xcd" * 32,
    baseline_algo_version=2,
    baseline_committer=b"\xee" * 32,
    baseline_committed_at=1714607200,
    commit_nonce=7,
    layout_version=2,
    baseline_data_pointer=b"\xdd" * 32,
) -> bytes:
    """Hand-roll the exact byte layout the Rust account would produce."""
    out  = AGENT_REGISTRATION_DISCRIMINATOR
    out += agent_wallet
    out += owner_wallet
    out += struct.pack("<q", registered_at)
    out += bytes([1 if active else 0])
    out += bytes([bump])
    out += bytes([1 if baseline_committed else 0])
    out += baseline_hash
    out += bytes([baseline_algo_version])
    out += baseline_committer
    out += struct.pack("<q", baseline_committed_at)
    out += struct.pack("<Q", commit_nonce)
    out += bytes([layout_version])
    out += baseline_data_pointer   # AW-03 (32 bytes, carved from reserve)
    out += b"\x00" * 32             # remaining _reserved (was 64 pre-AW-03)
    return out


class TestDecodeAgentRegistrationV2:

    def test_round_trip_all_fields(self):
        raw = _make_account_bytes(
            agent_wallet=b"\xa1" * 32,
            owner_wallet=b"\xb2" * 32,
            registered_at=1714566000,
            active=True,
            bump=254,
            baseline_committed=True,
            baseline_hash=b"\xcd" * 32,
            baseline_algo_version=2,
            baseline_committer=b"\xee" * 32,
            baseline_committed_at=1714607200,
            commit_nonce=7,
            layout_version=2,
            baseline_data_pointer=b"\xdd" * 32,
        )
        d = decode_agent_registration_v2(raw)
        assert bytes(d.agent_wallet) == b"\xa1" * 32
        assert bytes(d.owner_wallet) == b"\xb2" * 32
        assert d.registered_at == 1714566000
        assert d.active is True
        assert d.bump == 254
        assert d.baseline_committed is True
        assert d.baseline_hash == b"\xcd" * 32
        assert d.baseline_algo_version == 2
        assert bytes(d.baseline_committer) == b"\xee" * 32
        assert d.baseline_committed_at == 1714607200
        assert d.commit_nonce == 7
        assert d.layout_version == 2
        assert bytes(d.baseline_data_pointer) == b"\xdd" * 32

    def test_pre_commit_state_decodes_with_zeros(self):
        raw = _make_account_bytes(
            baseline_committed=False,
            baseline_hash=b"\x00" * 32,
            baseline_algo_version=0,
            baseline_committer=b"\x00" * 32,
            baseline_committed_at=0,
            commit_nonce=0,
            baseline_data_pointer=b"\x00" * 32,
        )
        d = decode_agent_registration_v2(raw)
        assert d.baseline_committed is False
        assert d.baseline_hash == b"\x00" * 32
        assert d.commit_nonce == 0
        # AW-03: pre-AW-03 legacy registrations decode the pointer as zero
        # — the sentinel meaning "no DA account exists".
        assert bytes(d.baseline_data_pointer) == b"\x00" * 32

    def test_discriminator_mismatch_rejected(self):
        raw = _make_account_bytes()
        broken = b"\xff" * 8 + raw[8:]
        with pytest.raises(ValueError, match="discriminator mismatch"):
            decode_agent_registration_v2(broken)

    def test_truncated_data_rejected(self):
        raw = _make_account_bytes()
        with pytest.raises(ValueError, match="too short"):
            decode_agent_registration_v2(raw[:100])
