"""
tests/test_vuln11_geyser_auth.py — VULN-11 mitigation invariants.

THE AUDIT FINDING
-----------------
VULN-11 (HIGH) — Geyser / Yellowstone stream has no message
authentication. A network-adjacent attacker (MITM, compromised endpoint,
supply-chain'd plugin binary) can inject synthetic transactions; the
indexer trusts the stream, writes them to TimescaleDB, the scoring
engine grades a fraudulent agent as perfect, a GREEN certificate
issues, a DeFi protocol lends to the attacker.

WHAT THIS FILE PINS
-------------------
The four layered mitigations the audit calls for:

  1. EVERY Geyser update wrapped in a `SignedGeyserUpdate` carrying
     sha256(slot_hash || canonical_payload) and an Ed25519 signature
     by the source. Tampering with any payload field, the slot hash,
     the commitment, the signature, or the source pubkey is rejected.

  2. A sampling cross-verifier hits an INDEPENDENT RPC and rejects
     updates whose stream-reported (slot, success) disagree with the
     RPC's record — or where the RPC has no record at all.

  3. A K-of-N consensus stream emits a transaction only after at least
     `min_agreements` distinct trusted sources have reported byte-
     identical canonical payloads. Endpoints disagreeing on the same
     signature surface as `ConflictReport`s.

  4. A `PluginPinManifest` binds (plugin version, binary sha256) with
     a release-engineer Ed25519 signature. The runtime verifier
     refuses to bring up the indexer against a binary whose hash isn't
     in the manifest, signed by a trusted release signer.

Each test class targets one trust surface. Failure of any of these is
the difference between "audit-clean" and "feature poisoning lands on
chain".
"""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Iterator
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from eventbus.signing import Ed25519PayloadSigner
from indexer import (
    ConflictReport,
    ConsensusStream,
    CrossVerificationFailed,
    GeyserAccountChange,
    GeyserAuthError,
    GeyserTransactionUpdate,
    PluginPin,
    PluginPinError,
    PluginPinManifest,
    RpcSignatureStatus,
    RpcSignatureVerifier,
    SamplingCrossVerifier,
    SignedGeyserUpdate,
    TrustedGeyserSource,
    TrustedGeyserSourceSet,
    TrustedReleaseSigner,
    TrustedReleaseSignerSet,
    UntrustedReleaseSigner,
    UntrustedSource,
    VerifyingStreamSource,
    canonical_update_bytes,
    commitment,
    compute_binary_sha256,
    cross_check,
    manifest_from_json,
    manifest_to_json,
    sign_update,
    verify_plugin_binary,
    verify_signed_update,
)


CONF = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
PROG = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
AGENT_A = "agentA".ljust(44, "x")
AGENT_B = "agentB".ljust(44, "x")
SLOT_HASH_ALPHA = b"\x01" * 32
SLOT_HASH_BETA  = b"\x02" * 32


# =============================================================================
# Factories
# =============================================================================

def _update(i: int, *, agent: str = AGENT_A,
            success: bool = True, slot: int | None = None,
            fee: int = 5000) -> GeyserTransactionUpdate:
    return GeyserTransactionUpdate(
        signature=f"sig{i:08d}".ljust(64, "x"),
        slot=slot if slot is not None else 300_000_000 + i,
        block_time=CONF,
        is_successful=success,
        fee_lamports=fee,
        compute_units=200_000,
        account_keys=(agent, "cp".ljust(44, "x"), PROG),
        account_changes=(
            GeyserAccountChange(agent, 1_000_000_000, 1_000_000_000 - 500_000),
        ),
        instr_program_ids=(PROG,),
    )


def _source_signer(seed: int) -> Ed25519PayloadSigner:
    """Deterministic source signer for tests."""
    return Ed25519PayloadSigner.from_seed(bytes([seed] * 32))


# =============================================================================
# Canonical bytes — determinism + sensitivity
# =============================================================================

class TestCanonicalBytes:

    def test_deterministic_across_calls(self):
        u = _update(1)
        assert canonical_update_bytes(u) == canonical_update_bytes(u)

    def test_changes_when_signature_changes(self):
        a = _update(1)
        b = replace(a, signature="forged".ljust(64, "x"))
        assert canonical_update_bytes(a) != canonical_update_bytes(b)

    def test_changes_when_success_flag_flips(self):
        a = _update(1, success=True)
        b = _update(1, success=False)
        assert canonical_update_bytes(a) != canonical_update_bytes(b)

    def test_changes_when_account_key_reordered(self):
        a = _update(1)
        b = replace(a, account_keys=tuple(reversed(a.account_keys)))
        # Order matters — Solana's account_keys carries the program-id
        # index by position, so a reorder is a different transaction.
        assert canonical_update_bytes(a) != canonical_update_bytes(b)

    def test_changes_when_balance_changes(self):
        a = _update(1)
        new_change = GeyserAccountChange(AGENT_A, 1_000_000_000, 999_999_999)
        b = replace(a, account_changes=(new_change,))
        assert canonical_update_bytes(a) != canonical_update_bytes(b)

    def test_block_time_does_not_affect_canonical_bytes(self):
        """Observation timestamps are not on-chain truth — must not bind."""
        a = _update(1)
        from datetime import timedelta
        b = replace(a, block_time=CONF + timedelta(seconds=3600))
        assert canonical_update_bytes(a) == canonical_update_bytes(b)


# =============================================================================
# Commitment — the audit formula
# =============================================================================

class TestCommitmentMath:

    def test_is_sha256_of_slot_hash_concat_payload(self):
        u = _update(1)
        payload = canonical_update_bytes(u)
        expected = hashlib.sha256(SLOT_HASH_ALPHA + payload).digest()
        assert commitment(SLOT_HASH_ALPHA, payload) == expected

    def test_commitment_is_32_bytes(self):
        u = _update(1)
        digest = commitment(SLOT_HASH_ALPHA, canonical_update_bytes(u))
        assert len(digest) == 32

    def test_short_slot_hash_rejected(self):
        u = _update(1)
        with pytest.raises(GeyserAuthError):
            commitment(b"\x01" * 16, canonical_update_bytes(u))

    def test_long_slot_hash_rejected(self):
        u = _update(1)
        with pytest.raises(GeyserAuthError):
            commitment(b"\x01" * 48, canonical_update_bytes(u))

    def test_different_slot_hash_yields_different_commitment(self):
        u = _update(1)
        payload = canonical_update_bytes(u)
        assert commitment(SLOT_HASH_ALPHA, payload) != \
               commitment(SLOT_HASH_BETA, payload)


# =============================================================================
# Signed-update round trip + tamper rejection
# =============================================================================

class TestSignedRoundTrip:

    def test_verifies_on_clean_round_trip(self):
        signer = _source_signer(7)
        trusted = TrustedGeyserSourceSet([
            TrustedGeyserSource("test-helius-1", signer.public_key),
        ])
        signed = sign_update(_update(1), SLOT_HASH_ALPHA, signer)
        verify_signed_update(signed, trusted)  # must not raise

    def test_unknown_source_rejected(self):
        signer = _source_signer(7)
        attacker = _source_signer(99)
        trusted = TrustedGeyserSourceSet([
            TrustedGeyserSource("test-helius-1", signer.public_key),
        ])
        signed = sign_update(_update(1), SLOT_HASH_ALPHA, attacker)
        with pytest.raises(UntrustedSource):
            verify_signed_update(signed, trusted)


class TestTamperRejection:

    @pytest.fixture
    def trusted_pair(self):
        signer = _source_signer(7)
        trusted = TrustedGeyserSourceSet([
            TrustedGeyserSource("test-helius-1", signer.public_key),
        ])
        return signer, trusted

    def test_payload_mutation_rejected(self, trusted_pair):
        signer, trusted = trusted_pair
        signed = sign_update(_update(1), SLOT_HASH_ALPHA, signer)
        tampered = replace(
            signed, update=replace(signed.update, is_successful=False),
        )
        with pytest.raises(GeyserAuthError):
            verify_signed_update(tampered, trusted)

    def test_slot_hash_mutation_rejected(self, trusted_pair):
        signer, trusted = trusted_pair
        signed = sign_update(_update(1), SLOT_HASH_ALPHA, signer)
        tampered = replace(signed, slot_hash=SLOT_HASH_BETA)
        with pytest.raises(GeyserAuthError):
            verify_signed_update(tampered, trusted)

    def test_commitment_mutation_rejected(self, trusted_pair):
        signer, trusted = trusted_pair
        signed = sign_update(_update(1), SLOT_HASH_ALPHA, signer)
        tampered = replace(signed, commitment_hash=b"\xff" * 32)
        with pytest.raises(GeyserAuthError):
            verify_signed_update(tampered, trusted)

    def test_signature_mutation_rejected(self, trusted_pair):
        signer, trusted = trusted_pair
        signed = sign_update(_update(1), SLOT_HASH_ALPHA, signer)
        tampered = replace(signed, signature=b"\xff" * 64)
        with pytest.raises(GeyserAuthError):
            verify_signed_update(tampered, trusted)

    def test_pubkey_swap_to_another_trusted_source_rejected(self, trusted_pair):
        """A signature by source A relabeled as source B must not verify."""
        signer_a, _ = trusted_pair
        signer_b = _source_signer(11)
        trusted = TrustedGeyserSourceSet([
            TrustedGeyserSource("helius-1", signer_a.public_key),
            TrustedGeyserSource("helius-2", signer_b.public_key),
        ])
        signed = sign_update(_update(1), SLOT_HASH_ALPHA, signer_a)
        # Relabel as B (still trusted, so it passes the trust check;
        # signature verification must catch it).
        tampered = replace(signed, source_pubkey=signer_b.public_key)
        with pytest.raises(GeyserAuthError):
            verify_signed_update(tampered, trusted)


# =============================================================================
# TrustedGeyserSourceSet — construction invariants
# =============================================================================

class TestTrustedSourceSet:

    def test_empty_set_rejected(self):
        with pytest.raises(ValueError):
            TrustedGeyserSourceSet([])

    def test_duplicate_pubkey_rejected(self):
        signer = _source_signer(7)
        with pytest.raises(ValueError):
            TrustedGeyserSourceSet([
                TrustedGeyserSource("a", signer.public_key),
                TrustedGeyserSource("b", signer.public_key),
            ])

    def test_short_pubkey_rejected(self):
        with pytest.raises(ValueError):
            TrustedGeyserSource("a", b"\x00" * 16)

    def test_name_must_be_non_empty(self):
        signer = _source_signer(7)
        with pytest.raises(ValueError):
            TrustedGeyserSource("", signer.public_key)


# =============================================================================
# VerifyingStreamSource — runner integration
# =============================================================================

class _ListSignedSource:
    def __init__(self, signed: list[SignedGeyserUpdate]) -> None:
        self._signed = signed

    def signed_updates(self) -> Iterator[SignedGeyserUpdate]:
        yield from self._signed


class TestVerifyingStreamSource:

    def test_passes_clean_updates_through(self):
        signer = _source_signer(7)
        trusted = TrustedGeyserSourceSet([
            TrustedGeyserSource("h1", signer.public_key),
        ])
        signed = [sign_update(_update(i), SLOT_HASH_ALPHA, signer)
                  for i in range(3)]
        wrapped = VerifyingStreamSource(_ListSignedSource(signed), trusted)
        out = list(wrapped.updates())
        assert len(out) == 3
        assert wrapped.accepted_count == 3
        assert wrapped.rejected_count == 0

    def test_silently_drops_forgery_and_counts_it(self):
        signer = _source_signer(7)
        attacker = _source_signer(99)
        trusted = TrustedGeyserSourceSet([
            TrustedGeyserSource("h1", signer.public_key),
        ])
        good = sign_update(_update(1), SLOT_HASH_ALPHA, signer)
        bad = sign_update(_update(2), SLOT_HASH_ALPHA, attacker)
        wrapped = VerifyingStreamSource(
            _ListSignedSource([good, bad, good]), trusted,
        )
        out = list(wrapped.updates())
        assert len(out) == 2                          # bad silently dropped
        assert wrapped.accepted_count == 2
        assert wrapped.rejected_count == 1
        assert wrapped.last_error is not None         # surfaced for alerter


# =============================================================================
# RPC cross-verify — fake verifier under the protocol
# =============================================================================

@dataclass
class _FakeRpc:
    """A test double for `RpcSignatureVerifier`."""
    by_sig: dict[str, RpcSignatureStatus]
    call_count: int = 0

    def fetch_status(self, signature: str) -> RpcSignatureStatus | None:
        self.call_count += 1
        return self.by_sig.get(signature)


class TestCrossCheck:

    def test_agreement_passes(self):
        u = _update(1)
        rpc = _FakeRpc({u.signature: RpcSignatureStatus(u.slot, u.is_successful)})
        cross_check(u, rpc)                          # must not raise

    def test_slot_mismatch_rejected(self):
        u = _update(1)
        rpc = _FakeRpc({u.signature: RpcSignatureStatus(u.slot + 1, u.is_successful)})
        with pytest.raises(CrossVerificationFailed):
            cross_check(u, rpc)

    def test_success_mismatch_rejected(self):
        """Stream says SUCCESS, RPC says FAIL — the forge signature."""
        u = _update(1, success=True)
        rpc = _FakeRpc({u.signature: RpcSignatureStatus(u.slot, False)})
        with pytest.raises(CrossVerificationFailed):
            cross_check(u, rpc)

    def test_unknown_signature_rejected(self):
        """RPC has no record — most likely an injected synthetic tx."""
        u = _update(1)
        rpc = _FakeRpc({})
        with pytest.raises(CrossVerificationFailed):
            cross_check(u, rpc)


class TestSamplingCrossVerifier:

    def test_sample_rate_zero_never_calls_rpc(self):
        updates = [_update(i) for i in range(20)]
        rpc = _FakeRpc({})
        sampler = SamplingCrossVerifier(
            iter(updates), rpc, sample_rate=0.0, rng=random.Random(42),
        )
        out = list(sampler.updates())
        assert len(out) == 20
        assert rpc.call_count == 0
        assert sampler.sampled_count == 0

    def test_sample_rate_one_calls_every_update(self):
        updates = [_update(i) for i in range(10)]
        rpc = _FakeRpc({
            u.signature: RpcSignatureStatus(u.slot, u.is_successful)
            for u in updates
        })
        sampler = SamplingCrossVerifier(
            iter(updates), rpc, sample_rate=1.0, rng=random.Random(42),
        )
        out = list(sampler.updates())
        assert len(out) == 10
        assert rpc.call_count == 10
        assert sampler.passed_count == 10
        assert sampler.rejected_count == 0

    def test_sampled_forgery_dropped_and_counted(self):
        updates = [_update(i) for i in range(5)]
        # RPC has no record of any of them — every sampled update fails.
        rpc = _FakeRpc({})
        sampler = SamplingCrossVerifier(
            iter(updates), rpc, sample_rate=1.0, rng=random.Random(42),
        )
        out = list(sampler.updates())
        assert out == []                              # all dropped
        assert sampler.rejected_count == 5
        assert sampler.last_error is not None

    def test_deterministic_with_seeded_rng(self):
        """Two samplers with the same seed sample the same updates."""
        updates_a = [_update(i) for i in range(50)]
        updates_b = [_update(i) for i in range(50)]
        rpc_a = _FakeRpc({u.signature: RpcSignatureStatus(u.slot, u.is_successful)
                          for u in updates_a})
        rpc_b = _FakeRpc({u.signature: RpcSignatureStatus(u.slot, u.is_successful)
                          for u in updates_b})
        sa = SamplingCrossVerifier(iter(updates_a), rpc_a, 0.3, random.Random(123))
        sb = SamplingCrossVerifier(iter(updates_b), rpc_b, 0.3, random.Random(123))
        list(sa.updates())
        list(sb.updates())
        assert sa.sampled_count == sb.sampled_count
        assert sa.passed_count == sb.passed_count

    def test_invalid_sample_rate_rejected(self):
        with pytest.raises(ValueError):
            SamplingCrossVerifier(iter([]), _FakeRpc({}), sample_rate=1.5)
        with pytest.raises(ValueError):
            SamplingCrossVerifier(iter([]), _FakeRpc({}), sample_rate=-0.1)


# =============================================================================
# Multi-endpoint consensus
# =============================================================================

class TestConsensusStream:

    @pytest.fixture
    def three_sources(self):
        s1 = _source_signer(1)
        s2 = _source_signer(2)
        s3 = _source_signer(3)
        trusted = TrustedGeyserSourceSet([
            TrustedGeyserSource("h1", s1.public_key),
            TrustedGeyserSource("h2", s2.public_key),
            TrustedGeyserSource("h3", s3.public_key),
        ])
        return s1, s2, s3, trusted

    def test_two_of_three_quorum_emits(self, three_sources):
        s1, s2, _, trusted = three_sources
        c = ConsensusStream(trusted, min_agreements=2, total_sources=3)
        u = _update(1)
        a = sign_update(u, SLOT_HASH_ALPHA, s1)
        b = sign_update(u, SLOT_HASH_ALPHA, s2)
        out = list(c.feed([a, b]))
        assert len(out) == 1
        assert out[0].signature == u.signature
        assert c.emitted_count == 1
        assert c.in_flight_count == 0

    def test_one_of_three_does_not_emit(self, three_sources):
        s1, *_rest, trusted = three_sources
        c = ConsensusStream(trusted, min_agreements=2, total_sources=3)
        u = _update(1)
        out = list(c.feed([sign_update(u, SLOT_HASH_ALPHA, s1)]))
        assert out == []
        assert c.in_flight_count == 1                  # awaiting second confirm

    def test_conflicting_canonical_bytes_yield_no_emission(self, three_sources):
        """Same signature, contradictory bytes — the smoking gun."""
        s1, s2, _, trusted = three_sources
        c = ConsensusStream(trusted, min_agreements=2, total_sources=3)
        u_a = _update(1, success=True)
        u_b = replace(u_a, is_successful=False)        # same sig, different bytes
        a = sign_update(u_a, SLOT_HASH_ALPHA, s1)
        b = sign_update(u_b, SLOT_HASH_ALPHA, s2)
        out = list(c.feed([a, b]))
        assert out == []
        assert c.emitted_count == 0
        conflicts = c.drain_conflicts()
        assert len(conflicts) == 1
        assert conflicts[0].signature == u_a.signature
        assert s2.public_key == conflicts[0].dissenting_source

    def test_three_of_three_emits_once(self, three_sources):
        s1, s2, s3, trusted = three_sources
        c = ConsensusStream(trusted, min_agreements=2, total_sources=3)
        u = _update(1)
        a = sign_update(u, SLOT_HASH_ALPHA, s1)
        b = sign_update(u, SLOT_HASH_ALPHA, s2)
        d = sign_update(u, SLOT_HASH_ALPHA, s3)
        out = list(c.feed([a, b, d]))
        # Once quorum hit (a+b), entry evicted. The third report finds
        # no entry and starts a new partial — does NOT emit again.
        assert len(out) == 1

    def test_envelope_failures_rejected_before_quorum(self, three_sources):
        s1, s2, _, trusted = three_sources
        attacker = _source_signer(99)
        c = ConsensusStream(trusted, min_agreements=2, total_sources=3)
        u = _update(1)
        a = sign_update(u, SLOT_HASH_ALPHA, s1)
        fake = sign_update(u, SLOT_HASH_ALPHA, attacker)   # bad envelope
        out = list(c.feed([a, fake]))
        # Attacker rejected — only one trusted observation, no quorum.
        assert out == []
        assert c.envelope_rejected_count == 1
        # Real second confirmation still completes quorum.
        b = sign_update(u, SLOT_HASH_ALPHA, s2)
        out2 = list(c.feed([b]))
        assert len(out2) == 1

    def test_min_agreements_at_least_two(self, three_sources):
        _, _, _, trusted = three_sources
        with pytest.raises(ValueError):
            ConsensusStream(trusted, min_agreements=1, total_sources=3)

    def test_min_agreements_cannot_exceed_total(self, three_sources):
        _, _, _, trusted = three_sources
        with pytest.raises(ValueError):
            ConsensusStream(trusted, min_agreements=4, total_sources=3)

    def test_window_eviction_drops_old_partial(self, three_sources):
        s1, *_rest, trusted = three_sources
        c = ConsensusStream(
            trusted, min_agreements=2, total_sources=3, window_size=2,
        )
        # Three partials, only one source each: window=2 ⇒ first evicts.
        list(c.feed([
            sign_update(_update(1), SLOT_HASH_ALPHA, s1),
            sign_update(_update(2), SLOT_HASH_ALPHA, s1),
            sign_update(_update(3), SLOT_HASH_ALPHA, s1),
        ]))
        assert c.in_flight_count == 2
        assert c.dropped_no_quorum_count == 1


# =============================================================================
# Plugin pin manifest + verifier
# =============================================================================

def _make_pin(version: str, binary_sha: bytes,
              signer: Ed25519PayloadSigner) -> PluginPin:
    sig = signer.sign(binary_sha + version.encode("utf-8"))
    return PluginPin(
        version=version,
        binary_sha256=binary_sha,
        signer_pubkey=signer.public_key,
        signature=sig,
    )


class TestPluginPinVerifier:

    @pytest.fixture
    def setup(self, tmp_path: Path):
        binary = tmp_path / "yellowstone-grpc.so"
        binary.write_bytes(b"PLUGIN-BYTES-V1.2.3-RELEASE")
        sha = compute_binary_sha256(binary)
        signer = _source_signer(50)
        trusted = TrustedReleaseSignerSet([
            TrustedReleaseSigner("release-bot", signer.public_key),
        ])
        manifest = PluginPinManifest([_make_pin("1.2.3", sha, signer)])
        return binary, sha, signer, trusted, manifest

    def test_valid_pin_verifies(self, setup):
        binary, _, _, trusted, manifest = setup
        pin = verify_plugin_binary(binary, "1.2.3", manifest, trusted)
        assert pin.version == "1.2.3"

    def test_missing_pin_rejected(self, setup):
        binary, _, _, trusted, manifest = setup
        with pytest.raises(PluginPinError):
            verify_plugin_binary(binary, "9.9.9", manifest, trusted)

    def test_tampered_binary_rejected(self, setup, tmp_path: Path):
        _, _, _, trusted, manifest = setup
        tampered = tmp_path / "yellowstone-grpc-evil.so"
        tampered.write_bytes(b"MALICIOUS-PLUGIN-BYTES")
        with pytest.raises(PluginPinError, match="hash mismatch"):
            verify_plugin_binary(tampered, "1.2.3", manifest, trusted)

    def test_untrusted_signer_rejected(self, setup, tmp_path: Path):
        binary, sha, _, _, _ = setup
        rogue = _source_signer(77)
        rogue_trusted = TrustedReleaseSignerSet([
            TrustedReleaseSigner("real-bot", _source_signer(50).public_key),
        ])
        # The manifest carries a pin signed by the ROGUE engineer.
        rogue_manifest = PluginPinManifest([_make_pin("1.2.3", sha, rogue)])
        with pytest.raises(UntrustedReleaseSigner):
            verify_plugin_binary(binary, "1.2.3", rogue_manifest, rogue_trusted)

    def test_forged_signature_rejected(self, setup, tmp_path: Path):
        binary, sha, signer, trusted, _ = setup
        # Same signer pubkey, but signature replaced with zeroes.
        bad_pin = PluginPin(
            version="1.2.3",
            binary_sha256=sha,
            signer_pubkey=signer.public_key,
            signature=b"\x00" * 64,
        )
        bad_manifest = PluginPinManifest([bad_pin])
        with pytest.raises(PluginPinError):
            verify_plugin_binary(binary, "1.2.3", bad_manifest, trusted)

    def test_version_string_is_bound_to_signature(self, setup, tmp_path: Path):
        """A pin signed for v1.2.3 cannot be replayed as v1.2.4."""
        binary, sha, signer, trusted, _ = setup
        sig_for_123 = signer.sign(sha + b"1.2.3")
        # Build a pin claiming v1.2.4 but with the v1.2.3 signature.
        spoofed = PluginPin(
            version="1.2.4",
            binary_sha256=sha,
            signer_pubkey=signer.public_key,
            signature=sig_for_123,
        )
        spoofed_manifest = PluginPinManifest([spoofed])
        with pytest.raises(PluginPinError):
            verify_plugin_binary(binary, "1.2.4", spoofed_manifest, trusted)


class TestManifestJsonCodec:

    def test_round_trip(self):
        signer = _source_signer(7)
        sha = hashlib.sha256(b"some-binary").digest()
        manifest = PluginPinManifest([_make_pin("1.0.0", sha, signer)])
        text = manifest_to_json(manifest)
        # Valid JSON, sorted-key string (stable across platforms).
        parsed = json.loads(text)
        assert "pins" in parsed and len(parsed["pins"]) == 1
        # Round-trip back to PluginPinManifest.
        recovered = manifest_from_json(text)
        rec = recovered.get("1.0.0")
        assert rec is not None
        assert rec.binary_sha256 == sha
        assert rec.signer_pubkey == signer.public_key

    def test_malformed_json_rejected(self):
        with pytest.raises(ValueError):
            manifest_from_json('{"not_pins": []}')

    def test_short_hex_field_rejected(self):
        bad = json.dumps({"pins": [{
            "version":       "1.0.0",
            "binary_sha256": "00" * 16,                 # only 16 bytes
            "signer_pubkey": "00" * 32,
            "signature":     "00" * 64,
        }]})
        with pytest.raises(ValueError):
            manifest_from_json(bad)


# =============================================================================
# End-to-end: signed stream into the writer pipeline
# =============================================================================

class TestEndToEnd:
    """One scenario that wires Verifying + writer to show the gate fits."""

    def test_signed_stream_only_writes_verified_updates(self):
        from db import InMemoryTransactionRepo
        from indexer import GeyserIndexer, IngestionWriter, WalletFilter

        signer = _source_signer(7)
        attacker = _source_signer(99)
        trusted = TrustedGeyserSourceSet([
            TrustedGeyserSource("h1", signer.public_key),
        ])

        good = [sign_update(_update(i), SLOT_HASH_ALPHA, signer) for i in range(3)]
        forged = sign_update(_update(99), SLOT_HASH_ALPHA, attacker)
        wrapped = VerifyingStreamSource(
            _ListSignedSource(good + [forged]), trusted,
        )

        repo = InMemoryTransactionRepo()
        writer = IngestionWriter(WalletFilter([AGENT_A]), repo)
        report = GeyserIndexer(wrapped, writer).run()

        assert report.transactions_written == 3     # forge never reaches DB
        assert wrapped.rejected_count == 1
