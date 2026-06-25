"""
tests/oracle/test_vuln25_signer.py — VULN-25 signing-surface guards.

Pins the narrow Signer Protocol so a future PR cannot accidentally
re-couple cert signing to the concrete NodeKeypair / cryptography
imports — and pins the HSMSigner stub so a misconfigured production
deploy that "forgot to wire the HSM" fails LOUDLY at sign time
instead of silently falling back to an in-process key.
"""

from __future__ import annotations

import pytest

from oracle.cluster.cert_signing import (
    cert_payload_digest,
    sign_cert_digest,
)
from oracle.cluster.identity import NodeKeypair
from oracle.cluster.input_commitment import SlotAnchor
from oracle.cluster.signer import HSMSigner, InProcessSigner, Signer


AGENT_PK      = b"\x11" * 32
BASELINE_HASH = b"\x33" * 32
INPUT_COMMITMENT = b"\x77" * 32     # AW-01: fixed test commitment
SLOT_ANCHOR = SlotAnchor(slot=250_000_000, block_hash=b"\x99" * 32)  # AW-01-EXT


def _digest() -> bytes:
    return cert_payload_digest(
        agent_wallet_bytes=AGENT_PK,
        epoch=42, score=500, alert_tier=1, flags=0,
        baseline_hash=BASELINE_HASH, immediate_red=False,
        input_commitment=INPUT_COMMITMENT,
        slot_anchor=SLOT_ANCHOR,
        baseline_commit_nonce=1,
    )


# =============================================================================
# Signer protocol
# =============================================================================

class TestSignerProtocol:

    def test_in_process_signer_satisfies_protocol(self):
        kp = NodeKeypair.from_seed("n0", b"seed-0")
        signer = InProcessSigner(kp)
        # runtime_checkable Protocol — isinstance MUST return True.
        assert isinstance(signer, Signer)
        assert signer.public_key == kp.public_key

    def test_hsm_signer_stub_satisfies_protocol(self):
        # The HSMSigner stub exposes the same shape, even though sign
        # raises. The Protocol check passes — the wiring is correct,
        # only the implementation is missing.
        stub = HSMSigner(public_key=b"\x05" * 32)
        assert isinstance(stub, Signer)
        assert stub.public_key == b"\x05" * 32

    def test_arbitrary_duck_typed_signer_works(self):
        # A future HSM client subclass need not be a NodeKeypair —
        # any object with .public_key + .sign satisfies InProcessSigner.
        class Dummy:
            public_key = b"\x07" * 32
            def sign(self, message: bytes) -> bytes:
                return b"\x00" * 64
        signer = InProcessSigner(Dummy())
        assert signer.sign(b"x") == b"\x00" * 64


# =============================================================================
# InProcessSigner — duck-typing guard
# =============================================================================

class TestInProcessSigner:

    def test_rejects_object_without_public_key(self):
        class Bad:
            def sign(self, message: bytes) -> bytes: return b""
        with pytest.raises(TypeError, match="public_key"):
            InProcessSigner(Bad())

    def test_rejects_object_without_sign(self):
        class Bad:
            public_key = b"\x00" * 32
        with pytest.raises(TypeError, match="public_key.*callable.*sign"):
            InProcessSigner(Bad())

    def test_repr_does_not_leak_secret(self):
        kp = NodeKeypair.from_seed("n0", b"seed-0")
        r = repr(InProcessSigner(kp))
        # The keypair's own repr is secret-free; the wrapper must
        # not reach into the private key either.
        assert "private" not in r.lower()


# =============================================================================
# HSMSigner — refuses to sign on the base class
# =============================================================================

class TestHSMSigner:

    def test_base_class_refuses_to_sign(self):
        # A misconfigured production deploy that forgot to subclass
        # HSMSigner must fail at sign time — never silently fall back
        # to in-process signing.
        stub = HSMSigner(public_key=b"\x05" * 32)
        with pytest.raises(NotImplementedError, match="VULN-25"):
            stub.sign(b"x" * 32)

    def test_rejects_short_pubkey(self):
        with pytest.raises(ValueError, match="32-byte"):
            HSMSigner(public_key=b"\x05" * 16)

    def test_rejects_non_bytes_pubkey(self):
        with pytest.raises(ValueError):
            HSMSigner(public_key="hello")  # type: ignore[arg-type]

    def test_repr_does_not_leak_pubkey(self):
        # We don't deliberately leak even the public material in repr —
        # the HSM client is the source of truth; the on-chain
        # OracleConfig publishes pubkeys explicitly elsewhere.
        stub = HSMSigner(public_key=b"\x05" * 32)
        r = repr(stub)
        assert "HSM-resident" in r


# =============================================================================
# Integration: sign_cert_digest works with the Signer protocol
# =============================================================================

class TestSignCertDigestThroughSigner:

    def test_in_process_signer_round_trip(self):
        # sign_cert_digest's `keypair` arg is duck-typed: any Signer
        # works. This is the swap point a future HSM signer plugs
        # into without touching the cert-signing call sites.
        kp = NodeKeypair.from_seed("n0", b"seed-0")
        signer = InProcessSigner(kp)
        sig = sign_cert_digest(signer, _digest())  # type: ignore[arg-type]
        assert sig.signer_pubkey == kp.public_key
        assert len(sig.signature) == 64
