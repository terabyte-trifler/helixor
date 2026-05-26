"""
tests/oracle/test_vuln21_ed25519_strictness.py — VULN-21 Ed25519 strictness.

Pins the three guarantees the audit asks for:

  1. **Canonical-S enforcement.** A signature whose S component is in
     [L, 2L) — the "S + L" malleability variant — is rejected before it
     is handed to the underlying verifier. This matches Solana's on-chain
     `Ed25519` precompile, which uses ed25519-dalek strict mode and
     rejects non-canonical S. A non-strict verifier would accept the
     S + L form for an otherwise-valid signature; an aggregator that
     accepted such a "valid" signature off-chain would build a
     transaction the on-chain precompile then refuses, manufacturing a
     liveness failure on demand.
  2. **One-by-one verification, never batched.** Threshold signatures
     for a certificate are verified individually. Batch verification
     can pass the batch equation while accepting an individual
     non-signature (known Ed25519 batch attack). The off-chain
     aggregator code does not call any batch-verify primitive; the
     on-chain precompile parses one (pubkey, message, signature)
     record per instruction. This test pins the static absence.
  3. **Library-symmetry pin.** The off-chain side uses the
     `cryptography` Ed25519 verifier (OpenSSL strict); the on-chain
     side uses Solana's ed25519 precompile (ed25519-dalek strict).
     Both reject the same set of non-canonical encodings — the test
     proves the off-chain side's behaviour by construction.

Together: the threshold-signature path on both sides of the wire agrees
on what "valid" means, and there is no future-PR surface to introduce
a batch shortcut.
"""

from __future__ import annotations

import pytest

from oracle.cluster.cert_signing import (
    ClusterSignature,
    InsufficientSignatures,
    aggregate_signatures,
    cert_payload_digest,
    is_canonical_signature_s,
    sign_cert_digest,
    _ED25519_GROUP_ORDER_L,
)
from oracle.cluster.identity import NodeKeypair
from oracle.cluster.input_commitment import SlotAnchor


AGENT_PK = b"\x11" * 32
BASELINE_HASH = b"\x33" * 32
INPUT_COMMITMENT = b"\x77" * 32     # AW-01: fixed test commitment
SLOT_ANCHOR = SlotAnchor(slot=250_000_000, block_hash=b"\x99" * 32)  # AW-01-EXT


def _digest() -> bytes:
    return cert_payload_digest(
        AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
        SLOT_ANCHOR,
    )


def _cluster(n: int = 5) -> list[NodeKeypair]:
    return [NodeKeypair.from_seed(f"node-{i}", f"seed{i}".encode())
            for i in range(n)]


def _keys_of(kps):
    return [kp.public_key for kp in kps]


def _make_signature_with_s(s_int: int, base_sig: bytes) -> bytes:
    """Return a 64-byte signature with R from `base_sig` and S = s_int."""
    if len(base_sig) != 64:
        raise ValueError("base_sig must be 64 bytes")
    new_s = s_int.to_bytes(32, "little")
    return base_sig[:32] + new_s


# =============================================================================
# Canonical-S predicate
# =============================================================================

class TestCanonicalSPredicate:

    def test_returns_false_for_wrong_length(self):
        assert is_canonical_signature_s(b"\x00" * 63) is False
        assert is_canonical_signature_s(b"\x00" * 65) is False
        assert is_canonical_signature_s(b"") is False

    def test_zero_s_is_canonical(self):
        # Boundary: S=0 is in [0, L), trivially canonical.
        sig = _make_signature_with_s(0, b"\x00" * 64)
        assert is_canonical_signature_s(sig) is True

    def test_s_just_below_L_is_canonical(self):
        sig = _make_signature_with_s(_ED25519_GROUP_ORDER_L - 1, b"\x00" * 64)
        assert is_canonical_signature_s(sig) is True

    def test_s_equal_to_L_is_non_canonical(self):
        # The first non-canonical value; strict-mode verifiers reject it.
        sig = _make_signature_with_s(_ED25519_GROUP_ORDER_L, b"\x00" * 64)
        assert is_canonical_signature_s(sig) is False

    def test_s_above_L_is_non_canonical(self):
        # The classic "S + L" malleability variant.
        sig = _make_signature_with_s(_ED25519_GROUP_ORDER_L + 7, b"\x00" * 64)
        assert is_canonical_signature_s(sig) is False

    def test_max_s_is_non_canonical(self):
        sig = _make_signature_with_s((1 << 256) - 1, b"\x00" * 64)
        assert is_canonical_signature_s(sig) is False


# =============================================================================
# Aggregator rejects non-canonical S signatures
# =============================================================================

class TestAggregatorRejectsNonCanonicalS:
    """A signature whose S is in [L, 2L) must NOT count toward the
    threshold, even though some Ed25519 verifiers would accept it. The
    on-chain Solana precompile rejects such signatures, so an aggregator
    that accepted them would manufacture deterministic liveness failures
    (`InsufficientSignatures` once the tx hits the chain)."""

    def test_malleable_signature_is_filtered_out(self):
        keys = _cluster()
        digest = _digest()

        # Two valid sigs from k0, k1, plus a third signature from k2 with
        # a non-canonical S value. The aggregator must count only 2.
        sig0 = sign_cert_digest(keys[0], digest)
        sig1 = sign_cert_digest(keys[1], digest)
        legit2 = sign_cert_digest(keys[2], digest)
        malleable2 = ClusterSignature(
            signer_pubkey=legit2.signer_pubkey,
            signature=_make_signature_with_s(
                _ED25519_GROUP_ORDER_L + 1, legit2.signature,
            ),
            digest=digest,
        )

        with pytest.raises(InsufficientSignatures) as exc:
            aggregate_signatures(
                digest, [sig0, sig1, malleable2],
                cluster_keys=_keys_of(keys), threshold=3,
            )

        assert exc.value.got == 2, (
            "the malleable S-value signature must not contribute to the count"
        )

    def test_only_canonical_signatures_reach_aggregated_set(self):
        keys = _cluster()
        digest = _digest()

        # 3 honest signatures; one is malleable; the aggregator picks the
        # 3 canonical ones to satisfy the threshold.
        good = [sign_cert_digest(k, digest) for k in keys[:3]]
        legit_extra = sign_cert_digest(keys[3], digest)
        malleable = ClusterSignature(
            signer_pubkey=legit_extra.signer_pubkey,
            signature=_make_signature_with_s(
                _ED25519_GROUP_ORDER_L + 5, legit_extra.signature,
            ),
            digest=digest,
        )

        agg = aggregate_signatures(
            digest, good + [malleable],
            cluster_keys=_keys_of(keys), threshold=3,
        )

        assert agg.count == 3
        for s in agg.signatures:
            assert is_canonical_signature_s(s.signature), (
                "every signature in the aggregated set must be canonical"
            )

    def test_zero_canonical_sigs_raises(self):
        # All signatures are malleable -> 0 valid signers.
        keys = _cluster()
        digest = _digest()
        malleable = []
        for k in keys[:3]:
            legit = sign_cert_digest(k, digest)
            malleable.append(ClusterSignature(
                signer_pubkey=legit.signer_pubkey,
                signature=_make_signature_with_s(
                    _ED25519_GROUP_ORDER_L + 1, legit.signature,
                ),
                digest=digest,
            ))

        with pytest.raises(InsufficientSignatures) as exc:
            aggregate_signatures(
                digest, malleable,
                cluster_keys=_keys_of(keys), threshold=3,
            )
        assert exc.value.got == 0


# =============================================================================
# No batch-verification primitive on the threshold path
# =============================================================================

class TestNoBatchVerification:
    """The audit's "never batch-verify threshold signatures" rule is a
    code-shape guarantee, not a runtime one. We enforce it statically by
    asserting that `cert_signing.py` contains no batch-verify calls."""

    FORBIDDEN_NAMES: tuple[str, ...] = (
        "verify_batch",
        "batch_verify",
        "verify_strict_batch",
        "verify_multi",
        "multi_verify",
    )

    def test_cert_signing_module_does_not_use_batch_verify(self):
        from pathlib import Path
        text = (
            Path(__file__).parent.parent.parent
            / "oracle" / "cluster" / "cert_signing.py"
        ).read_text()
        for name in self.FORBIDDEN_NAMES:
            assert name not in text, (
                f"cert_signing.py must not use {name!r}: threshold "
                "signatures MUST be verified individually (VULN-21)."
            )

    def test_identity_module_does_not_use_batch_verify(self):
        from pathlib import Path
        text = (
            Path(__file__).parent.parent.parent
            / "oracle" / "cluster" / "identity.py"
        ).read_text()
        for name in self.FORBIDDEN_NAMES:
            assert name not in text, (
                f"identity.py must not use {name!r}: signature "
                "verification MUST be one-at-a-time (VULN-21)."
            )


# =============================================================================
# Library-symmetry pin
# =============================================================================

class TestLibrarySymmetry:
    """Off-chain uses `cryptography` (OpenSSL strict Ed25519); on-chain
    uses Solana's precompile (ed25519-dalek strict). Both reject the
    same set of non-canonical encodings. We can pin only the off-chain
    side here — the on-chain side is exercised by the certificate-issuer
    Rust tests."""

    def test_cryptography_library_present_and_modern(self):
        # If `cryptography` is missing the test suite would not have got
        # this far (NodeKeypair would have failed import). Still pin a
        # version floor — strict Ed25519 has been the default for years.
        from cryptography import __version__
        major = int(__version__.split(".")[0])
        assert major >= 41, (
            f"cryptography>=41 required for strict Ed25519 (VULN-21); "
            f"have {__version__}"
        )

    def test_cryptography_rejects_malleable_signature(self):
        """Confirm the off-chain verifier actually refuses S + L. This
        is the property we depend on; if a future upgrade ever relaxed
        it, the explicit `is_canonical_signature_s` guard would still
        catch the issue."""
        keys = _cluster(1)
        digest = _digest()
        legit = sign_cert_digest(keys[0], digest)
        malleable_sig = _make_signature_with_s(
            _ED25519_GROUP_ORDER_L + 1, legit.signature,
        )
        # The NodeIdentity.verify() path goes through `cryptography` —
        # which must refuse the non-canonical S.
        ok = keys[0].identity.verify(digest, malleable_sig)
        assert ok is False, (
            "cryptography's Ed25519 verifier accepted a non-canonical S — "
            "the off-chain ↔ on-chain library symmetry is broken."
        )
