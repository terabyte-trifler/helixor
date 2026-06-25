"""
tests/oracle/test_cert_signing.py — off-chain threshold signing.

Pins the canonical cert digest, signature aggregation (with all the filter
rules a real adversary would try to slip through), and the Ed25519
precompile-instruction builder.
"""

from __future__ import annotations

import pytest

from oracle.cluster.cert_signing import (
    HEADER_LEN,
    MESSAGE_LEN,
    PUBKEY_LEN,
    SIGNATURE_LEN,
    THIS_IX_SENTINEL,
    AggregatedSignatures,
    ClusterSignature,
    InsufficientSignatures,
    aggregate_signatures,
    build_ed25519_instructions,
    build_ed25519_ix_data,
    cert_payload_digest,
    sign_cert_digest,
)
from oracle.cluster.identity import NodeKeypair
from oracle.cluster.input_commitment import SlotAnchor


# =============================================================================
# Helpers
# =============================================================================

AGENT_PK = b"\x11" * 32
BASELINE_HASH = b"\x33" * 32
INPUT_COMMITMENT = b"\x77" * 32     # AW-01: fixed test commitment
SLOT_ANCHOR = SlotAnchor(slot=250_000_000, block_hash=b"\x99" * 32)  # AW-01-EXT


def _cluster(n: int = 5) -> list[NodeKeypair]:
    return [NodeKeypair.from_seed(f"node-{i}", f"seed{i}".encode())
            for i in range(n)]


def _keys_of(kps):
    return [kp.public_key for kp in kps]


# =============================================================================
# Canonical cert payload digest
# =============================================================================

class TestCertPayloadDigest:

    def test_digest_is_32_bytes(self):
        d = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        assert len(d) == 32

    def test_digest_is_deterministic(self):
        a = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        b = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        assert a == b

    def test_digest_changes_with_score(self):
        a = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        b = cert_payload_digest(AGENT_PK, 1, 852, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        assert a != b

    def test_digest_changes_with_epoch(self):
        a = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        b = cert_payload_digest(AGENT_PK, 2, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        assert a != b

    def test_digest_changes_with_alert_tier(self):
        a = cert_payload_digest(AGENT_PK, 1, 851, 0, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        b = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        assert a != b

    def test_digest_changes_with_flags(self):
        a = cert_payload_digest(AGENT_PK, 1, 851, 2, 0, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        b = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        assert a != b

    def test_digest_changes_with_baseline_hash(self):
        a = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, b"\x33" * 32, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        b = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, b"\x44" * 32, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        assert a != b

    def test_digest_changes_with_input_commitment(self):
        # AW-01: a different input commitment must yield a different digest
        # — without this, an attacker could submit a cert with the same
        # score over different (poisoned) inputs.
        a = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, b"\x77" * 32, SLOT_ANCHOR)
        b = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, b"\x88" * 32, SLOT_ANCHOR)
        assert a != b

    def test_digest_changes_with_slot_anchor_slot(self):
        # AW-01-EXT: a different slot in the SlotAnchor must yield a
        # different digest — the on-chain handler verifies (slot, hash)
        # against the SlotHashes sysvar, so an attacker that swaps the
        # slot post-hoc would also break the signature.
        anchor_a = SlotAnchor(slot=250_000_000, block_hash=b"\x99" * 32)
        anchor_b = SlotAnchor(slot=250_000_001, block_hash=b"\x99" * 32)
        a = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, anchor_a)
        b = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, anchor_b)
        assert a != b

    def test_digest_changes_with_slot_anchor_hash(self):
        # AW-01-EXT: a different block_hash in the SlotAnchor must yield
        # a different digest — symmetric to the slot case; both halves of
        # the anchor are folded in.
        anchor_a = SlotAnchor(slot=250_000_000, block_hash=b"\x99" * 32)
        anchor_b = SlotAnchor(slot=250_000_000, block_hash=b"\xaa" * 32)
        a = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, anchor_a)
        b = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, anchor_b)
        assert a != b

    def test_digest_changes_with_baseline_commit_nonce(self):
        # AW-03: a different commit_nonce names a different BaselineDataAccount
        # PDA. Folding it into the digest means a cluster signature for nonce
        # N cannot be replayed against the on-chain handler if the agent's
        # current BaselineStats nonce has rotated to N+1.
        a = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, baseline_commit_nonce=1,
        )
        b = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, baseline_commit_nonce=2,
        )
        assert a != b

    def test_digest_legacy_default_nonce_is_zero(self):
        # Pre-AW-03 callers omit the nonce and the digest matches an
        # explicit nonce=0 — guarantees byte-identical digests across the
        # legacy/AW-03 boundary.
        default = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR,
        )
        explicit_zero = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, baseline_commit_nonce=0,
        )
        assert default == explicit_zero

    def test_digest_rejects_out_of_range_baseline_commit_nonce(self):
        with pytest.raises(ValueError, match="baseline_commit_nonce"):
            cert_payload_digest(
                AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
                SLOT_ANCHOR, baseline_commit_nonce=1 << 64,
            )

    # --- AW-04: scoring-bundle + components hash folded into the digest ---

    def test_digest_changes_with_scoring_code_hash(self):
        # AW-04: different scoring-bundle hashes name different scoring
        # kernels. Folding it into the digest means a cluster running
        # patched scoring code cannot produce a digest with the
        # published bundle's hash unless it actually ran that bundle.
        a = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, baseline_commit_nonce=7,
            scoring_code_hash=b"\xaa" * 32,
        )
        b = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, baseline_commit_nonce=7,
            scoring_code_hash=b"\xbb" * 32,
        )
        assert a != b

    def test_digest_changes_with_score_components_hash(self):
        # AW-04: different per-dimension breakdowns produce different
        # canonical-JSON bytes, and therefore different SHA-256 hashes.
        # The cluster cannot publish a fabricated score without committing
        # to a `dims[]` whose replay arithmetic produces that score.
        a = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, baseline_commit_nonce=7,
            scoring_code_hash=b"\xaa" * 32,
            score_components_hash=b"\x11" * 32,
        )
        b = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, baseline_commit_nonce=7,
            scoring_code_hash=b"\xaa" * 32,
            score_components_hash=b"\x22" * 32,
        )
        assert a != b

    def test_digest_legacy_default_aw04_hashes_are_zero(self):
        # Pre-AW-04 callers omit both kwargs and the digest matches an
        # explicit zero pair — guarantees byte-identical digests across
        # the legacy/AW-04 boundary.
        default = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR,
        )
        explicit_zero = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR,
            scoring_code_hash=b"\x00" * 32,
            score_components_hash=b"\x00" * 32,
        )
        assert default == explicit_zero

    def test_digest_rejects_short_scoring_code_hash(self):
        with pytest.raises(ValueError, match="scoring_code_hash"):
            cert_payload_digest(
                AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
                SLOT_ANCHOR,
                scoring_code_hash=b"\xaa" * 31,
            )

    def test_digest_rejects_short_score_components_hash(self):
        with pytest.raises(ValueError, match="score_components_hash"):
            cert_payload_digest(
                AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
                SLOT_ANCHOR,
                score_components_hash=b"\xaa" * 31,
            )

    def test_aw04_hashes_fold_after_aw03_nonce(self):
        # The byte-layout contract: AW-04 bytes are appended AFTER the
        # AW-03 baseline_commit_nonce, in the documented order
        # (scoring_code_hash, then score_components_hash). Build the
        # digest two ways and verify the manual layout matches.
        import hashlib

        sc_hash = b"\xc0" * 32
        comp_hash = b"\xd0" * 32

        produced = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, baseline_commit_nonce=7,
            scoring_code_hash=sc_hash,
            score_components_hash=comp_hash,
        )

        manual = (
            AGENT_PK
            + (1).to_bytes(8, "big")
            + (851).to_bytes(2, "big")
            + (2).to_bytes(1, "big")
            + (8).to_bytes(4, "big")
            + BASELINE_HASH
            + b"\x01"  # immediate_red
            + INPUT_COMMITMENT
            + SLOT_ANCHOR.to_bytes()
            + (7).to_bytes(8, "big")
            + sc_hash
            + comp_hash
            # M-05 sentinel + Day 38 sentinel zeros (default kwargs).
            + (0).to_bytes(4, "big")        # issuer_config_version
            + (0).to_bytes(8, "big")        # failure_mode_bitmask
            + (0).to_bytes(4, "big")        # remediation_codes
            + b"\x00" * 32                  # diagnosis_payload_hash
            + (0).to_bytes(1, "big")        # taxonomy_version
        )
        assert produced == hashlib.sha256(manual).digest()

    def test_digest_changes_with_immediate_red(self):
        a = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        b = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, False, INPUT_COMMITMENT, SLOT_ANCHOR)
        assert a != b

    def test_digest_changes_with_agent(self):
        a = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        b = cert_payload_digest(b"\x22" * 32, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        assert a != b

    def test_bad_agent_length_rejected(self):
        with pytest.raises(ValueError):
            cert_payload_digest(b"short", 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        with pytest.raises(ValueError):
            cert_payload_digest(AGENT_PK, 1, 851, 2, 8, b"short", True, INPUT_COMMITMENT, SLOT_ANCHOR)
        with pytest.raises(ValueError, match="input_commitment"):
            # AW-01: short input_commitment must be rejected.
            cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, b"short", SLOT_ANCHOR)

    def test_out_of_range_inputs_rejected(self):
        with pytest.raises(ValueError):
            cert_payload_digest(AGENT_PK, 1, 1 << 17, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        with pytest.raises(ValueError):
            cert_payload_digest(AGENT_PK, 1, 851, 1 << 9, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)

    # ─── M-05 sensitivity ────────────────────────────────────────────────────

    def test_digest_changes_with_issuer_config_version(self):
        a = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, issuer_config_version=1,
        )
        b = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, issuer_config_version=2,
        )
        assert a != b, "M-05: issuer_config_version must be folded into the digest"

    def test_digest_rejects_out_of_range_issuer_config_version(self):
        with pytest.raises(ValueError, match="issuer_config_version"):
            cert_payload_digest(
                AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
                SLOT_ANCHOR, issuer_config_version=1 << 32,
            )

    # ─── Day 38 sensitivity ──────────────────────────────────────────────────

    def test_digest_changes_with_failure_mode_bitmask(self):
        a = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, failure_mode_bitmask=0,
        )
        b = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, failure_mode_bitmask=1,
        )
        assert a != b

    def test_digest_changes_with_remediation_codes(self):
        a = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, remediation_codes=0,
        )
        b = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, remediation_codes=1,
        )
        assert a != b

    def test_digest_changes_with_diagnosis_payload_hash(self):
        a = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, diagnosis_payload_hash=b"\xaa" * 32,
        )
        b = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, diagnosis_payload_hash=b"\xbb" * 32,
        )
        assert a != b

    def test_digest_changes_with_taxonomy_version(self):
        a = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, taxonomy_version=1,
        )
        b = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, taxonomy_version=2,
        )
        assert a != b

    def test_digest_rejects_out_of_range_day38_fields(self):
        with pytest.raises(ValueError, match="failure_mode_bitmask"):
            cert_payload_digest(
                AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
                SLOT_ANCHOR, failure_mode_bitmask=1 << 64,
            )
        with pytest.raises(ValueError, match="remediation_codes"):
            cert_payload_digest(
                AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
                SLOT_ANCHOR, remediation_codes=1 << 32,
            )
        with pytest.raises(ValueError, match="diagnosis_payload_hash"):
            cert_payload_digest(
                AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
                SLOT_ANCHOR, diagnosis_payload_hash=b"short",
            )
        with pytest.raises(ValueError, match="taxonomy_version"):
            cert_payload_digest(
                AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
                SLOT_ANCHOR, taxonomy_version=1 << 8,
            )

    def test_preimage_length_is_273_bytes(self):
        # Day-23 discipline: pin the exact preimage length so any layout
        # drift (extra/missing field, wrong width) trips immediately.
        import hashlib
        produced = cert_payload_digest(
            AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT,
            SLOT_ANCHOR, baseline_commit_nonce=7,
            scoring_code_hash=b"\xc0" * 32,
            score_components_hash=b"\xd0" * 32,
            issuer_config_version=9,
            failure_mode_bitmask=0xDEADBEEFCAFEF00D,
            remediation_codes=0xCAFE_BABE,
            diagnosis_payload_hash=b"\x77" * 32,
            taxonomy_version=3,
        )
        manual = (
            AGENT_PK                              # 32
            + (1).to_bytes(8, "big")              #  8
            + (851).to_bytes(2, "big")            #  2
            + (2).to_bytes(1, "big")              #  1
            + (8).to_bytes(4, "big")              #  4
            + BASELINE_HASH                       # 32
            + b"\x01"                             #  1
            + INPUT_COMMITMENT                    # 32
            + SLOT_ANCHOR.to_bytes()              # 40
            + (7).to_bytes(8, "big")              #  8
            + (b"\xc0" * 32)                      # 32
            + (b"\xd0" * 32)                      # 32
            + (9).to_bytes(4, "big")              #  4  M-05
            + (0xDEADBEEFCAFEF00D).to_bytes(8, "big")  # 8 Day 38
            + (0xCAFE_BABE).to_bytes(4, "big")    #  4  Day 38
            + (b"\x77" * 32)                      # 32  Day 38
            + (3).to_bytes(1, "big")              #  1  Day 38
        )
        assert len(manual) == 273, f"preimage length drifted: {len(manual)}"
        assert produced == hashlib.sha256(manual).digest()

    # ─── Cross-language pin (Day 23 discipline) ─────────────────────────────

    def test_cross_language_pin_v2_all_zero(self):
        # Pin: the SHA-256 of 273 zero bytes is exactly this digest. The
        # Rust pin at certificate-issuer/tests/cert_payload_digest_fold_order_pin.rs
        # `all_zero_input_vector_produces_pinned_digest` asserts the same
        # 32-byte value. If EITHER side reorders or resizes the layout,
        # this test fails on BOTH sides and the cluster cannot sign certs
        # the chain will accept.
        import hashlib
        produced = cert_payload_digest(
            b"\x00" * 32, 0, 0, 0, 0, b"\x00" * 32, False, b"\x00" * 32,
            SlotAnchor(slot=0, block_hash=b"\x00" * 32),
            baseline_commit_nonce=0,
            scoring_code_hash=b"\x00" * 32,
            score_components_hash=b"\x00" * 32,
            issuer_config_version=0,
            failure_mode_bitmask=0,
            remediation_codes=0,
            diagnosis_payload_hash=b"\x00" * 32,
            taxonomy_version=0,
        )
        expected = hashlib.sha256(b"\x00" * 273).digest()
        assert produced == expected, "v2 cross-language zero-vector pin drifted"


# =============================================================================
# Signing
# =============================================================================

class TestSignCertDigest:

    def test_signature_is_64_bytes(self):
        kp = _cluster()[0]
        digest = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        sig = sign_cert_digest(kp, digest)
        assert len(sig.signature) == 64
        assert sig.signer_pubkey == kp.public_key
        assert sig.digest == digest

    def test_signature_verifies(self):
        # The off-chain pre-check is the same check the on-chain
        # precompile does — sanity here.
        kp = _cluster()[0]
        digest = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        sig = sign_cert_digest(kp, digest)
        assert kp.identity.verify(digest, sig.signature)

    def test_bad_digest_length_rejected(self):
        kp = _cluster()[0]
        with pytest.raises(ValueError):
            sign_cert_digest(kp, b"short")


# =============================================================================
# Aggregation — the heart of the threshold rule
# =============================================================================

class TestAggregateSignatures:

    def _setup(self, signers: int = 3, threshold: int = 3):
        kps = _cluster(5)
        cluster_keys = _keys_of(kps)
        digest = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        sigs = [sign_cert_digest(kps[i], digest) for i in range(signers)]
        return cluster_keys, digest, sigs, kps

    def test_threshold_satisfied(self):
        cluster_keys, digest, sigs, _ = self._setup(3, 3)
        agg = aggregate_signatures(
            digest, sigs, cluster_keys=cluster_keys, threshold=3,
        )
        assert agg.count == 3

    def test_below_threshold_rejected(self):
        cluster_keys, digest, sigs, _ = self._setup(2, 3)
        with pytest.raises(InsufficientSignatures) as exc:
            aggregate_signatures(
                digest, sigs, cluster_keys=cluster_keys, threshold=3,
            )
        assert exc.value.got == 2
        assert exc.value.needed == 3

    def test_extra_signatures_truncated_to_threshold(self):
        # 5 signers, threshold 3 — take exactly 3 deterministically.
        cluster_keys, digest, sigs, _ = self._setup(5, 3)
        agg = aggregate_signatures(
            digest, sigs, cluster_keys=cluster_keys, threshold=3,
        )
        assert agg.count == 3

    def test_wrong_digest_filtered(self):
        # A signature over a DIFFERENT digest must not count toward the
        # threshold. This is exactly what stops a replay across cert payloads.
        cluster_keys, digest, sigs, kps = self._setup(2, 3)
        wrong_digest = cert_payload_digest(AGENT_PK, 1, 999, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        wrong_sig = sign_cert_digest(kps[2], wrong_digest)
        with pytest.raises(InsufficientSignatures):
            aggregate_signatures(
                digest, [*sigs, wrong_sig],
                cluster_keys=cluster_keys, threshold=3,
            )

    def test_non_cluster_key_filtered(self):
        # An outsider signing the right digest must not count.
        cluster_keys, digest, sigs, _ = self._setup(2, 3)
        outsider = NodeKeypair.from_seed("outsider", b"outsider")
        outsider_sig = sign_cert_digest(outsider, digest)
        with pytest.raises(InsufficientSignatures):
            aggregate_signatures(
                digest, [*sigs, outsider_sig],
                cluster_keys=cluster_keys, threshold=3,
            )

    def test_duplicate_signer_counts_once(self):
        # A node signing twice does not count twice toward the threshold.
        cluster_keys, digest, sigs, kps = self._setup(2, 3)
        duplicate = sign_cert_digest(kps[0], digest)
        with pytest.raises(InsufficientSignatures):
            aggregate_signatures(
                digest, [*sigs, duplicate],
                cluster_keys=cluster_keys, threshold=3,
            )

    def test_aggregation_is_deterministic(self):
        # Two honest aggregators with the same set produce the same output.
        cluster_keys, digest, sigs, _ = self._setup(5, 3)
        a = aggregate_signatures(
            digest, sigs, cluster_keys=cluster_keys, threshold=3,
        )
        # Same set in reverse order -> same result (sorted by pubkey).
        b = aggregate_signatures(
            digest, list(reversed(sigs)),
            cluster_keys=cluster_keys, threshold=3,
        )
        assert [s.signer_pubkey for s in a.signatures] == \
               [s.signer_pubkey for s in b.signatures]

    def test_a_forged_signature_is_filtered(self):
        # An attacker that copies a cluster pubkey but signs with the
        # wrong key — the signature won't verify and is filtered out.
        cluster_keys, digest, sigs, kps = self._setup(2, 3)
        attacker = NodeKeypair.from_seed("attacker", b"attacker")
        attacker_sig = ClusterSignature(
            signer_pubkey=kps[2].public_key,           # claims to be node-2
            signature=attacker.sign(digest),           # but is signed by attacker
            digest=digest,
        )
        with pytest.raises(InsufficientSignatures):
            aggregate_signatures(
                digest, [*sigs, attacker_sig],
                cluster_keys=cluster_keys, threshold=3,
            )


# =============================================================================
# Ed25519 precompile-instruction builder
# =============================================================================

class TestEd25519InstructionBuilder:

    def test_data_blob_layout(self):
        kp = _cluster()[0]
        digest = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        sig = sign_cert_digest(kp, digest)
        data = build_ed25519_ix_data(sig)

        expected_len = HEADER_LEN + PUBKEY_LEN + SIGNATURE_LEN + MESSAGE_LEN
        assert len(data) == expected_len == 144

        # Header sanity.
        assert data[0] == 1                            # num_signatures
        assert data[1] == 0                            # padding

        # The header fixes "this ix" sentinels — defends against a
        # cross-instruction misdirection attack.
        import struct
        (_n, _pad, sig_off, sig_ix, pk_off, pk_ix,
         msg_off, msg_size, msg_ix) = struct.unpack("<BBHHHHHHH", data[:HEADER_LEN])
        assert sig_ix == THIS_IX_SENTINEL
        assert pk_ix == THIS_IX_SENTINEL
        assert msg_ix == THIS_IX_SENTINEL
        assert msg_size == MESSAGE_LEN

        # The fields are at the expected offsets.
        assert data[pk_off:pk_off + PUBKEY_LEN] == kp.public_key
        assert data[sig_off:sig_off + SIGNATURE_LEN] == sig.signature
        assert data[msg_off:msg_off + MESSAGE_LEN] == digest

    def test_builds_one_ix_per_signature(self):
        kps = _cluster(5)
        digest = cert_payload_digest(AGENT_PK, 1, 851, 2, 8, BASELINE_HASH, True, INPUT_COMMITMENT, SLOT_ANCHOR)
        sigs = [sign_cert_digest(kp, digest) for kp in kps[:3]]
        agg = aggregate_signatures(
            digest, sigs, cluster_keys=_keys_of(kps), threshold=3,
        )
        ixs = build_ed25519_instructions(agg)
        assert len(ixs) == 3
        for ix in ixs:
            assert ix["program_id"] == "Ed25519SigVerify111111111111111111111111111"
            assert ix["accounts"] == []
            assert len(ix["data"]) == 144
