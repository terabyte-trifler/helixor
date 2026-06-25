"""
tests/oracle/test_hcr4_operator_signature.py — OFAC-1 hardening of HCR-4.

The HCR-4 diversity gate (test_hcr4_operator_diversity.py) checks only
the DECLARED tallies — an operator who lies about jurisdiction defeats
it without breaking it. This file pins the OFAC-1 hardening: each
operator signs the canonical bytes of their own attestation with the
SAME private key whose public half they declare as `pubkey`. Lying
about any field invalidates the sig; re-signing requires possession
of the same key the rest of the protocol assumes the adversary cannot
exfiltrate.

Pins:
  - `attestation_canonical_bytes` is deterministic and binds every
    declared field (node_id, pubkey, org, contact, jurisdiction).
  - The canonical format does NOT include `signature` (you cannot sign
    over your own signature).
  - `verify_attestation_signature` returns True for a valid sig
    produced by the declared pubkey.
  - Tampering with ANY declared field invalidates the sig.
  - Lying about jurisdiction without re-signing fails the gate.
  - Empty signature fails verification (returns False, does NOT raise).
  - Hex with wrong length / non-hex / wrong pubkey format all fail
    gracefully (return False).
  - Sig produced by a DIFFERENT key fails (the attacker cannot reuse
    a sig from another node).
  - `verify_attestation_signatures` aggregates per-node verdicts and
    raises OperatorSignatureError on any failure.
  - Domain separator `phylanx.operator_attestation.v1` is folded in
    — a cert-payload sig cannot be replayed as an attestation sig.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from solders.pubkey import Pubkey

from oracle.operator_manifest import (
    ATTESTATION_DOMAIN_TAG,
    OperatorAttestation,
    OperatorSignatureError,
    OperatorSignatureReport,
    attestation_canonical_bytes,
    build_manifest,
    verify_attestation_signature,
    verify_attestation_signatures,
)


# ----------------------------------------------------------------------------
# Helpers — produce real Ed25519 keypairs + base58 pubkeys for tests
# ----------------------------------------------------------------------------

def _new_keypair():
    """Return (privkey, base58_pubkey)."""
    priv = Ed25519PrivateKey.generate()
    raw_pub = priv.public_key().public_bytes_raw()
    return priv, str(Pubkey.from_bytes(raw_pub))


def _signed_att(
    node_id: str,
    *,
    priv=None,
    pubkey_b58: str | None = None,
    org: str = "Org A",
    contact: str = "ops@orga.example",
    jurisdiction: str = "US",
) -> OperatorAttestation:
    """Produce a fully-signed OperatorAttestation."""
    if priv is None or pubkey_b58 is None:
        priv, pubkey_b58 = _new_keypair()
    unsigned = OperatorAttestation(
        node_id=node_id,
        pubkey=pubkey_b58,
        operator_org=org,
        operator_contact=contact,
        jurisdiction=jurisdiction,
        signature="",
    )
    sig_hex = priv.sign(attestation_canonical_bytes(unsigned)).hex()
    return OperatorAttestation(
        node_id=node_id,
        pubkey=pubkey_b58,
        operator_org=org,
        operator_contact=contact,
        jurisdiction=jurisdiction,
        signature=sig_hex,
    )


# ----------------------------------------------------------------------------
# attestation_canonical_bytes — determinism and domain tag
# ----------------------------------------------------------------------------

def test_canonical_bytes_deterministic():
    att = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        signature="ignored",
    )
    a = attestation_canonical_bytes(att)
    b = attestation_canonical_bytes(att)
    assert a == b


def test_canonical_bytes_carries_domain_tag():
    att = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
    )
    canonical = attestation_canonical_bytes(att)
    assert canonical.startswith(ATTESTATION_DOMAIN_TAG)


def test_canonical_bytes_does_not_include_signature():
    """The signature is not folded in — otherwise you could not sign
    your own attestation."""
    att_a = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        signature="aaaa",
    )
    att_b = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        signature="bbbb",
    )
    assert attestation_canonical_bytes(att_a) == attestation_canonical_bytes(att_b)


def test_canonical_bytes_changes_when_any_declared_field_changes():
    """Every declared field is bound — a lie about ANY of them
    invalidates the sig."""
    base_kwargs = dict(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
    )
    base = OperatorAttestation(**base_kwargs)
    base_bytes = attestation_canonical_bytes(base)
    for field_name in ("node_id", "pubkey", "operator_org",
                       "operator_contact", "jurisdiction"):
        mutated_kwargs = dict(base_kwargs)
        mutated_kwargs[field_name] = mutated_kwargs[field_name] + "-tampered"
        mutated = OperatorAttestation(**mutated_kwargs)
        assert attestation_canonical_bytes(mutated) != base_bytes, (
            f"canonical bytes did not change when {field_name} mutated"
        )


# ----------------------------------------------------------------------------
# verify_attestation_signature — happy path
# ----------------------------------------------------------------------------

def test_valid_signature_verifies():
    att = _signed_att("n-0")
    assert verify_attestation_signature(att) is True


def test_tampered_jurisdiction_fails_verification():
    """The OFAC-1 case: an operator declares US, signs, then a
    captured cluster swaps the jurisdiction to SG without re-signing."""
    priv, pubkey = _new_keypair()
    legit = _signed_att(
        "n-0", priv=priv, pubkey_b58=pubkey, jurisdiction="US",
    )
    # Tamper: swap jurisdiction but keep the signature.
    tampered = OperatorAttestation(
        node_id=legit.node_id,
        pubkey=legit.pubkey,
        operator_org=legit.operator_org,
        operator_contact=legit.operator_contact,
        jurisdiction="SG",            # <- lie
        signature=legit.signature,    # <- old sig
    )
    assert verify_attestation_signature(tampered) is False


def test_tampered_org_fails_verification():
    priv, pubkey = _new_keypair()
    legit = _signed_att("n-0", priv=priv, pubkey_b58=pubkey, org="Phylanx Labs")
    tampered = OperatorAttestation(
        node_id=legit.node_id,
        pubkey=legit.pubkey,
        operator_org="Adversary Corp",  # <- lie
        operator_contact=legit.operator_contact,
        jurisdiction=legit.jurisdiction,
        signature=legit.signature,
    )
    assert verify_attestation_signature(tampered) is False


def test_signature_from_different_key_fails():
    """An attacker cannot present a sig from another node's key."""
    priv_a, pubkey_a = _new_keypair()
    priv_b, _pubkey_b = _new_keypair()
    unsigned = OperatorAttestation(
        node_id="n-0", pubkey=pubkey_a, operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        signature="",
    )
    # Sign with priv_B but declare pubkey_A.
    sig_hex = priv_b.sign(attestation_canonical_bytes(unsigned)).hex()
    att = OperatorAttestation(
        node_id="n-0", pubkey=pubkey_a, operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        signature=sig_hex,
    )
    assert verify_attestation_signature(att) is False


def test_empty_signature_fails_verification():
    att = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        signature="",
    )
    assert verify_attestation_signature(att) is False


def test_non_hex_signature_fails_gracefully():
    att = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        signature="not-a-hex-string",
    )
    assert verify_attestation_signature(att) is False


def test_wrong_length_signature_fails_gracefully():
    """An Ed25519 sig is exactly 64 bytes (128 hex chars)."""
    att = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        signature="aabbcc",  # 3 bytes, not 64
    )
    assert verify_attestation_signature(att) is False


def test_invalid_base58_pubkey_fails_gracefully():
    """`pk-foo` is not a valid base58 Solana pubkey — verification
    must return False (not raise) so a test manifest with stub
    pubkeys can run the diversity gate without crashing the sig gate."""
    att = OperatorAttestation(
        node_id="n-0", pubkey="pk-foo", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        signature="00" * 64,
    )
    assert verify_attestation_signature(att) is False


# ----------------------------------------------------------------------------
# verify_attestation_signatures — batch gate
# ----------------------------------------------------------------------------

def test_all_signed_manifest_passes():
    atts = [_signed_att(f"n-{i}") for i in range(5)]
    manifest = build_manifest(atts, threshold=3)
    report = verify_attestation_signatures(manifest)
    assert isinstance(report, OperatorSignatureReport)
    assert report.all_signed is True
    assert report.failed_node_ids == ()


def test_one_unsigned_attestation_raises():
    """A manifest with even one unsigned attestation fails the gate.
    This is the OFAC-1 boot floor — production refuses to start
    unless every operator has cryptographically bound their
    declaration."""
    atts = [_signed_att(f"n-{i}") for i in range(4)]
    unsigned = OperatorAttestation(
        node_id="n-4", pubkey="pk-4", operator_org="Org B",
        operator_contact="ops@orgb.example", jurisdiction="DE",
        signature="",
    )
    atts.append(unsigned)
    manifest = build_manifest(atts, threshold=3)
    with pytest.raises(OperatorSignatureError) as exc:
        verify_attestation_signatures(manifest)
    assert "n-4" in exc.value.report.failed_node_ids


def test_failed_verdicts_preserve_input_order():
    """Determinism: two operators running the gate on the same
    manifest produce byte-identical verdict order."""
    atts = [_signed_att(f"n-{i}") for i in range(3)]
    # Insert one tampered attestation in the middle.
    priv, pubkey = _new_keypair()
    legit = _signed_att("n-mid", priv=priv, pubkey_b58=pubkey,
                        jurisdiction="US")
    tampered = OperatorAttestation(
        node_id="n-mid", pubkey=pubkey, operator_org=legit.operator_org,
        operator_contact=legit.operator_contact, jurisdiction="SG",
        signature=legit.signature,
    )
    atts.insert(1, tampered)
    manifest = build_manifest(atts, threshold=3)
    with pytest.raises(OperatorSignatureError) as exc:
        verify_attestation_signatures(manifest)
    verdict_order = [node_id for node_id, _ in exc.value.report.verdicts]
    assert verdict_order == [a.node_id for a in atts]


# ----------------------------------------------------------------------------
# Domain separation — sigs from another domain cannot be replayed
# ----------------------------------------------------------------------------

def test_cert_payload_sig_does_not_verify_as_attestation():
    """A signature produced over the cert-payload digest must NOT
    verify when presented as an attestation sig. The
    ATTESTATION_DOMAIN_TAG prefix is what enforces this."""
    priv, pubkey = _new_keypair()
    # Imagine the operator's private key signed an arbitrary cert
    # payload (NOT the attestation canonical bytes).
    cert_payload_sig = priv.sign(b"cert.payload.digest.example").hex()
    att = OperatorAttestation(
        node_id="n-0", pubkey=pubkey, operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        signature=cert_payload_sig,
    )
    assert verify_attestation_signature(att) is False
