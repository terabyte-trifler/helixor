"""
tests/oracle/test_sec1_securities_compliance.py — SEC-1 hardening.

Cluster operators carry latent securities-law exposure if their
compensation couples to consumer-side capital outcomes (Howey prong 4)
or if they sign certs for agents they have undisclosed financial
relationships with (IA Act / SEBI IA regs).

SEC-1 closes the substrate path by:
  * Extending `OperatorAttestation` with `compensation_model` (closed
    enum, today only `FLAT_FEE_PER_CERT_FROM_TREASURY`) and
    `conflicts_disclosed` (tuple of `ConflictDisclosure`).
  * Folding both fields into `attestation_canonical_bytes` so the
    OFAC-1 Ed25519 sig binding extends to cover them.
  * `verify_compensation_independence(manifest)` as the production
    boot gate — refuses empty / disallowed compensation models and
    malformed conflict disclosures.

This file pins:
  - `CompensationModel` is a closed enum and
    `ALLOWED_COMPENSATION_MODELS` matches its values.
  - `serialize_conflicts` is deterministic, sort-stable, returns
    empty string for empty tuple, and binds both fields.
  - `attestation_canonical_bytes` includes compensation_model AND the
    canonical conflicts string — mutating either field changes the
    canonical bytes.
  - A tampered compensation_model invalidates the OFAC-1 sig.
  - A tampered conflict (added / removed / re-typed) invalidates the
    OFAC-1 sig.
  - `verify_compensation_independence` passes a clean manifest.
  - `verify_compensation_independence` rejects empty
    compensation_model, disallowed compensation_model, conflict
    disclosure with empty fields, and conflict disclosure with
    forbidden separator chars.
  - The report preserves manifest order.
  - `collect_disclosed_conflicts` enumerates conflicts in
    manifest+canonical sort order.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from solders.pubkey import Pubkey

from oracle.operator_manifest import (
    OperatorAttestation,
    attestation_canonical_bytes,
    build_manifest,
    verify_attestation_signature,
)
from oracle.securities_compliance import (
    ALLOWED_COMPENSATION_MODELS,
    CompensationModel,
    ConflictDisclosure,
    SecuritiesComplianceError,
    SecuritiesComplianceReport,
    collect_disclosed_conflicts,
    serialize_conflicts,
    verify_compensation_independence,
)


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

_FLAT_FEE = CompensationModel.FLAT_FEE_PER_CERT_FROM_TREASURY.value


def _new_keypair():
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
    compensation_model: str = _FLAT_FEE,
    conflicts_disclosed: tuple = (),
) -> OperatorAttestation:
    """Produce a fully-signed OperatorAttestation with SEC-1 fields."""
    if priv is None or pubkey_b58 is None:
        priv, pubkey_b58 = _new_keypair()
    unsigned = OperatorAttestation(
        node_id=node_id,
        pubkey=pubkey_b58,
        operator_org=org,
        operator_contact=contact,
        jurisdiction=jurisdiction,
        compensation_model=compensation_model,
        conflicts_disclosed=conflicts_disclosed,
        signature="",
    )
    sig_hex = priv.sign(attestation_canonical_bytes(unsigned)).hex()
    return OperatorAttestation(
        node_id=node_id,
        pubkey=pubkey_b58,
        operator_org=org,
        operator_contact=contact,
        jurisdiction=jurisdiction,
        compensation_model=compensation_model,
        conflicts_disclosed=conflicts_disclosed,
        signature=sig_hex,
    )


# ----------------------------------------------------------------------------
# CompensationModel enum + allowlist
# ----------------------------------------------------------------------------

def test_compensation_model_enum_values_match_allowlist():
    """The enum and the allowlist must agree — otherwise a future
    enum addition silently widens the boot gate without a
    governance event."""
    assert ALLOWED_COMPENSATION_MODELS == frozenset(
        m.value for m in CompensationModel
    )


def test_only_flat_fee_is_allowed_today():
    """A regression that adds a performance-fee or token-grant model
    must light this red."""
    assert ALLOWED_COMPENSATION_MODELS == frozenset(
        {"FLAT_FEE_PER_CERT_FROM_TREASURY"}
    )


# ----------------------------------------------------------------------------
# serialize_conflicts — determinism + sort stability
# ----------------------------------------------------------------------------

def test_serialize_empty_conflicts():
    assert serialize_conflicts(()) == ""


def test_serialize_single_conflict():
    c = ConflictDisclosure(rated_wallet="Wal1", relationship_type="EMPLOYEE")
    assert serialize_conflicts((c,)) == "Wal1:EMPLOYEE"


def test_serialize_conflicts_is_sort_stable():
    """Two operators rendering the same conflict set in different
    input orders must produce byte-identical canonical strings —
    otherwise their sigs would disagree."""
    c1 = ConflictDisclosure("Wallet-B", "EMPLOYEE")
    c2 = ConflictDisclosure("Wallet-A", "AFFILIATE")
    c3 = ConflictDisclosure("Wallet-A", "EMPLOYEE")
    forward = serialize_conflicts((c1, c2, c3))
    reverse = serialize_conflicts((c3, c2, c1))
    assert forward == reverse
    assert forward == "Wallet-A:AFFILIATE;Wallet-A:EMPLOYEE;Wallet-B:EMPLOYEE"


# ----------------------------------------------------------------------------
# attestation_canonical_bytes — SEC-1 fields are folded in
# ----------------------------------------------------------------------------

def test_canonical_bytes_includes_compensation_model():
    base = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        compensation_model=_FLAT_FEE,
    )
    mutated = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        compensation_model="PERFORMANCE_FEE",  # different — would change posture
    )
    assert (
        attestation_canonical_bytes(base) != attestation_canonical_bytes(mutated)
    )


def test_canonical_bytes_includes_conflicts():
    c = ConflictDisclosure("Wal1", "EMPLOYEE")
    base = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        compensation_model=_FLAT_FEE,
        conflicts_disclosed=(),
    )
    mutated = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        compensation_model=_FLAT_FEE,
        conflicts_disclosed=(c,),
    )
    assert (
        attestation_canonical_bytes(base) != attestation_canonical_bytes(mutated)
    )


def test_canonical_bytes_conflicts_order_does_not_matter():
    """Same conflict set in different input orders must produce the
    same canonical bytes (sort-stable serialisation)."""
    c1 = ConflictDisclosure("Wal-B", "EMPLOYEE")
    c2 = ConflictDisclosure("Wal-A", "AFFILIATE")
    a_fwd = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        compensation_model=_FLAT_FEE,
        conflicts_disclosed=(c1, c2),
    )
    a_rev = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        compensation_model=_FLAT_FEE,
        conflicts_disclosed=(c2, c1),
    )
    assert attestation_canonical_bytes(a_fwd) == attestation_canonical_bytes(a_rev)


# ----------------------------------------------------------------------------
# OFAC-1 sig binding extends to SEC-1 fields
# ----------------------------------------------------------------------------

def test_tampered_compensation_model_invalidates_sig():
    """An operator who declares FLAT_FEE, signs, then later swaps in
    PERFORMANCE_FEE without re-signing must fail the gate."""
    priv, pubkey = _new_keypair()
    legit = _signed_att(
        "n-0", priv=priv, pubkey_b58=pubkey,
        compensation_model=_FLAT_FEE,
    )
    tampered = OperatorAttestation(
        node_id=legit.node_id,
        pubkey=legit.pubkey,
        operator_org=legit.operator_org,
        operator_contact=legit.operator_contact,
        jurisdiction=legit.jurisdiction,
        compensation_model="PERFORMANCE_FEE",     # <- lie
        conflicts_disclosed=legit.conflicts_disclosed,
        signature=legit.signature,                # <- old sig
    )
    assert verify_attestation_signature(tampered) is False


def test_adding_a_conflict_invalidates_sig():
    """An operator who signs a clean (no conflicts) attestation and
    later quietly adds a conflict must fail the gate — otherwise
    they could hide a self-dealing arrangement."""
    priv, pubkey = _new_keypair()
    legit = _signed_att(
        "n-0", priv=priv, pubkey_b58=pubkey,
        conflicts_disclosed=(),
    )
    tampered = OperatorAttestation(
        node_id=legit.node_id, pubkey=legit.pubkey,
        operator_org=legit.operator_org,
        operator_contact=legit.operator_contact,
        jurisdiction=legit.jurisdiction,
        compensation_model=legit.compensation_model,
        conflicts_disclosed=(
            ConflictDisclosure("Wal-hidden", "EMPLOYEE"),
        ),
        signature=legit.signature,
    )
    assert verify_attestation_signature(tampered) is False


def test_removing_a_conflict_invalidates_sig():
    """An operator who signs WITH a disclosed conflict, then quietly
    drops it after signing, must fail the gate — otherwise they
    could retroactively disclaim a relationship they had at sig
    time."""
    priv, pubkey = _new_keypair()
    legit = _signed_att(
        "n-0", priv=priv, pubkey_b58=pubkey,
        conflicts_disclosed=(
            ConflictDisclosure("Wal-disclosed", "EMPLOYEE"),
        ),
    )
    tampered = OperatorAttestation(
        node_id=legit.node_id, pubkey=legit.pubkey,
        operator_org=legit.operator_org,
        operator_contact=legit.operator_contact,
        jurisdiction=legit.jurisdiction,
        compensation_model=legit.compensation_model,
        conflicts_disclosed=(),                   # <- lie
        signature=legit.signature,
    )
    assert verify_attestation_signature(tampered) is False


def test_retyped_conflict_invalidates_sig():
    """Changing the relationship_type without re-signing must fail."""
    priv, pubkey = _new_keypair()
    legit = _signed_att(
        "n-0", priv=priv, pubkey_b58=pubkey,
        conflicts_disclosed=(
            ConflictDisclosure("Wal-1", "EMPLOYEE"),
        ),
    )
    tampered = OperatorAttestation(
        node_id=legit.node_id, pubkey=legit.pubkey,
        operator_org=legit.operator_org,
        operator_contact=legit.operator_contact,
        jurisdiction=legit.jurisdiction,
        compensation_model=legit.compensation_model,
        conflicts_disclosed=(
            ConflictDisclosure("Wal-1", "PARTNER"),  # <- relabel
        ),
        signature=legit.signature,
    )
    assert verify_attestation_signature(tampered) is False


# ----------------------------------------------------------------------------
# verify_compensation_independence — happy path
# ----------------------------------------------------------------------------

def test_clean_manifest_passes():
    atts = [_signed_att(f"n-{i}") for i in range(3)]
    manifest = build_manifest(atts, threshold=2)
    report = verify_compensation_independence(manifest)
    assert isinstance(report, SecuritiesComplianceReport)
    assert report.all_compliant is True
    assert report.failed_node_ids == ()


def test_clean_manifest_with_disclosed_conflicts_passes():
    """Disclosed conflicts are NOT a failure — the cluster doesn't
    refuse self-dealing; it just makes it sig-bound + audit-visible."""
    atts = [
        _signed_att("n-0", conflicts_disclosed=(
            ConflictDisclosure("Wal-rel", "AFFILIATE"),
        )),
        _signed_att("n-1"),
    ]
    manifest = build_manifest(atts, threshold=2)
    report = verify_compensation_independence(manifest)
    assert report.all_compliant is True


# ----------------------------------------------------------------------------
# verify_compensation_independence — failure modes
# ----------------------------------------------------------------------------

def test_empty_compensation_model_is_rejected():
    """The default empty string means the attestation has not been
    SEC-1-extended. Production refuses to boot."""
    atts = [
        _signed_att("n-0", compensation_model=""),
        _signed_att("n-1"),
    ]
    manifest = build_manifest(atts, threshold=2)
    with pytest.raises(SecuritiesComplianceError) as exc:
        verify_compensation_independence(manifest)
    assert "n-0" in exc.value.report.failed_node_ids
    assert "compensation_model is empty" in str(exc.value)


def test_disallowed_compensation_model_is_rejected():
    """A performance-fee or token-grant model triggers Howey prong 4
    in a way the flat-fee model does not. The gate refuses."""
    atts = [
        _signed_att("n-0", compensation_model="PERFORMANCE_FEE"),
        _signed_att("n-1"),
    ]
    manifest = build_manifest(atts, threshold=2)
    with pytest.raises(SecuritiesComplianceError) as exc:
        verify_compensation_independence(manifest)
    assert "n-0" in exc.value.report.failed_node_ids
    assert "ALLOWED_COMPENSATION_MODELS" in str(exc.value)


def test_conflict_with_empty_wallet_is_rejected():
    bad_conflict = ConflictDisclosure(rated_wallet="", relationship_type="EMPLOYEE")
    atts = [
        _signed_att("n-0", conflicts_disclosed=(bad_conflict,)),
        _signed_att("n-1"),
    ]
    manifest = build_manifest(atts, threshold=2)
    with pytest.raises(SecuritiesComplianceError) as exc:
        verify_compensation_independence(manifest)
    assert "n-0" in exc.value.report.failed_node_ids
    assert "rated_wallet is empty" in str(exc.value)


def test_conflict_with_empty_type_is_rejected():
    bad_conflict = ConflictDisclosure(rated_wallet="Wal", relationship_type="")
    atts = [
        _signed_att("n-0", conflicts_disclosed=(bad_conflict,)),
        _signed_att("n-1"),
    ]
    manifest = build_manifest(atts, threshold=2)
    with pytest.raises(SecuritiesComplianceError) as exc:
        verify_compensation_independence(manifest)
    assert "n-0" in exc.value.report.failed_node_ids
    assert "relationship_type is empty" in str(exc.value)


def test_conflict_with_forbidden_separator_is_rejected():
    """The canonical-bytes separators (|, :, ;) cannot appear inside
    either field — otherwise a crafted wallet/type could splice an
    extra "conflict" into the canonical bytes."""
    bad_conflict = ConflictDisclosure(
        rated_wallet="Wal", relationship_type="EMPL;EXTRA:SPLICE",
    )
    atts = [
        _signed_att("n-0", conflicts_disclosed=(bad_conflict,)),
        _signed_att("n-1"),
    ]
    manifest = build_manifest(atts, threshold=2)
    with pytest.raises(SecuritiesComplianceError) as exc:
        verify_compensation_independence(manifest)
    assert "n-0" in exc.value.report.failed_node_ids
    assert "forbidden separator" in str(exc.value)


def test_failed_verdicts_preserve_manifest_order():
    """Determinism: two auditors running the gate on the same
    manifest produce byte-identical verdict order."""
    atts = [
        _signed_att("n-0"),
        _signed_att("n-1", compensation_model=""),     # bad
        _signed_att("n-2"),
        _signed_att("n-3", compensation_model="BAD"),  # bad
    ]
    manifest = build_manifest(atts, threshold=3)
    with pytest.raises(SecuritiesComplianceError) as exc:
        verify_compensation_independence(manifest)
    verdict_order = [node_id for node_id, _, _ in exc.value.report.verdicts]
    assert verdict_order == ["n-0", "n-1", "n-2", "n-3"]


# ----------------------------------------------------------------------------
# collect_disclosed_conflicts — audit summary
# ----------------------------------------------------------------------------

def test_collect_disclosed_conflicts_in_manifest_order():
    c_a = ConflictDisclosure("Wal-A", "EMPLOYEE")
    c_b = ConflictDisclosure("Wal-B", "AFFILIATE")
    atts = [
        _signed_att("n-0", conflicts_disclosed=(c_a, c_b)),
        _signed_att("n-1"),
        _signed_att("n-2", conflicts_disclosed=(c_b,)),
    ]
    manifest = build_manifest(atts, threshold=2)
    summary = collect_disclosed_conflicts(manifest)
    # n-0 first (a then b canonical order), then n-2.
    assert [node_id for node_id, _ in summary] == ["n-0", "n-0", "n-2"]
    assert [c.rated_wallet for _, c in summary] == ["Wal-A", "Wal-B", "Wal-B"]


def test_collect_disclosed_conflicts_empty_for_clean_manifest():
    atts = [_signed_att(f"n-{i}") for i in range(3)]
    manifest = build_manifest(atts, threshold=2)
    assert collect_disclosed_conflicts(manifest) == ()
