"""
tests/oracle/test_aml1_compliance.py — AML-1 hardening.

Cluster operators carry latent KYC/AML regulatory exposure if they
cannot point to a sig-bound posture statement at the moment an
adversarial complaint lands. Helixor itself is not an MSB / VASP /
CASP / reporting entity — it has no custody, no transmission, no
exchange — but a clean intake response depends on the operator's
posture being legible BEFORE a regulator asks.

AML-1 closes the substrate path by:
  * Extending `OperatorAttestation` with `aml_program_attestation`
    (closed enum: NO_AML_PROGRAM_REQUIRED_FOR_HELIXOR_ACTIVITY |
    EXTERNAL_AML_PROGRAM_DECLARED).
  * Folding the field into `attestation_canonical_bytes` so the
    OFAC-1 Ed25519 sig binding extends to cover it.
  * `verify_aml_posture(manifest)` as the production boot gate —
    refuses empty / disallowed AML postures.
  * `_KYC_FORBIDDEN_FIELDS` + `assert_no_kyc_fields(name)` as the
    forward-looking guard against KYC drift: any future DataCategory
    or per-agent storage column named with a KYC-shaped substring
    (`LEGAL_NAME`, `DOB`, `SSN`, ...) is refused.

This file pins:
  - `AmlProgramAttestation` is a closed enum and
    `ALLOWED_AML_ATTESTATIONS` matches its values.
  - `attestation_canonical_bytes` includes aml_program_attestation —
    mutating it changes the canonical bytes.
  - A tampered aml_program_attestation invalidates the OFAC-1 sig.
  - `verify_aml_posture` passes a clean manifest with either allowed
    value.
  - `verify_aml_posture` rejects empty + disallowed values.
  - The report preserves manifest order.
  - `collect_aml_attestations` enumerates postures in manifest order.
  - `_KYC_FORBIDDEN_FIELDS` is well-formed (non-empty, ascii-upper).
  - `assert_no_kyc_fields` is case-insensitive and catches every
    pinned pattern.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from solders.pubkey import Pubkey

from oracle.aml_compliance import (
    ALLOWED_AML_ATTESTATIONS,
    AML_KYC_DISCLAIMER,
    AmlComplianceError,
    AmlComplianceReport,
    AmlProgramAttestation,
    KycFieldRefusedError,
    _KYC_FORBIDDEN_FIELDS,
    aml_kyc_disclaimer_text,
    assert_no_kyc_fields,
    collect_aml_attestations,
    verify_aml_posture,
)
from oracle.operator_manifest import (
    OperatorAttestation,
    attestation_canonical_bytes,
    build_manifest,
    verify_attestation_signature,
)
from oracle.securities_compliance import CompensationModel


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

_FLAT_FEE = CompensationModel.FLAT_FEE_PER_CERT_FROM_TREASURY.value
_NO_AML = AmlProgramAttestation.NO_AML_PROGRAM_REQUIRED_FOR_HELIXOR_ACTIVITY.value
_EXT_AML = AmlProgramAttestation.EXTERNAL_AML_PROGRAM_DECLARED.value


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
    aml_program_attestation: str = _NO_AML,
) -> OperatorAttestation:
    """Produce a fully-signed OperatorAttestation with SEC-1 + AML-1 fields."""
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
        aml_program_attestation=aml_program_attestation,
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
        aml_program_attestation=aml_program_attestation,
        signature=sig_hex,
    )


# ----------------------------------------------------------------------------
# AmlProgramAttestation enum + allowlist
# ----------------------------------------------------------------------------

def test_aml_enum_values_match_allowlist():
    """The enum and the allowlist must agree — otherwise a future
    enum addition silently widens the boot gate without a
    governance event."""
    assert ALLOWED_AML_ATTESTATIONS == frozenset(
        m.value for m in AmlProgramAttestation
    )


def test_aml_allowlist_matches_governance_pin():
    """A regression that adds an `OPERATES_AS_MSB`-shaped value must
    light this red."""
    assert ALLOWED_AML_ATTESTATIONS == frozenset({
        "NO_AML_PROGRAM_REQUIRED_FOR_HELIXOR_ACTIVITY",
        "EXTERNAL_AML_PROGRAM_DECLARED",
    })


# ----------------------------------------------------------------------------
# attestation_canonical_bytes — AML-1 field is folded in
# ----------------------------------------------------------------------------

def test_canonical_bytes_includes_aml_attestation():
    base = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        compensation_model=_FLAT_FEE,
        aml_program_attestation=_NO_AML,
    )
    mutated = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        compensation_model=_FLAT_FEE,
        aml_program_attestation=_EXT_AML,
    )
    assert (
        attestation_canonical_bytes(base)
        != attestation_canonical_bytes(mutated)
    )


def test_canonical_bytes_empty_aml_differs_from_set_aml():
    """A pre-AML-1 attestation (empty aml field) must produce
    different canonical bytes than a post-AML-1 attestation —
    otherwise a downgrade attack could strip the binding."""
    pre = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        compensation_model=_FLAT_FEE,
        aml_program_attestation="",
    )
    post = OperatorAttestation(
        node_id="n-0", pubkey="pk-0", operator_org="Org A",
        operator_contact="ops@orga.example", jurisdiction="US",
        compensation_model=_FLAT_FEE,
        aml_program_attestation=_NO_AML,
    )
    assert (
        attestation_canonical_bytes(pre)
        != attestation_canonical_bytes(post)
    )


# ----------------------------------------------------------------------------
# OFAC-1 sig binding extends to AML-1 field
# ----------------------------------------------------------------------------

def test_tampered_aml_attestation_invalidates_sig():
    """An operator who declares NO_AML_PROGRAM_REQUIRED, signs, then
    later swaps in EXTERNAL_AML_PROGRAM_DECLARED without re-signing
    must fail the gate. (Either change of posture is allowed — but
    only with a fresh signature.)"""
    priv, pubkey = _new_keypair()
    legit = _signed_att(
        "n-0", priv=priv, pubkey_b58=pubkey,
        aml_program_attestation=_NO_AML,
    )
    tampered = OperatorAttestation(
        node_id=legit.node_id,
        pubkey=legit.pubkey,
        operator_org=legit.operator_org,
        operator_contact=legit.operator_contact,
        jurisdiction=legit.jurisdiction,
        compensation_model=legit.compensation_model,
        conflicts_disclosed=legit.conflicts_disclosed,
        aml_program_attestation=_EXT_AML,          # <- lie
        signature=legit.signature,                  # <- old sig
    )
    assert verify_attestation_signature(tampered) is False


def test_legit_signed_attestation_verifies():
    """Sanity check: a freshly signed attestation with AML-1 field
    populated must verify cleanly."""
    legit = _signed_att("n-0")
    assert verify_attestation_signature(legit) is True


# ----------------------------------------------------------------------------
# verify_aml_posture — happy path
# ----------------------------------------------------------------------------

def test_clean_manifest_with_no_aml_passes():
    atts = [_signed_att(f"n-{i}") for i in range(3)]
    manifest = build_manifest(atts, threshold=2)
    report = verify_aml_posture(manifest)
    assert isinstance(report, AmlComplianceReport)
    assert report.all_compliant is True
    assert report.failed_node_ids == ()


def test_clean_manifest_with_external_aml_passes():
    """An operator who declares EXTERNAL_AML_PROGRAM_DECLARED is
    fully compliant — the value signals disclosure of an unrelated
    AML program, not failure."""
    atts = [
        _signed_att("n-0", aml_program_attestation=_EXT_AML),
        _signed_att("n-1", aml_program_attestation=_NO_AML),
    ]
    manifest = build_manifest(atts, threshold=2)
    report = verify_aml_posture(manifest)
    assert report.all_compliant is True


# ----------------------------------------------------------------------------
# verify_aml_posture — failure modes
# ----------------------------------------------------------------------------

def test_empty_aml_attestation_is_rejected():
    """The default empty string means the attestation has not been
    AML-1-extended. Production refuses to boot."""
    atts = [
        _signed_att("n-0", aml_program_attestation=""),
        _signed_att("n-1"),
    ]
    manifest = build_manifest(atts, threshold=2)
    with pytest.raises(AmlComplianceError) as exc:
        verify_aml_posture(manifest)
    assert "n-0" in exc.value.report.failed_node_ids
    assert "aml_program_attestation is empty" in str(exc.value)


def test_disallowed_aml_attestation_is_rejected():
    """An `OPERATES_AS_MSB`-shaped value would imply the cluster IS
    a covered activity, contradicting every other surface. The gate
    refuses."""
    atts = [
        _signed_att("n-0", aml_program_attestation="OPERATES_AS_MSB"),
        _signed_att("n-1"),
    ]
    manifest = build_manifest(atts, threshold=2)
    with pytest.raises(AmlComplianceError) as exc:
        verify_aml_posture(manifest)
    assert "n-0" in exc.value.report.failed_node_ids
    assert "ALLOWED_AML_ATTESTATIONS" in str(exc.value)


def test_failed_verdicts_preserve_manifest_order():
    """Determinism: two auditors running the gate on the same
    manifest produce byte-identical verdict order."""
    atts = [
        _signed_att("n-0"),
        _signed_att("n-1", aml_program_attestation=""),     # bad
        _signed_att("n-2"),
        _signed_att("n-3", aml_program_attestation="BAD"),  # bad
    ]
    manifest = build_manifest(atts, threshold=3)
    with pytest.raises(AmlComplianceError) as exc:
        verify_aml_posture(manifest)
    verdict_order = [node_id for node_id, _, _ in exc.value.report.verdicts]
    assert verdict_order == ["n-0", "n-1", "n-2", "n-3"]


# ----------------------------------------------------------------------------
# collect_aml_attestations — audit summary
# ----------------------------------------------------------------------------

def test_collect_aml_attestations_in_manifest_order():
    atts = [
        _signed_att("n-0", aml_program_attestation=_EXT_AML),
        _signed_att("n-1", aml_program_attestation=_NO_AML),
        _signed_att("n-2", aml_program_attestation=_EXT_AML),
    ]
    manifest = build_manifest(atts, threshold=2)
    summary = collect_aml_attestations(manifest)
    assert summary == (
        ("n-0", _EXT_AML),
        ("n-1", _NO_AML),
        ("n-2", _EXT_AML),
    )


def test_collect_aml_attestations_empty_manifest_attestations():
    """Manifest cannot have zero attestations (build_manifest
    refuses), so the smallest input is one entry."""
    atts = [_signed_att("n-0")]
    manifest = build_manifest(atts, threshold=1)
    assert collect_aml_attestations(manifest) == (("n-0", _NO_AML),)


# ----------------------------------------------------------------------------
# _KYC_FORBIDDEN_FIELDS + assert_no_kyc_fields
# ----------------------------------------------------------------------------

def test_kyc_forbidden_fields_is_non_empty():
    assert len(_KYC_FORBIDDEN_FIELDS) > 0


def test_kyc_forbidden_fields_are_ascii_upper_underscored():
    """All patterns must be upper-case ASCII so the case-insensitive
    substring match in `assert_no_kyc_fields` is well-defined."""
    for f in _KYC_FORBIDDEN_FIELDS:
        assert f == f.upper(), f
        assert all(c.isalpha() or c == "_" for c in f), f


def test_assert_no_kyc_fields_passes_clean_name():
    """Wallet IDs, transaction history, scores, refusal log — all
    existing DataCategory shapes must pass."""
    assert_no_kyc_fields("WALLET_ID")
    assert_no_kyc_fields("TRANSACTION_HISTORY")
    assert_no_kyc_fields("BEHAVIORAL_PROFILE_SCORE")
    assert_no_kyc_fields("REFUSAL_LOG")


def test_assert_no_kyc_fields_catches_legal_name():
    with pytest.raises(KycFieldRefusedError) as exc:
        assert_no_kyc_fields("CUSTOMER_LEGAL_NAME")
    assert "LEGAL_NAME" in str(exc.value)


def test_assert_no_kyc_fields_is_case_insensitive():
    """Both lowercase and uppercase variants of an underscored
    field name must trip. (Substring match is on upper-cased input;
    the guard expects snake_case / ALL_CAPS_WITH_UNDERSCORES — the
    convention used throughout DataCategory and the rest of the
    codebase.)"""
    for name in (
        "customer_legal_name",
        "Customer_Legal_Name",
        "CUSTOMER_LEGAL_NAME",
    ):
        with pytest.raises(KycFieldRefusedError):
            assert_no_kyc_fields(name)


@pytest.mark.parametrize("name", [
    "user_dob",
    "DATE_OF_BIRTH",
    "user_ssn",
    "TAX_ID",
    "gov_id_number",
    "PASSPORT_NUMBER",
    "STREET_ADDRESS",
    "phone_number",
    "personal_email",
    "BANK_ACCOUNT_NUMBER",
    "IBAN",
])
def test_assert_no_kyc_fields_catches_pinned_patterns(name):
    """Every pinned forbidden pattern must be caught when embedded
    in a realistic field name."""
    with pytest.raises(KycFieldRefusedError):
        assert_no_kyc_fields(name)


# ----------------------------------------------------------------------------
# Existing DataCategory enum stays clean
# ----------------------------------------------------------------------------

def test_existing_data_categories_pass_kyc_guard():
    """Every DataCategory currently declared in DP-1 must pass the
    AML-1 KYC guard. A future PR that adds a KYC-shaped category
    name must trip this test."""
    from oracle.data_protection_policy import DataCategory
    for member in DataCategory:
        # Should not raise.
        assert_no_kyc_fields(member.value)


# ----------------------------------------------------------------------------
# AML_KYC_DISCLAIMER — content + helper
# ----------------------------------------------------------------------------

def test_aml_kyc_disclaimer_is_non_empty():
    assert AML_KYC_DISCLAIMER
    assert len(AML_KYC_DISCLAIMER) > 0


def test_aml_kyc_disclaimer_carries_required_carve_outs():
    """The audit-mandated concrete carve-outs MUST appear."""
    assert "NOT a KYC control" in AML_KYC_DISCLAIMER
    assert "NOT an AML screen" in AML_KYC_DISCLAIMER
    assert "Travel Rule" in AML_KYC_DISCLAIMER
    assert "sanctions screening" in AML_KYC_DISCLAIMER


def test_aml_kyc_disclaimer_frames_as_technical_trust_signal():
    assert "technical trust signal" in AML_KYC_DISCLAIMER


def test_aml_kyc_disclaimer_disclaims_identity_collection():
    """The cluster's load-bearing AML posture is that it does NOT
    collect customer identity information. The disclaimer must say
    this explicitly."""
    assert "does not collect customer identity information" in AML_KYC_DISCLAIMER


def test_aml_kyc_disclaimer_tells_consumer_they_must_run_own_program():
    assert "MUST run their own KYC/AML program" in AML_KYC_DISCLAIMER


def test_aml_kyc_disclaimer_text_returns_constant_unchanged():
    assert aml_kyc_disclaimer_text() == AML_KYC_DISCLAIMER


def test_aml_kyc_disclaimer_text_is_referentially_stable():
    """Two calls return the same string — the helper is a constant
    getter, not a builder."""
    assert aml_kyc_disclaimer_text() == aml_kyc_disclaimer_text()
