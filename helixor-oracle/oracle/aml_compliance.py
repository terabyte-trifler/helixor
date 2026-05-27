"""
oracle/aml_compliance.py — AML-1: cluster operator KYC/AML posture.

THE LATENT REGULATORY EXPOSURE (audit)
--------------------------------------
    "Large-scale AI agent lending enabled by Helixor certs may
    trigger AML compliance requirements for DeFi protocols, creating
    a regulatory attack surface that adversaries can exploit via
    regulatory complaints."

The audit-flagged risk is NOT that Helixor itself is an MSB / VASP /
CASP — the cluster does not hold customer funds, does not transmit
value, does not exchange one asset for another, and does not originate
or terminate a transaction. FinCEN's 2019 CVC guidance (FIN-2019-G001),
FATF Recommendation 15 / 16, and MiCA Art. 3(1)(16) all turn on the
service being a *custodial / transmission / exchange* service. The
cluster's output is an analytical signal over public on-chain data.

The risk is the SHAPE of an adversarial regulatory complaint:

  * A consumer protocol uses a Helixor cert to size a loan to an AI
    agent. The loan funds eventually move into a sanctioned mixer.
  * An adversary files a complaint with FinCEN / the FCA / SEBI
    alleging the cluster (or its operators) "facilitated" the
    transmission and therefore should have registered as an MSB,
    or that the operators were obligated to file SARs on
    suspicious on-chain behaviour they observed.
  * The complaint is meritless under the agencies' own published
    guidance — but if the cluster cannot produce a clean,
    mechanical, sig-bound posture statement at intake, the
    complaint becomes a *process tax*: lawyers, time, chilling
    effect on operator recruitment.

We cannot make complaints go away. What we CAN do is make the
operator's AML posture *mechanically auditable* before any complaint
lands, so a regulator's intake desk can resolve the question by
reading the on-disk manifest rather than by issuing a subpoena.

THE MITIGATION (this file)
--------------------------
AML-1 extends the existing HCR-4 / OFAC-1 / SEC-1 substrate with one
new field on every `OperatorAttestation`:

  * `aml_program_attestation` — drawn from a closed enum
    (`AmlProgramAttestation`). Each operator declares, at attestation
    time, ONE of:

      - `NO_AML_PROGRAM_REQUIRED_FOR_HELIXOR_ACTIVITY` — the
        operator's home-jurisdiction counsel has determined that
        the operator's activity *as a Helixor cluster operator*
        does NOT trigger BSA / PMLA / 5AMLD / MLR-2017 / PSA
        registration. This is the default posture: operators
        observe public on-chain data, do not custody value, do
        not transmit funds, and therefore do not meet the MSB /
        reporting-entity definition in their jurisdiction. The
        responsibility for this determination is the operator's
        (and their counsel's), not the protocol's.

      - `EXTERNAL_AML_PROGRAM_DECLARED` — the operator runs an
        external AML program for an *unrelated* business (e.g.
        they are also a registered money transmitter for a
        separate product). Their Helixor cluster activity remains
        outside that program's scope, and the protocol records
        the disclosure so a regulator inspecting the manifest can
        see that the operator's other registrations do NOT
        extend to their Helixor capacity. This value is the same
        legal posture as the first — it just signals "this
        operator has filed paperwork elsewhere" rather than "this
        operator has never filed paperwork".

The field is folded into `attestation_canonical_bytes`, so the
existing OFAC-1 Ed25519 sig binding extends to cover it. Lying about
AML posture costs the operator the same private key compromise the
rest of the protocol already assumes the adversary cannot perform.

ANCILLARY GUARD — _KYC_FORBIDDEN_FIELDS
---------------------------------------
The protocol explicitly does NOT collect KYC data on rated agents
(see `data_protection_policy.py`'s closed `DataCategory` set). If a
future PR adds a new data category, the maintainer must not
accidentally introduce a KYC-shaped field — that would silently
re-shape the protocol from "an analytical signal over public data"
to "a reporting entity holding customer identity information",
inverting the AML carve-out.

This module exports `_KYC_FORBIDDEN_FIELDS` (the set of substring
patterns that signal KYC-shaped data: `LEGAL_NAME`, `DOB`, `SSN`,
`TAX_ID`, `GOV_ID`, `PASSPORT`, `STREET_ADDRESS`, `PHONE_NUMBER`,
`PERSONAL_EMAIL`) and `assert_no_kyc_fields(name)` so DP-1's
DataCategory introduction flow can call it and the AML-1 audit gate
can verify the canonical category enum stays clean.

WHAT THIS FILE DOES NOT DO
--------------------------
It does NOT make any operator an MSB / VASP / CASP / FIU /
reporting-entity. Registration is per-operator legal posture, not a
protocol feature — same anti-pattern as SEC-1 declining to register
Helixor as an investment adviser. It does NOT implement SAR filing
or Travel Rule message generation; the cluster has no value
transmission to report on. It does NOT decide whether ANY specific
on-chain transaction is suspicious — that determination belongs to
the consumer who originates or terminates the transaction, not to
the cluster that observes it.

What it DOES is make the posture mechanically verifiable so legal,
audit, and the operator's own counsel can all read the same source
of truth.

DETERMINISM
-----------
Pure stdlib. No clock, no randomness, no network. Two auditors
running the gate on the same manifest produce byte-identical reports.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from oracle.operator_manifest import (
    OperatorAttestation,
    OperatorManifest,
)


# =============================================================================
# Constants — the closed enum of allowed AML program attestations
# =============================================================================

class AmlProgramAttestation(str, Enum):
    """
    Closed enum of allowed operator AML-posture declarations.

    The audit-mandated reading:

      * `NO_AML_PROGRAM_REQUIRED_FOR_HELIXOR_ACTIVITY` — the
        operator's home-jurisdiction counsel has determined the
        operator's Helixor cluster activity does NOT trigger
        BSA / PMLA / 5AMLD / MLR-2017 / PSA / similar reporting-
        entity registration. The cluster does not custody value,
        does not transmit funds, does not exchange one asset for
        another. The operator declares the posture; the
        protocol records and sig-binds it.

      * `EXTERNAL_AML_PROGRAM_DECLARED` — the operator runs an AML
        program for an unrelated business (e.g. they are also a
        registered money transmitter, or a regulated bank, etc.).
        Their Helixor cluster activity is *outside* that
        program's scope. The protocol records this so a regulator
        inspecting the manifest sees the disclosure plainly
        rather than having to issue a subpoena to find out
        whether the operator holds an MSB licence elsewhere.

    Both values represent the same load-bearing legal posture —
    that the operator's Helixor activity is not a covered activity.
    The difference is purely *disclosure shape*. Adding a value to
    this enum is a protocol governance change. Legal review + the
    public AML notice in `launch/legal/aml_kyc_notice.md` must be
    updated in lockstep.

    Models we intentionally do NOT enumerate (and therefore the
    gate refuses):

      * `HELIXOR_OPERATES_AS_MSB` / `HELIXOR_OPERATES_AS_VASP` etc.
        — would imply the cluster IS a covered activity. The
        compensation-independence floor in SEC-1
        (`FLAT_FEE_PER_CERT_FROM_TREASURY` only) plus the absence
        of custody / transmission / exchange in the protocol's
        actual behaviour mean these labels are simply not what the
        cluster is. Encoding them in the enum would let a
        regulator argue that the protocol *itself* believes it is
        a covered activity, contradicting every other surface.
    """

    NO_AML_PROGRAM_REQUIRED_FOR_HELIXOR_ACTIVITY = (
        "NO_AML_PROGRAM_REQUIRED_FOR_HELIXOR_ACTIVITY"
    )
    EXTERNAL_AML_PROGRAM_DECLARED = "EXTERNAL_AML_PROGRAM_DECLARED"


#: The set of AML attestations the production boot gate accepts.
#: Explicit so a future "add a model" PR cannot quietly widen the
#: gate without touching this constant.
ALLOWED_AML_ATTESTATIONS: frozenset[str] = frozenset(
    {m.value for m in AmlProgramAttestation}
)


#: AML-1 AML/KYC DISCLAIMER — the canonical string every consumer-
#: facing surface that returns a cert score must render alongside
#: the numeric output (and alongside the SEC-1 `ADVISORY_DISCLAIMER`).
#: Mirrored byte-for-byte in `helixor-sdk/src/safe_reader.ts` (the
#: `AML_KYC_DISCLAIMER` export) and verified by
#: `audit/aml_compliance_check.py` so a refactor that quietly edits
#: the SDK string drifts from this source-of-truth and lights the
#: gate red.
#:
#: The text is the union of the concrete carve-outs the audit
#: requires: not a KYC control, not an AML screen, not a substitute
#: for the consumer's own due-diligence / sanctions / Travel Rule
#: obligations, and an explicit "the cluster does not collect
#: customer identity information" so a regulator reading the
#: disclaimer sees the AML carve-out posture upfront.
AML_KYC_DISCLAIMER: str = (
    "Helixor cert scores are technical trust signals computed from "
    "observable on-chain behaviour. They are NOT a KYC control, "
    "NOT an AML screen, and NOT a substitute for the consumer's "
    "own customer due-diligence, sanctions screening, or Travel "
    "Rule obligations under applicable law. The Helixor cluster "
    "does not collect customer identity information; consumers "
    "MUST run their own KYC/AML program for any transaction they "
    "originate or terminate based on a cert score."
)


def aml_kyc_disclaimer_text() -> str:
    """
    Return the canonical AML-1 KYC/AML disclaimer.

    Helper for callsites that want to render the disclaimer
    alongside a returned score. Returns the same string as
    `AML_KYC_DISCLAIMER` — the function exists so a caller can
    import a helper rather than a module-level constant when that
    pattern fits the surrounding code better.
    """
    return AML_KYC_DISCLAIMER


# =============================================================================
# _KYC_FORBIDDEN_FIELDS — forward-looking guard against KYC drift
# =============================================================================

#: Substring patterns that signal KYC-shaped data. Any
#: `DataCategory` name (or other on-disk identifier that names a
#: per-agent storage column / topic field) that matches one of
#: these substrings is refused.
#:
#: The list is intentionally redundant — `DOB` AND
#: `DATE_OF_BIRTH` both appear so a maintainer who picks either
#: spelling trips the guard. The substrings are upper-case ASCII;
#: matching is case-insensitive.
#:
#: Adding to this list is a one-way ratchet (you can add more
#: forbidden patterns but should not remove existing ones).
_KYC_FORBIDDEN_FIELDS: tuple[str, ...] = (
    "LEGAL_NAME",
    "FULL_NAME",
    "FIRST_NAME",
    "LAST_NAME",
    "DOB",
    "DATE_OF_BIRTH",
    "BIRTH_DATE",
    "SSN",
    "TAX_ID",
    "TAX_NUMBER",
    "GOV_ID",
    "GOVERNMENT_ID",
    "PASSPORT",
    "NATIONAL_ID",
    "DRIVERS_LICENSE",
    "DRIVERS_LICENCE",
    "STREET_ADDRESS",
    "POSTAL_ADDRESS",
    "HOME_ADDRESS",
    "PHONE_NUMBER",
    "MOBILE_NUMBER",
    "PERSONAL_EMAIL",
    "BANK_ACCOUNT",
    "ROUTING_NUMBER",
    "IBAN",
)


class KycFieldRefusedError(ValueError):
    """
    Raised by `assert_no_kyc_fields` when a candidate field name
    matches one of the `_KYC_FORBIDDEN_FIELDS` patterns.

    The error carries the offending name + the matched pattern so
    the caller (typically `DataCategory` introduction in DP-1) sees
    exactly which substring tripped the guard.
    """


def assert_no_kyc_fields(name: str) -> None:
    """
    Refuse `name` if it matches any `_KYC_FORBIDDEN_FIELDS` pattern.

    Case-insensitive substring match — `"customer_legal_name"`,
    `"LEGAL_NAME"`, and `"OperatorLegalName"` all trip.

    This is the forward-looking guard the protocol uses when a new
    per-agent storage column / topic field / category enum value
    is introduced. The cluster's posture as a NON-reporting-entity
    rests on the fact that it does not collect KYC data; a future
    PR that adds a column named `customer_legal_name` would
    silently re-shape the protocol from "an analytical signal over
    public data" to "a reporting entity holding customer identity
    information", inverting the AML carve-out.

    Raises `KycFieldRefusedError` on a match; returns None on a
    clean name.
    """
    upper = name.upper()
    for forbidden in _KYC_FORBIDDEN_FIELDS:
        if forbidden in upper:
            raise KycFieldRefusedError(
                f"name {name!r} matches KYC-forbidden pattern "
                f"{forbidden!r}; the cluster's AML posture rests on "
                f"NOT collecting KYC data — adding this field would "
                f"invert the carve-out. See "
                f"oracle/aml_compliance.py:_KYC_FORBIDDEN_FIELDS."
            )


# =============================================================================
# Errors
# =============================================================================

class AmlComplianceError(RuntimeError):
    """
    AML-1 HARDENING: raised when an operator manifest fails the
    AML-posture gate — empty / disallowed `aml_program_attestation`.

    The exception's `.report` carries per-attestation verdicts so an
    operator can see WHICH declaration is non-compliant.
    """

    def __init__(self, message: str, report: "AmlComplianceReport"):
        super().__init__(message)
        self.report = report


# =============================================================================
# AmlComplianceReport
# =============================================================================

@dataclass(frozen=True, slots=True)
class AmlComplianceReport:
    """
    One run of the AML-1 gate.

    `verdicts`   tuple of `(node_id, ok, reason)` triples in
                 manifest order. `reason` is the empty string on
                 pass, a short failure description on fail. Ordered
                 so two auditors running the gate on the same
                 manifest produce byte-identical reports.
    """

    verdicts: tuple[tuple[str, bool, str], ...] = ()

    @property
    def all_compliant(self) -> bool:
        return all(ok for _, ok, _ in self.verdicts)

    @property
    def failed_node_ids(self) -> tuple[str, ...]:
        return tuple(node_id for node_id, ok, _ in self.verdicts if not ok)


# =============================================================================
# verify_aml_posture — the boot gate
# =============================================================================

def _verify_one(att: OperatorAttestation) -> tuple[bool, str]:
    """Return (ok, reason)."""
    if not att.aml_program_attestation:
        return False, (
            "aml_program_attestation is empty — every operator must "
            "declare a posture from ALLOWED_AML_ATTESTATIONS before "
            "the cluster boots"
        )
    if att.aml_program_attestation not in ALLOWED_AML_ATTESTATIONS:
        return False, (
            f"aml_program_attestation {att.aml_program_attestation!r} "
            f"is not in ALLOWED_AML_ATTESTATIONS "
            f"({sorted(ALLOWED_AML_ATTESTATIONS)!r}) — postures that "
            f"would imply the cluster IS a covered activity are "
            f"refused at the gate"
        )
    return True, ""


def verify_aml_posture(
    manifest: OperatorManifest,
) -> AmlComplianceReport:
    """
    Verify every attestation in `manifest` declares an AML posture
    from `ALLOWED_AML_ATTESTATIONS`.

    Returns the report on full-pass; raises
    `AmlComplianceError` (with the report attached) on any
    failure. This is the production boot gate. Tests that only
    care about diversity / sig binding skip this and call
    `verify_operator_diversity` / `verify_attestation_signatures`
    alone.
    """
    verdicts: list[tuple[str, bool, str]] = []
    for att in manifest.attestations:
        ok, reason = _verify_one(att)
        verdicts.append((att.node_id, ok, reason))

    report = AmlComplianceReport(verdicts=tuple(verdicts))
    if report.all_compliant:
        return report

    failures = [
        f"{node_id}: {reason}" for node_id, ok, reason in verdicts if not ok
    ]
    raise AmlComplianceError(
        f"AML-1: {len(report.failed_node_ids)} of "
        f"{len(manifest.attestations)} operator attestation(s) FAILED "
        f"the AML-posture gate:\n  - "
        + "\n  - ".join(failures)
        + "\nEvery operator must declare an aml_program_attestation "
        + f"from {sorted(ALLOWED_AML_ATTESTATIONS)!r}. Re-issue the "
        + "manifest with the correct field and re-sign "
        + "attestation_canonical_bytes(att) with the same private "
        + "key whose public half is in att.pubkey.",
        report,
    )


# =============================================================================
# collect_aml_attestations — audit summary
# =============================================================================

def collect_aml_attestations(
    manifest: OperatorManifest,
) -> tuple[tuple[str, str], ...]:
    """
    Return every operator's declared AML posture paired with their
    node_id, in manifest order. Used by the audit gate to render a
    deterministic summary of "every operator's AML posture in this
    cluster".
    """
    return tuple(
        (att.node_id, att.aml_program_attestation)
        for att in manifest.attestations
    )


__all__ = [
    "ALLOWED_AML_ATTESTATIONS",
    "AML_KYC_DISCLAIMER",
    "AmlComplianceError",
    "AmlComplianceReport",
    "AmlProgramAttestation",
    "KycFieldRefusedError",
    "aml_kyc_disclaimer_text",
    "assert_no_kyc_fields",
    "collect_aml_attestations",
    "verify_aml_posture",
]
