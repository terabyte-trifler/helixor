"""
oracle/securities_compliance.py — SEC-1: cluster operator securities-law posture.

THE LATENT REGULATORY EXPOSURE (audit)
--------------------------------------
    "If DeFi protocols use cert scores to gate capital allocation and
    oracle operators have financial interest in the protocol, there
    could be securities liability."

The audit-flagged risk is structural, not implementation-bug shaped:

  * Cert scores are consumed by external lending markets to size
    loans. A consumer who reads a Helixor cert and lends against an
    inflated score has been *materially influenced* by the cluster's
    output.
  * If a cluster operator has a *financial interest* in the protocol
    that varies with that lending outcome — performance fees, equity
    upside tied to TVL, a token whose price tracks score-gated
    capital flows — the four prongs of the US Howey test
    (investment of money / common enterprise / expectation of
    profits / derived solely from efforts of others) start to align
    with their compensation structure rather than with a pure
    service-for-fee posture.
  * Worse: if an operator has *undisclosed* financial relationships
    with a rated agent_wallet (employs the operator, is owned by
    a related party, is the operator themselves), then every cert
    they sign for that wallet is potentially a self-dealing
    arrangement of the kind the Investment Advisers Act §202(a)(11)
    and SEBI's IA regs forbid for compensated advice.

We cannot make securities law go away with code. What we CAN do is
make the *posture* of every operator legible BEFORE registration, and
make any lie about that posture cost the same private key compromise
the rest of the protocol already assumes the adversary cannot perform.

THE MITIGATION (this file)
--------------------------
SEC-1 hardens the existing HCR-4 / OFAC-1 substrate with two new
fields on every `OperatorAttestation`:

  * `compensation_model` — drawn from a closed enum (`CompensationModel`).
    Today the ONLY allowed value is `FLAT_FEE_PER_CERT_FROM_TREASURY`:
    a fixed per-cert fee paid out of the protocol treasury, NOT a
    fee that varies with the lending outcome the cert influences,
    NOT a token allocation, NOT a performance fee. This positions
    the operator as a service provider (compensated for work
    rendered) and explicitly NOT as a participant in a common
    enterprise tied to consumer outcomes.
  * `conflicts_disclosed` — a tuple of `(rated_wallet,
    relationship_type)` declarations. An operator who has a
    financial relationship with a rated agent must enumerate it.
    The cluster does NOT refuse to rate the wallet — that decision
    belongs to the operator's legal counsel — but the disclosure
    is sig-bound and audit-visible, so a regulator inspecting the
    manifest can see the relationship as plainly as the operator's
    own org affiliation.

Both fields are folded into `attestation_canonical_bytes`, so the
existing OFAC-1 Ed25519 sig binding extends to cover them. Lying
about compensation or hiding a conflict requires re-signing with the
operator's private key — the same one they use to sign certs in
production. The lie costs the same key compromise the rest of the
protocol assumes the adversary cannot perform.

WHAT THIS FILE DOES NOT DO
--------------------------
It does NOT register Helixor (or any operator) as an investment
adviser, broker-dealer, CASP under MiCA, or registered IA under SEBI.
Registration is a per-operator legal posture, not a protocol
feature. It does NOT enforce an on-chain accredited-investor gate —
same anti-pattern as OFAC-1's declined SanctionedAgentList PDA
(creates a high-value authority key, breaks permissionless
invariant). It does NOT decide whether a cert score IS or IS NOT a
"security" under any specific regulator's framework — that is for
counsel + the public not-investment-advice notice
(`launch/legal/securities_notice.md`) to disclose.

What it DOES is make the posture mechanically verifiable so legal,
audit, and the operator's own counsel can all read the same source
of truth.

DETERMINISM
-----------
Pure stdlib. No clock, no randomness, no network. Two auditors
running the gate on the same manifest produce byte-identical reports.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum

from oracle.operator_manifest import (
    OperatorAttestation,
    OperatorManifest,
)


# =============================================================================
# Constants — the closed enum of allowed compensation models
# =============================================================================

class CompensationModel(str, Enum):
    """
    Closed enum of allowed operator compensation arrangements.

    The Howey-prong analysis we are anchoring to:

      * `FLAT_FEE_PER_CERT_FROM_TREASURY` — operator paid a fixed
        amount per cert issued, out of the protocol treasury. Does
        NOT depend on the lending outcome the cert influences. Does
        NOT scale with TVL. Does NOT include token allocation. The
        operator is a service provider, compensated for work
        rendered. This is the ONLY value the boot gate accepts.

    Models we intentionally do NOT enumerate (and therefore the gate
    refuses):

      * Performance-fee / revenue-share — couples operator income to
        consumer-side capital allocation. Triggers Howey prong 4
        ("derived solely from efforts of others") in a way the flat-
        fee model does not.
      * Token grants whose value tracks protocol TVL — couples
        operator income to consumer-side use of cert scores.
      * Equity in a Helixor-affiliated entity that does not exist
        purely for service delivery.

    Adding a value to this enum is a protocol governance change.
    Legal review + the public notice in
    `launch/legal/securities_notice.md` must be updated in lockstep.
    """

    FLAT_FEE_PER_CERT_FROM_TREASURY = "FLAT_FEE_PER_CERT_FROM_TREASURY"


#: The set of compensation models the production boot gate accepts.
#: Currently a single value — explicit so a future "add a model" PR
#: cannot quietly widen the gate without touching this constant.
ALLOWED_COMPENSATION_MODELS: frozenset[str] = frozenset(
    {CompensationModel.FLAT_FEE_PER_CERT_FROM_TREASURY.value}
)


#: SEC-1 ADVISORY DISCLAIMER — the canonical string every consumer-
#: facing surface that returns a cert score must render alongside the
#: numeric output. Mirrored byte-for-byte in
#: `helixor-sdk/src/safe_reader.ts` (the `ADVISORY_DISCLAIMER` export)
#: and verified by `audit/securities_compliance_check.py` so a
#: refactor that quietly edits the SDK string drifts from this
#: source-of-truth and lights the gate red.
#:
#: The text is the union of the three concrete carve-outs the audit
#: requires: not investment advice, not a security rating, not a
#: registered investment adviser. The phrasing is intentionally plain
#: and short — long legalese in API output gets ignored; a single
#: sentence at the boundary is what an end-user actually reads.
ADVISORY_DISCLAIMER: str = (
    "Helixor cert scores are technical trust signals computed from "
    "observable on-chain behaviour. They are NOT investment advice, "
    "NOT a security rating, and NOT issued by a registered "
    "investment adviser. Consumers MUST NOT treat a Helixor cert "
    "score as a recommendation to buy, sell, or hold any asset; the "
    "decision to act on the score is the consumer's alone."
)


def disclaimer_text() -> str:
    """
    Return the canonical SEC-1 advisory disclaimer.

    Helper for callsites that want to render the disclaimer alongside
    a returned score. Returns the same string as `ADVISORY_DISCLAIMER`
    — the function exists so a caller can import a helper rather than
    a module-level constant when that pattern fits the surrounding
    code better.
    """
    return ADVISORY_DISCLAIMER


# =============================================================================
# Errors
# =============================================================================

class SecuritiesComplianceError(RuntimeError):
    """
    SEC-1 HARDENING: raised when an operator manifest fails the
    securities-posture gate — empty / disallowed compensation model,
    or a malformed conflict disclosure.

    The exception's `.report` carries per-attestation verdicts so an
    operator can see WHICH declaration is non-compliant.
    """

    def __init__(self, message: str, report: "SecuritiesComplianceReport"):
        super().__init__(message)
        self.report = report


# =============================================================================
# ConflictDisclosure — the per-relationship declaration
# =============================================================================

@dataclass(frozen=True, slots=True)
class ConflictDisclosure:
    """
    One declared financial relationship between an operator and a
    rated agent.

    `rated_wallet`        base58 Solana pubkey of the rated agent the
                          operator has a relationship with.
    `relationship_type`   short uppercase ASCII label — e.g.
                          `"EMPLOYEE"`, `"AFFILIATE"`,
                          `"SAME_LEGAL_ENTITY"`, `"PARTNER"`. Opaque
                          to the gate; the audit trail consumes it.
                          The label MUST NOT contain `|`, `:`, or
                          `;` (those are canonical-bytes separators).

    The cluster does NOT refuse to rate `rated_wallet` — see module
    docstring. The cluster DOES bind the declaration into the
    operator's signed attestation so the disclosure cannot be hidden
    or retroactively edited without re-signing with the operator's
    private key.
    """

    rated_wallet:      str
    relationship_type: str


_FORBIDDEN_CONFLICT_CHARS = ("|", ":", ";")


def _validate_conflict_well_formed(conflict: ConflictDisclosure) -> str | None:
    """Return `None` if well-formed, else a short reason string."""
    if not conflict.rated_wallet or not conflict.rated_wallet.strip():
        return "rated_wallet is empty"
    if not conflict.relationship_type or not conflict.relationship_type.strip():
        return "relationship_type is empty"
    for forbidden in _FORBIDDEN_CONFLICT_CHARS:
        if forbidden in conflict.rated_wallet:
            return (
                f"rated_wallet contains forbidden separator "
                f"{forbidden!r}"
            )
        if forbidden in conflict.relationship_type:
            return (
                f"relationship_type contains forbidden separator "
                f"{forbidden!r}"
            )
    return None


# =============================================================================
# Canonical serialisation for sig-binding
# =============================================================================

def serialize_conflicts(
    conflicts: Sequence[ConflictDisclosure],
) -> str:
    """
    Canonical string for the `conflicts_disclosed` field, folded
    into `attestation_canonical_bytes` so the OFAC-1 sig binding
    extends to cover it.

    Format::

        <wallet1>:<type1>;<wallet2>:<type2>;...

    Sorted lexically by `(rated_wallet, relationship_type)` so two
    operators rendering the same conflict set produce byte-identical
    output. Returns the empty string for an empty tuple.
    """
    if not conflicts:
        return ""
    pairs = sorted(
        (c.rated_wallet, c.relationship_type) for c in conflicts
    )
    return ";".join(f"{w}:{t}" for (w, t) in pairs)


# =============================================================================
# SecuritiesComplianceReport
# =============================================================================

@dataclass(frozen=True, slots=True)
class SecuritiesComplianceReport:
    """
    One run of the SEC-1 gate.

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
# verify_compensation_independence — the boot gate
# =============================================================================

def _verify_one(att: OperatorAttestation) -> tuple[bool, str]:
    """Return (ok, reason)."""
    if not att.compensation_model:
        return False, (
            "compensation_model is empty — every operator must "
            "declare a model from ALLOWED_COMPENSATION_MODELS before "
            "the cluster boots"
        )
    if att.compensation_model not in ALLOWED_COMPENSATION_MODELS:
        return False, (
            f"compensation_model {att.compensation_model!r} is not in "
            f"ALLOWED_COMPENSATION_MODELS "
            f"({sorted(ALLOWED_COMPENSATION_MODELS)!r}) — models that "
            f"couple operator income to consumer-side capital "
            f"outcomes are refused at the gate"
        )
    for forbidden in _FORBIDDEN_CONFLICT_CHARS:
        if forbidden in att.compensation_model:
            return False, (
                f"compensation_model contains forbidden separator "
                f"{forbidden!r}"
            )
    for i, conflict in enumerate(att.conflicts_disclosed):
        if not isinstance(conflict, ConflictDisclosure):
            return False, (
                f"conflicts_disclosed[{i}] is not a ConflictDisclosure "
                f"instance"
            )
        reason = _validate_conflict_well_formed(conflict)
        if reason is not None:
            return False, f"conflicts_disclosed[{i}]: {reason}"
    return True, ""


def verify_compensation_independence(
    manifest: OperatorManifest,
) -> SecuritiesComplianceReport:
    """
    Verify every attestation in `manifest` declares a compensation
    model in `ALLOWED_COMPENSATION_MODELS` and every
    `conflicts_disclosed` entry is well-formed.

    Returns the report on full-pass; raises
    `SecuritiesComplianceError` (with the report attached) on any
    failure. This is the production boot gate. Tests that only care
    about diversity / sig binding skip this and call
    `verify_operator_diversity` / `verify_attestation_signatures`
    alone.
    """
    verdicts: list[tuple[str, bool, str]] = []
    for att in manifest.attestations:
        ok, reason = _verify_one(att)
        verdicts.append((att.node_id, ok, reason))

    report = SecuritiesComplianceReport(verdicts=tuple(verdicts))
    if report.all_compliant:
        return report

    failures = [
        f"{node_id}: {reason}" for node_id, ok, reason in verdicts if not ok
    ]
    raise SecuritiesComplianceError(
        f"SEC-1: {len(report.failed_node_ids)} of "
        f"{len(manifest.attestations)} operator attestation(s) FAILED "
        f"the securities-posture gate:\n  - "
        + "\n  - ".join(failures)
        + "\nEvery operator must declare a compensation_model from "
        + f"{sorted(ALLOWED_COMPENSATION_MODELS)!r} and well-formed "
        + "conflicts_disclosed entries. Re-issue the manifest with "
        + "the correct fields and re-sign attestation_canonical_bytes(att) "
        + "with the same private key whose public half is in att.pubkey.",
        report,
    )


# =============================================================================
# verify_all_conflicts_sig_bound — paranoia cross-check
# =============================================================================

def collect_disclosed_conflicts(
    manifest: OperatorManifest,
) -> tuple[tuple[str, ConflictDisclosure], ...]:
    """
    Return every disclosed conflict in the manifest paired with the
    declaring node_id, in manifest order, then in canonical conflict
    sort order. Used by the audit gate to render a deterministic
    audit summary of "every disclosed conflict in this cluster".
    """
    out: list[tuple[str, ConflictDisclosure]] = []
    for att in manifest.attestations:
        ordered = sorted(
            att.conflicts_disclosed,
            key=lambda c: (c.rated_wallet, c.relationship_type),
        )
        for c in ordered:
            out.append((att.node_id, c))
    return tuple(out)


__all__ = [
    "ADVISORY_DISCLAIMER",
    "ALLOWED_COMPENSATION_MODELS",
    "CompensationModel",
    "ConflictDisclosure",
    "SecuritiesComplianceError",
    "SecuritiesComplianceReport",
    "collect_disclosed_conflicts",
    "disclaimer_text",
    "serialize_conflicts",
    "verify_compensation_independence",
]
