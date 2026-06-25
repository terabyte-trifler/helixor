"""
oracle/operator_manifest.py — HCR-4: operator key diversity manifest.

THE HIDDEN CENTRALIZATION RISK (audit)
--------------------------------------
    "If all 5 oracle node operators are the same organization (or
    individual), the 3-of-5 threshold is socially, not technically,
    distributed."

The threshold-signing math (3-of-5 on the cluster, M-of-N attestations
on slash-authority) assumes each KEY is held by an INDEPENDENT
party. If one organisation operates three of the five nodes — even
across three different machines in three different regions — that
organisation can produce a valid threshold signature unilaterally,
and the protocol's "no single point of trust" guarantee is fiction.

This is a fundamentally SOCIAL fact (who runs which key), but we can
reify it into an on-disk MANIFEST the cluster ships with and audit at
boot:

  * Each cluster operator declares their pubkey, their organisation
    name, a contact identity (email / PGP key id), and the
    jurisdiction (ISO-3166 country code) they sign from.
  * The manifest is the tuple of those declarations + the cluster's
    threshold.
  * The HCR-4 gate refuses any manifest where ONE org owns ≥
    threshold pubkeys (so they could not unilaterally sign a cert
    even with full insider co-operation), or where the cluster spans
    fewer than `MIN_DISTINCT_JURISDICTIONS` (so a single
    legal-process compulsion cannot reach all operators).

THE MITIGATION (this file)
--------------------------
`OperatorAttestation` and `OperatorManifest` are pure dataclasses;
`verify_operator_diversity(manifest)` is a pure function. The
manifest is loaded at boot from a path the deploy script controls;
the audit gate verifies the manifest's structure at CI time.

What this file does NOT do
--------------------------
It does NOT verify the TRUTHFULNESS of the attestations — an operator
who signs the manifest claiming "Org A" while secretly running Org B's
node cannot be caught by code alone. That is the job of the EXTERNAL
audit retest (3rd-party reviewer cross-checks the public commitments
of each operator against the manifest). What HCR-4 enforces is that
the manifest itself is internally consistent: the math of "no single
org meets threshold" is verifiable from the declared file, so the
external auditor only needs to verify that the declarations match
reality, not also re-do the threshold arithmetic.

DETERMINISM
-----------
Pure stdlib. No clock, no randomness, no network. Two operators
running the gate on the same manifest produce byte-identical reports.

INTERACTION WITH HCR-2
----------------------
HCR-2 protects against REGION monoculture; HCR-4 protects against
ORG monoculture. The two are orthogonal — an attacker who collapses
either axis collapses the threshold:

  * 5 nodes / 1 region / 5 orgs   -> regional outage = cluster down
  * 5 nodes / 5 regions / 1 org   -> insider = unilateral cert
  * 5 nodes / 3 regions / 3 orgs  -> both gates green
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field

try:                                                       # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
    _ED25519_AVAILABLE = True
except ImportError:                                        # pragma: no cover
    _ED25519_AVAILABLE = False

try:                                                       # pragma: no cover
    from solders.pubkey import Pubkey as _SoldersPubkey
    _SOLDERS_AVAILABLE = True
except ImportError:                                        # pragma: no cover
    _SOLDERS_AVAILABLE = False


# =============================================================================
# Constants
# =============================================================================

#: HCR-4 floor on jurisdictions: at least two distinct ISO-3166
#: country codes across the cluster. A single legal-process
#: compulsion cannot reach operators in two unrelated jurisdictions
#: simultaneously.
MIN_DISTINCT_JURISDICTIONS = 2

#: HCR-4 floor on organisations: at least two distinct operator orgs.
#: This is the bare-minimum independence floor; the per-org-cap check
#: (no single org owns ≥ threshold) is the stronger constraint.
MIN_DISTINCT_OPERATORS = 2


# =============================================================================
# Errors
# =============================================================================

class OperatorDiversityError(RuntimeError):
    """
    Raised when an operator manifest violates HCR-4 — one org owns
    enough pubkeys to meet the threshold unilaterally, OR the cluster
    spans too few distinct orgs / jurisdictions.

    The exception's `.report` carries the per-org and per-jurisdiction
    tallies so an operator can see WHICH grouping over-concentrated.
    """

    def __init__(self, message: str, report: "OperatorDiversityReport"):
        super().__init__(message)
        self.report = report


class OperatorManifestError(ValueError):
    """Raised on a malformed `OperatorManifest` construction."""


class OperatorSignatureError(RuntimeError):
    """
    OFAC-1 HARDENING: raised when one or more operator attestations
    fail cryptographic signature verification.

    The diversity gate (`verify_operator_diversity`) only checks that
    the manifest's DECLARED tallies are diverse. It cannot tell whether
    an operator LIED about their org or jurisdiction. This signature
    gate closes that gap: each operator signs the canonical bytes of
    their own attestation with the same Ed25519 key they declare as
    `pubkey`. If they lie about org / jurisdiction / contact / node_id
    without re-signing, verification fails. If they re-sign, they have
    proven possession of the same key the cluster uses for cert
    signing — so the lie costs the same key compromise the rest of
    the protocol is already designed around.

    The exception's `.report` carries per-attestation verdicts.
    """

    def __init__(self, message: str, report: "OperatorSignatureReport"):
        super().__init__(message)
        self.report = report


class OperatorSigningUnavailable(RuntimeError):
    """Raised if the `cryptography` or `solders` package is missing
    when sig verification is attempted. Production wheels include
    both; this is only hit in stripped-down dev environments."""


# =============================================================================
# OperatorAttestation / OperatorManifest / Report
# =============================================================================

@dataclass(frozen=True, slots=True)
class OperatorAttestation:
    """
    One cluster operator's declaration of who they are.

    `node_id`        cluster-unique label (matches `NodeLocation.node_id`).
    `pubkey`         base58 Solana pubkey of the cluster member.
    `operator_org`   human-readable organisation name (e.g.
                     `"Phylanx Labs"`, `"Acme Validator Co"`).
    `operator_contact`  identity binding — PGP fingerprint or
                     contractually-recorded email. Opaque to the
                     gate; the external auditor verifies it.
    `jurisdiction`   ISO-3166 alpha-2 country code (`"US"`, `"DE"`,
                     `"SG"`). Two-letter code so the gate can apply
                     uniform validation.
    `compensation_model`  SEC-1 HARDENING: closed-enum string drawn
                     from `oracle.securities_compliance.
                     ALLOWED_COMPENSATION_MODELS`. Today the only
                     allowed value is
                     `"FLAT_FEE_PER_CERT_FROM_TREASURY"` — fixed per-
                     cert fee paid out of the treasury, NOT a
                     performance fee, NOT a token allocation that
                     tracks TVL, NOT a revenue share. Default empty
                     string means the attestation has not been
                     extended for SEC-1; the boot gate refuses it.
                     The diversity / signature gates ignore this
                     field, so diversity-only or sig-only tests can
                     omit it. Folded into
                     `attestation_canonical_bytes` so the OFAC-1 sig
                     binding extends to cover it — lying about
                     compensation costs the same key compromise the
                     rest of the protocol already assumes the
                     adversary cannot perform.
    `conflicts_disclosed`  SEC-1 HARDENING: tuple of
                     `ConflictDisclosure(rated_wallet,
                     relationship_type)` — financial relationships
                     between the operator and rated agent_wallets.
                     The cluster does NOT refuse to rate disclosed
                     wallets (legal posture for self-dealing is the
                     operator's, not the protocol's) but the
                     disclosure is sig-bound so it cannot be hidden
                     or retroactively edited. Default empty tuple
                     means "no disclosed conflicts". Folded into
                     `attestation_canonical_bytes`.
    `aml_program_attestation`  AML-1 HARDENING: closed-enum string
                     drawn from `oracle.aml_compliance.
                     ALLOWED_AML_ATTESTATIONS`. The operator
                     declares whether their Phylanx cluster
                     activity triggers BSA / PMLA / 5AMLD / MLR-
                     2017 / PSA / similar reporting-entity
                     registration. Today the allowed values are
                     `"NO_AML_PROGRAM_REQUIRED_FOR_PHYLANX_ACTIVITY"`
                     (default operator posture: observing public
                     on-chain data, no custody / transmission /
                     exchange) and `"EXTERNAL_AML_PROGRAM_DECLARED"`
                     (operator runs an AML program for an unrelated
                     business — disclosure only). Default empty
                     string means the attestation has not been
                     AML-1-extended; the boot gate refuses it. The
                     diversity / signature gates ignore this field,
                     so diversity-only or sig-only tests can omit
                     it. Folded into `attestation_canonical_bytes`
                     so the OFAC-1 sig binding extends to cover it
                     — lying about AML posture costs the same key
                     compromise the rest of the protocol already
                     assumes the adversary cannot perform.
    `signature`      OFAC-1 HARDENING: hex-encoded 64-byte Ed25519
                     signature over `attestation_canonical_bytes(self)`
                     produced by the SAME private key whose public
                     half is declared in `pubkey`. Empty string (the
                     default) means the attestation is unsigned —
                     `verify_attestation_signature` returns False and
                     the production boot gate refuses the manifest.
                     The diversity gate ignores this field, so
                     diversity-only tests can omit it. The sig binds
                     the operator's declaration of org / jurisdiction
                     / compensation / conflicts / AML posture to the
                     same key they sign certs with — lying about any
                     of those without re-signing fails the gate;
                     re-signing requires possession of the key and
                     therefore the lie costs the same key compromise
                     the rest of the protocol already assumes the
                     adversary cannot perform.
    """
    node_id:                  str
    pubkey:                   str
    operator_org:             str
    operator_contact:         str
    jurisdiction:             str
    compensation_model:       str = ""
    conflicts_disclosed:      tuple = ()
    aml_program_attestation:  str = ""
    signature:                str = ""


@dataclass(frozen=True, slots=True)
class OperatorManifest:
    """
    The full set of operator attestations + the cluster's threshold.

    `attestations`   tuple of per-node attestations.
    `threshold`      the K in K-of-N. HCR-4 refuses if any single
                     org owns ≥ threshold pubkeys.
    """
    attestations: tuple[OperatorAttestation, ...]
    threshold:    int


@dataclass(frozen=True, slots=True)
class OperatorDiversityReport:
    """
    One run of the HCR-4 check.

    `manifest`              the input manifest, echoed.
    `org_counts`            org name -> pubkey count.
    `jurisdiction_counts`   ISO code -> pubkey count.
    `largest_org`           org name with the most pubkeys.
    `largest_org_count`     how many pubkeys that org holds.
    """
    manifest:            OperatorManifest
    org_counts:          dict[str, int]
    jurisdiction_counts: dict[str, int]
    largest_org:         str
    largest_org_count:   int

    @property
    def distinct_orgs(self) -> int:
        return len(self.org_counts)

    @property
    def distinct_jurisdictions(self) -> int:
        return len(self.jurisdiction_counts)

    @property
    def is_diverse(self) -> bool:
        return (
            self.largest_org_count < self.manifest.threshold
            and self.distinct_orgs >= MIN_DISTINCT_OPERATORS
            and self.distinct_jurisdictions >= MIN_DISTINCT_JURISDICTIONS
        )


# =============================================================================
# Construction helper
# =============================================================================

def build_manifest(
    attestations: Sequence[OperatorAttestation],
    *,
    threshold:    int,
) -> OperatorManifest:
    """
    Validate the inputs and return an `OperatorManifest`. Construction
    is via this helper (rather than the dataclass directly) so the
    input-shape errors raise the typed `OperatorManifestError`.
    """
    if not attestations:
        raise OperatorManifestError("attestations must be non-empty")
    if threshold < 1:
        raise OperatorManifestError(
            f"threshold must be >= 1, got {threshold}",
        )
    if threshold > len(attestations):
        raise OperatorManifestError(
            f"threshold ({threshold}) cannot exceed attestation count "
            f"({len(attestations)})",
        )

    seen_ids:     set[str] = set()
    seen_pubkeys: set[str] = set()
    for a in attestations:
        for field_name, value in (
            ("node_id", a.node_id),
            ("pubkey", a.pubkey),
            ("operator_org", a.operator_org),
            ("operator_contact", a.operator_contact),
            ("jurisdiction", a.jurisdiction),
        ):
            if not value or not value.strip():
                raise OperatorManifestError(
                    f"attestation {a.node_id!r} has empty {field_name!r}",
                )
        if a.node_id in seen_ids:
            raise OperatorManifestError(
                f"duplicate node_id: {a.node_id!r}",
            )
        seen_ids.add(a.node_id)
        if a.pubkey in seen_pubkeys:
            raise OperatorManifestError(
                f"duplicate pubkey: {a.pubkey!r}",
            )
        seen_pubkeys.add(a.pubkey)

        if len(a.jurisdiction) != 2 or not a.jurisdiction.isalpha():
            raise OperatorManifestError(
                f"jurisdiction must be a 2-letter ISO-3166 code, got "
                f"{a.jurisdiction!r} for {a.node_id!r}",
            )

    return OperatorManifest(
        attestations=tuple(attestations),
        threshold=int(threshold),
    )


# =============================================================================
# The diversity gate
# =============================================================================

def verify_operator_diversity(
    manifest: OperatorManifest,
    *,
    min_distinct_orgs:           int = MIN_DISTINCT_OPERATORS,
    min_distinct_jurisdictions:  int = MIN_DISTINCT_JURISDICTIONS,
) -> OperatorDiversityReport:
    """
    Verify that the manifest's org / jurisdiction distribution
    survives the HCR-4 floors. Returns the report on success; raises
    `OperatorDiversityError` (with the report attached) on failure.

    The three floor checks:
      1. No single org owns ≥ `manifest.threshold` pubkeys — otherwise
         that org could unilaterally produce a valid threshold
         signature.
      2. At least `min_distinct_orgs` distinct orgs across the
         cluster.
      3. At least `min_distinct_jurisdictions` distinct ISO codes —
         a single legal-process compulsion cannot reach two
         unrelated jurisdictions simultaneously.
    """
    orgs   = Counter(a.operator_org.strip()   for a in manifest.attestations)
    jurs   = Counter(a.jurisdiction.upper()   for a in manifest.attestations)
    largest_org, largest_count = orgs.most_common(1)[0]

    report = OperatorDiversityReport(
        manifest=manifest,
        org_counts=dict(orgs),
        jurisdiction_counts=dict(jurs),
        largest_org=largest_org,
        largest_org_count=largest_count,
    )

    if largest_count >= manifest.threshold:
        raise OperatorDiversityError(
            f"HCR-4: organisation {largest_org!r} controls {largest_count} "
            f"of {len(manifest.attestations)} cluster pubkeys (threshold "
            f"is {manifest.threshold}). A single org meeting the threshold "
            f"unilaterally collapses the M-of-N guarantee. "
            f"Per-org tally: {dict(orgs)!r}. Recruit at least one operator "
            f"from a separate organisation before redeploy.",
            report,
        )
    if report.distinct_orgs < min_distinct_orgs:
        raise OperatorDiversityError(
            f"HCR-4: only {report.distinct_orgs} distinct operator org(s) "
            f"across {len(manifest.attestations)} pubkeys (need at least "
            f"{min_distinct_orgs}).",
            report,
        )
    if report.distinct_jurisdictions < min_distinct_jurisdictions:
        raise OperatorDiversityError(
            f"HCR-4: only {report.distinct_jurisdictions} distinct "
            f"jurisdiction(s) across {len(manifest.attestations)} "
            f"operators (need at least {min_distinct_jurisdictions}). "
            f"Per-jurisdiction tally: {dict(jurs)!r}. A single "
            f"legal-process compulsion in one jurisdiction reaches every "
            f"operator simultaneously.",
            report,
        )
    return report


# =============================================================================
# OFAC-1 HARDENING — operator attestation cryptographic binding
# =============================================================================
#
# The diversity gate above checks only what the manifest DECLARES. An
# operator who lies — running Org A's node while attesting as Org B in
# jurisdiction SG when they are physically in US — defeats HCR-4 without
# breaking it. The external auditor catches this in retrospect, but not
# at boot.
#
# The sig binding closes that gap: each operator signs their own
# attestation with the SAME Ed25519 private key whose public half they
# declare as `pubkey`. The same key signs certs in production, so
# lying about jurisdiction now costs the operator the same private key
# the rest of the protocol assumes the adversary cannot exfiltrate.
#
# Canonical bytes are intentionally NOT JSON — JSON encoders disagree
# on whitespace, key order, and Unicode normalisation across versions
# and languages. A pipe-separated UTF-8 byte string is unambiguous,
# stable across hosts, and trivially reproducible in any language an
# operator might use to sign offline.

#: Canonical sig-binding prefix. Folded into the signed bytes so a sig
#: generated for one domain (e.g. cert-payload) can never be replayed
#: against an attestation, and vice-versa. Bump the version suffix if
#: the canonical format ever changes.
ATTESTATION_DOMAIN_TAG = b"phylanx.operator_attestation.v1"


def attestation_canonical_bytes(att: OperatorAttestation) -> bytes:
    """
    The canonical bytes the operator signs to bind their attestation.

    Format::

        ATTESTATION_DOMAIN_TAG
        |node_id|pubkey|operator_org|operator_contact|jurisdiction
        |compensation_model|<canonical conflicts string>
        |aml_program_attestation

    Joined with the ASCII `|` byte. UTF-8 encoded. Deterministic — two
    callers given the same attestation produce byte-identical output.

    `signature` is NOT included (you cannot sign over your own
    signature). Every OTHER declared field IS included, so a lie about
    any of them invalidates the sig.

    SEC-1 / AML-1 NOTE: the trailing three fields (compensation_model
    + the canonical conflicts string + aml_program_attestation) are
    always present, even if empty — omitting them on legacy
    attestations would let an adversary silently strip a sig-binding
    boundary by downgrading.
    """
    # SEC-1: import lazily to avoid a hard cycle. The conflicts list
    # is rendered via the canonical helper in `securities_compliance`
    # so the canonical bytes (signed by the operator) and the audit
    # gate (inspecting the same conflicts later) agree byte-for-byte.
    from oracle.securities_compliance import serialize_conflicts

    pieces = (
        att.node_id,
        att.pubkey,
        att.operator_org,
        att.operator_contact,
        att.jurisdiction,
        att.compensation_model,
        serialize_conflicts(att.conflicts_disclosed),
        att.aml_program_attestation,
    )
    body = "|".join(pieces).encode("utf-8")
    return ATTESTATION_DOMAIN_TAG + b"|" + body


def _decode_pubkey_bytes(pubkey: str) -> bytes:
    """Decode a base58 Solana pubkey to its raw 32 bytes via solders."""
    if not _SOLDERS_AVAILABLE:                              # pragma: no cover
        raise OperatorSigningUnavailable(
            "operator sig verification needs the 'solders' package for "
            "base58 pubkey decoding"
        )
    return bytes(_SoldersPubkey.from_string(pubkey))


def verify_attestation_signature(att: OperatorAttestation) -> bool:
    """
    Verify the operator's Ed25519 sig over `attestation_canonical_bytes(att)`.

    Returns True iff:
      * `att.signature` is a hex string of exactly 64 bytes.
      * `att.pubkey` is a valid base58 Solana pubkey (32 bytes).
      * `Ed25519PublicKey(pubkey_bytes).verify(sig_bytes, canonical)`
        succeeds.

    Returns False on ANY of: empty signature, malformed hex, wrong sig
    length, malformed pubkey, verification failure. Never raises for a
    bad signature — only `OperatorSigningUnavailable` if the crypto
    backend is missing (stripped dev env).
    """
    if not _ED25519_AVAILABLE:                              # pragma: no cover
        raise OperatorSigningUnavailable(
            "operator sig verification needs the 'cryptography' package"
        )
    if not att.signature:
        return False
    try:
        sig_bytes = bytes.fromhex(att.signature)
    except ValueError:
        return False
    if len(sig_bytes) != 64:
        return False
    try:
        pubkey_bytes = _decode_pubkey_bytes(att.pubkey)
    except (ValueError, Exception):                         # noqa: BLE001
        # solders raises a plain ValueError on bad base58 — and historic
        # builds have surfaced other errors. Treat all as verification
        # failure rather than letting them surface as runtime crashes.
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pubkey_bytes).verify(
            sig_bytes, attestation_canonical_bytes(att),
        )
        return True
    except Exception:                                       # noqa: BLE001
        return False


@dataclass(frozen=True, slots=True)
class OperatorSignatureReport:
    """
    One run of the operator-signature gate.

    `verdicts`   tuple of (node_id, ok) pairs in input order. Ordered
                 so the report is deterministic across two operators
                 running the gate on the same manifest.
    """
    verdicts: tuple[tuple[str, bool], ...] = field(default_factory=tuple)

    @property
    def all_signed(self) -> bool:
        return all(ok for _, ok in self.verdicts)

    @property
    def failed_node_ids(self) -> tuple[str, ...]:
        return tuple(node_id for node_id, ok in self.verdicts if not ok)


def verify_attestation_signatures(
    manifest: OperatorManifest,
) -> OperatorSignatureReport:
    """
    Verify every attestation in the manifest carries a valid sig from
    its declared pubkey. Returns the report on full-pass; raises
    `OperatorSignatureError` (with the report attached) on any failure.

    This is the production boot gate. Tests that only care about
    diversity (no real keypairs) skip this and call
    `verify_operator_diversity` alone.
    """
    verdicts = tuple(
        (a.node_id, verify_attestation_signature(a))
        for a in manifest.attestations
    )
    report = OperatorSignatureReport(verdicts=verdicts)
    if report.all_signed:
        return report
    raise OperatorSignatureError(
        f"HCR-4 sig binding: {len(report.failed_node_ids)} of "
        f"{len(manifest.attestations)} operator attestation(s) FAILED "
        f"signature verification: {list(report.failed_node_ids)!r}. "
        f"Either the attestation was never signed (empty `signature` "
        f"field) or the operator lied about their declared fields "
        f"without re-signing. Re-issue the manifest with each operator "
        f"re-signing `attestation_canonical_bytes(att)` with the "
        f"SAME private key whose public half is in `att.pubkey`, then "
        f"redeploy.",
        report,
    )


__all__ = [
    "ATTESTATION_DOMAIN_TAG",
    "MIN_DISTINCT_JURISDICTIONS",
    "MIN_DISTINCT_OPERATORS",
    "OperatorAttestation",
    "OperatorDiversityError",
    "OperatorDiversityReport",
    "OperatorManifest",
    "OperatorManifestError",
    "OperatorSignatureError",
    "OperatorSignatureReport",
    "OperatorSigningUnavailable",
    "attestation_canonical_bytes",
    "build_manifest",
    "verify_attestation_signature",
    "verify_attestation_signatures",
    "verify_operator_diversity",
]
