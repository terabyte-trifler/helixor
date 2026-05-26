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
from dataclasses import dataclass


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
                     `"Helixor Labs"`, `"Acme Validator Co"`).
    `operator_contact`  identity binding — PGP fingerprint or
                     contractually-recorded email. Opaque to the
                     gate; the external auditor verifies it.
    `jurisdiction`   ISO-3166 alpha-2 country code (`"US"`, `"DE"`,
                     `"SG"`). Two-letter code so the gate can apply
                     uniform validation.
    """
    node_id:          str
    pubkey:           str
    operator_org:     str
    operator_contact: str
    jurisdiction:     str


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


__all__ = [
    "MIN_DISTINCT_JURISDICTIONS",
    "MIN_DISTINCT_OPERATORS",
    "OperatorAttestation",
    "OperatorDiversityError",
    "OperatorDiversityReport",
    "OperatorManifest",
    "OperatorManifestError",
    "build_manifest",
    "verify_operator_diversity",
]
