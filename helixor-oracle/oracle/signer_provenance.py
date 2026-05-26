"""
oracle/signer_provenance.py — FHS-2: per-signer provenance attestation
gate for red-team Path 1 sub-leaf 1b ("Exploit VULN-01 signature
verification bypass").

THE ATTACK PATH (Forge-High-Score-Cert Path 1, sub-leaf 1b)
-----------------------------------------------------------
VULN-01 is the signature-verification bypass family. The on-chain
defence (`certificate-issuer/src/signing.rs::verify_threshold_signatures`)
ALREADY refuses (a) duplicate signers, (b) non-canonical S values,
(c) signatures over the wrong digest, (d) batch-verify primitives,
(e) signers outside the cluster set. VULN-21's strictness sweep
mechanically enforces those properties at the source-tree layer.

What none of those defences see is the PROVENANCE of the K signers:
an attacker who compromises ONE physical host running TWO of the
cluster's HSMs (e.g. the same operator runs node-0 and node-1 on
sibling EC2 instances sharing a hypervisor) can pass every on-chain
check — the signatures are over the canonical digest, signed by two
distinct cluster pubkeys, both canonical S, no duplicates — yet
violate the SPIRIT of the K-of-N threshold: only ONE physical
machine actually attested.

FHS-2 closes that substrate. Every cluster signer carries an
operator-attested provenance label `(host_id, cloud_region)` that
ships alongside the signature. The verifier refuses a threshold set
if any two signers share `host_id` OR if more than
`MAX_SIGNERS_PER_REGION = 2` signers live in the same cloud region
(matching NSS-1's per-cloud cap of N - K = 2 for a 3-of-5 cluster).
Missing attestations are refused outright: an attacker who can't
produce the provenance metadata defaults closed.

CALIBRATION
-----------
- `MAX_SIGNERS_PER_HOST = 1` — no two cluster signers may share a
  `host_id`. A duplicate host is structurally impossible for a
  legitimate 5-node cluster and is a hard refusal.
- `MAX_SIGNERS_PER_REGION = 2` — at most two signatures from any
  single cloud region. This mirrors NSS-1's per-cloud cap of
  N - K = 5 - 3 = 2: a captured single region cannot dominate the
  threshold even if all its nodes signed.
- `MIN_DISTINCT_HOSTS = 3` — the threshold itself. For a 3-of-5
  cluster the verifier rejects any set of K signatures that does
  not come from K distinct hosts.

INTERACTION WITH NSS-1 / NSS-2 / VULN-01 / VULN-21
--------------------------------------------------
- NSS-1 (`cloud_diversity.py`) refuses to BOOT a cluster whose
  static topology concentrates on one cloud — this module enforces
  the same property AT SIGNATURE TIME against the actual K signers
  that produced a given certificate.
- NSS-2 (`signer_enforcement.py`) refuses in-process Ed25519 signers
  — this module assumes every signer is HSM-backed and enforces
  diversity OF THE HSMS.
- VULN-01's on-chain `verify_threshold_signatures` deduplicates by
  pubkey — this module deduplicates by physical host, catching the
  case where TWO cluster pubkeys live on the same HSM.
- VULN-21's strictness sweep ensures canonical-S and strict precompile
  semantics — this module is the provenance overlay, orthogonal to
  the canonical-S property.

DETERMINISM
-----------
Pure stdlib. Iterates K signatures, builds two dictionaries (host,
region) and applies inequality checks. No clock, no network, no
randomness.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

#: Maximum number of cluster signatures permitted from the same
#: physical host. 1 = no two signers may share a host.
MAX_SIGNERS_PER_HOST = 1

#: Maximum number of cluster signatures permitted from the same cloud
#: region. Mirrors NSS-1's per-cloud cap of N - K = 2.
MAX_SIGNERS_PER_REGION = 2

#: Minimum count of distinct physical hosts that must contribute to a
#: threshold set. Equal to the canonical threshold K for a 3-of-5
#: cluster. A captured smaller-host attack cannot meet this floor.
MIN_DISTINCT_HOSTS = 3

#: Status labels.
PROVENANCE_OK = "OK"
PROVENANCE_REFUSED = "REFUSED"

#: Reason codes.
REASON_SIGNERS_SHARE_HOST = "SIGNERS_SHARE_HOST"
REASON_SIGNERS_OVER_REGION_CAP = "SIGNERS_OVER_REGION_CAP"
REASON_INSUFFICIENT_DISTINCT_HOSTS = "INSUFFICIENT_DISTINCT_HOSTS"
REASON_MISSING_ATTESTATION = "MISSING_ATTESTATION"


# =============================================================================
# Errors
# =============================================================================

class SignerProvenanceError(RuntimeError):
    """
    Raised by `enforce_signer_provenance` when the set of K signatures
    backing a certificate violates the per-host / per-region
    diversity contract.

    `.report` carries the structured verdict (offending hosts /
    regions / signers without attestations) so the on-call operator
    can correlate against the cluster manifest.
    """

    def __init__(self, message: str, report: "SignerProvenanceReport"):
        super().__init__(message)
        self.report = report


# =============================================================================
# Records
# =============================================================================

@dataclass(frozen=True, slots=True)
class SignerAttestation:
    """
    Operator-attested provenance for one cluster signature.

    `signer_pubkey` stable base58 identity of the cluster signer.
    `host_id`       stable identifier of the physical machine running
                    the signer (HSM serial number, KMS key fingerprint,
                    bare-metal hostname). Empty / None indicates the
                    attestation is missing and the signature defaults
                    closed.
    `cloud_region`  stable region label (e.g. "aws:us-east-1",
                    "gcp:europe-west-4", "hetzner:fsn1"). Empty / None
                    is treated as missing.
    """
    signer_pubkey: str
    host_id:       str | None
    cloud_region:  str | None


@dataclass(frozen=True, slots=True)
class SignerProvenanceReport:
    """
    Verdict of one FHS-2 check.

    `status`                  PROVENANCE_OK / REFUSED.
    `host_counts`             how many signers each host produced.
    `region_counts`           how many signers each region produced.
    `distinct_hosts`          number of distinct host_ids (excluding
                              missing attestations).
    `missing_attestation`     pubkeys whose host_id or region was
                              missing.
    `over_host_cap_hosts`     hosts whose signer count exceeded
                              MAX_SIGNERS_PER_HOST.
    `over_region_cap_regions` regions whose signer count exceeded
                              MAX_SIGNERS_PER_REGION.
    `min_distinct_hosts`      echoed from constants.
    `reasons`                 reason codes; empty when OK.
    """
    status:                   str
    host_counts:              tuple[tuple[str, int], ...]
    region_counts:            tuple[tuple[str, int], ...]
    distinct_hosts:           int
    missing_attestation:      tuple[str, ...]
    over_host_cap_hosts:      tuple[str, ...]
    over_region_cap_regions:  tuple[str, ...]
    min_distinct_hosts:       int
    reasons:                  tuple[str, ...]

    @property
    def is_allowed(self) -> bool:
        return self.status == PROVENANCE_OK


# =============================================================================
# Verifier (pure)
# =============================================================================

def verify_signer_provenance(
    attestations: tuple[SignerAttestation, ...] | list[SignerAttestation],
) -> SignerProvenanceReport:
    """
    Decide whether the K signers backing one cert respect the
    per-host / per-region diversity contract.

    The rule:
      * Any signer with missing `host_id` or `cloud_region` adds
        REASON_MISSING_ATTESTATION and the set is REFUSED.
      * Any `host_id` that appears > MAX_SIGNERS_PER_HOST times adds
        REASON_SIGNERS_SHARE_HOST and the set is REFUSED.
      * Any `cloud_region` that appears > MAX_SIGNERS_PER_REGION times
        adds REASON_SIGNERS_OVER_REGION_CAP and the set is REFUSED.
      * Distinct host count < MIN_DISTINCT_HOSTS (after excluding
        missing attestations) adds REASON_INSUFFICIENT_DISTINCT_HOSTS
        and the set is REFUSED.

    Pure: no logging, no environment reads, no I/O.
    """
    reasons: list[str] = []
    missing: list[str] = []
    host_counts: Counter[str] = Counter()
    region_counts: Counter[str] = Counter()

    for a in attestations:
        host = (a.host_id or "").strip()
        region = (a.cloud_region or "").strip()
        if not host or not region:
            missing.append(a.signer_pubkey)
            continue
        host_counts[host] += 1
        region_counts[region] += 1

    if missing:
        reasons.append(REASON_MISSING_ATTESTATION)

    over_host = tuple(
        h for h, c in host_counts.items() if c > MAX_SIGNERS_PER_HOST
    )
    if over_host:
        reasons.append(REASON_SIGNERS_SHARE_HOST)

    over_region = tuple(
        r for r, c in region_counts.items() if c > MAX_SIGNERS_PER_REGION
    )
    if over_region:
        reasons.append(REASON_SIGNERS_OVER_REGION_CAP)

    distinct_hosts = len(host_counts)
    if distinct_hosts < MIN_DISTINCT_HOSTS:
        reasons.append(REASON_INSUFFICIENT_DISTINCT_HOSTS)

    status = PROVENANCE_OK if not reasons else PROVENANCE_REFUSED

    return SignerProvenanceReport(
        status=status,
        host_counts=tuple(sorted(host_counts.items())),
        region_counts=tuple(sorted(region_counts.items())),
        distinct_hosts=distinct_hosts,
        missing_attestation=tuple(missing),
        over_host_cap_hosts=over_host,
        over_region_cap_regions=over_region,
        min_distinct_hosts=MIN_DISTINCT_HOSTS,
        reasons=tuple(reasons),
    )


# =============================================================================
# Enforcement (fail-closed wrapper)
# =============================================================================

def enforce_signer_provenance(
    attestations: tuple[SignerAttestation, ...] | list[SignerAttestation],
) -> SignerProvenanceReport:
    """
    Run `verify_signer_provenance` and raise on any violation.

    Returns the report when status == PROVENANCE_OK. Raises
    `SignerProvenanceError` otherwise — the cert produced by this
    threshold set must not be issued.
    """
    report = verify_signer_provenance(attestations)
    if report.is_allowed:
        return report
    raise SignerProvenanceError(
        f"FHS-2: signer provenance refused — "
        f"missing={list(report.missing_attestation)!r}, "
        f"over_host={list(report.over_host_cap_hosts)!r}, "
        f"over_region={list(report.over_region_cap_regions)!r}, "
        f"distinct_hosts={report.distinct_hosts}/"
        f"{report.min_distinct_hosts}, "
        f"reasons={list(report.reasons)!r}. "
        f"Threshold set does not honor the K-distinct-host "
        f"contract — a single compromised physical machine cannot "
        f"forge a K-of-N cert.",
        report,
    )


__all__ = [
    "MAX_SIGNERS_PER_HOST",
    "MAX_SIGNERS_PER_REGION",
    "MIN_DISTINCT_HOSTS",
    "PROVENANCE_OK",
    "PROVENANCE_REFUSED",
    "REASON_INSUFFICIENT_DISTINCT_HOSTS",
    "REASON_MISSING_ATTESTATION",
    "REASON_SIGNERS_OVER_REGION_CAP",
    "REASON_SIGNERS_SHARE_HOST",
    "SignerAttestation",
    "SignerProvenanceError",
    "SignerProvenanceReport",
    "enforce_signer_provenance",
    "verify_signer_provenance",
]
