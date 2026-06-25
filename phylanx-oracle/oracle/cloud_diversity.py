"""
oracle/cloud_diversity.py — NSS-1: cluster cloud-provider compute-diversity gate.

THE CATASTROPHIC FAILURE SCENARIO (audit Scenario B — Nation-State Silent Subversion)
-------------------------------------------------------------------------------------
    "A nation-state actor compromises a cloud provider hosting the
    oracle nodes, installs a kernel module that intercepts signing
    calls, and walks away with 3 cluster private keys — enough to
    forge any cert for any agent."

The cluster's HCR mitigations close some of the substrate, but NOT
this one:

  HCR-1  protects against RPC PROVIDER monoculture (all five nodes
         reading Helius RPCs is refused).
  HCR-2  protects against REGION monoculture (all five nodes in
         `aws:us-east-1` is refused).
  HCR-4  protects against ORG monoculture (one operator holding ≥ K
         pubkeys is refused).

A cluster passing all three is STILL exposed to this attack if every
node happens to run on AWS (different regions, different orgs). A
nation-state with a relationship to one cloud provider gets root on
every host at once — the HCR-2 region label `"aws:us-east-1"` vs
`"aws:eu-central-1"` is a DIFFERENT FAULT DOMAIN to AWS's network
team but the SAME FAULT DOMAIN to a state actor with a court order
to AWS's hypervisor.

THE MITIGATION (this file)
--------------------------
Reify the cloud-compute diversity contract: each operator declares
their node's cloud provider (extracted from the region label or
declared separately), and the cluster gate refuses any topology where
one cloud provider hosts more nodes than the K-of-N threshold can
tolerate.

  * `classify_cloud_provider(region)` — pure-stdlib provider extractor.
    Known provider names bucket as themselves; unknown labels bucket
    as `"unknown:<label>"` (strictly conservative: a typo cannot
    silently merge two providers).
  * `verify_cloud_diversity(nodes, *, threshold)` — refuses any
    topology where `max_per_cloud > N - K` OR where
    `distinct_clouds < MIN_DISTINCT_CLOUD_PROVIDERS`.
  * Raises `CloudDiversityError` (with the per-provider tally
    attached) on violation.

The math mirrors HCR-2: for an N-node, K-of-N cluster, losing every
node hosted by one cloud provider must leave at least K honest nodes
alive. For the canonical 3-of-5 cluster: max_per_cloud = N − K = 2.
Three nodes on AWS is a NSS-1 violation EVEN IF they span three
distinct AWS regions (HCR-2 green) AND three distinct orgs (HCR-4
green).

DETERMINISM
-----------
Pure stdlib (`collections.Counter`). The cloud-provider table is a
small, audited tuple. Two operators running the gate on the same
manifest produce byte-identical reports.

INTERACTION WITH HCR-1 / HCR-2 / HCR-4 / NSS-2
----------------------------------------------
HCR-1 = RPC PROVIDER (data-input substrate). NSS-1 = CLOUD COMPUTE
(host substrate). Both are "providers" of different services. A
cluster reading from 3 distinct RPC providers but running on 1 cloud
provider has 1 cloud kill-switch and 3 data kill-switches: an
asymmetric defence.

NSS-1 catches the substrate of the attack; NSS-2
(`signer_enforcement.py`) catches the OPERATIONAL step where the
cluster boots with `InProcessSigner` on mainnet. The two are paired:
even with full cloud diversity, an `InProcessSigner` can be
exfiltrated by a kernel module on ANY of the diverse clouds — so NSS-2
is the second leg of defence-in-depth.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

#: Known cloud-provider tokens. The classifier returns one of these
#: when the operator's region label prefixes match (`aws:*`, `gcp:*`,
#: ...). The bucket name MUST be the lowercase prefix — the table is
#: lookup-only, no normalisation, no aliasing. Adding a provider is a
#: deliberate act; an alias should NOT be added without auditing the
#: existing manifest deploys.
#:
#: Order is not load-bearing; the tuple makes the table immutable.
KNOWN_CLOUD_PROVIDERS = (
    "aws",
    "gcp",
    "azure",
    "oci",            # Oracle Cloud Infrastructure
    "ibm",            # IBM Cloud
    "alibaba",
    "tencent",
    "hetzner",
    "ovh",
    "digitalocean",
    "vultr",
    "linode",
    "scaleway",
    "fly",
    "self-hosted",    # operator-run hardware in their own facility
    "bare-metal",     # colo / non-virtualised
)

#: Hard floor on distinct cloud providers across the cluster. Two is
#: the minimum for ANY cluster larger than 1 node — a single-cloud
#: cluster is a one-provider kill-switch, no matter how many nodes it
#: has.
MIN_DISTINCT_CLOUD_PROVIDERS = 2

#: Mirrors `region_diversity.DEFAULT_CLUSTER_*` so callers can derive
#: `max_per_cloud = N - K` for the canonical 3-of-5 default.
DEFAULT_CLUSTER_SIZE = 5
DEFAULT_CLUSTER_THRESHOLD = 3


# =============================================================================
# Errors
# =============================================================================

class CloudDiversityError(RuntimeError):
    """
    Raised when a cluster topology violates NSS-1 — one cloud provider
    hosts too many nodes, OR fewer than `MIN_DISTINCT_CLOUD_PROVIDERS`
    distinct providers are represented.

    The exception's `.report` carries the per-provider tally so the
    operator can see WHICH provider over-concentrated.
    """

    def __init__(self, message: str, report: "CloudDiversityReport"):
        super().__init__(message)
        self.report = report


# =============================================================================
# Records
# =============================================================================

@dataclass(frozen=True, slots=True)
class NodeCloud:
    """
    One cluster operator's declaration of where their node's COMPUTE
    runs.

    `node_id`         cluster-unique label (matches HCR-2's NodeLocation).
    `cloud_provider`  the provider bucket the operator declares (e.g.
                      `"aws"`, `"gcp"`, `"self-hosted"`). Must be one
                      of `KNOWN_CLOUD_PROVIDERS` or it is treated as
                      its own `unknown:<label>` bucket — strict so a
                      typo cannot silently aggregate.
    """
    node_id:        str
    cloud_provider: str


@dataclass(frozen=True, slots=True)
class CloudDiversityReport:
    """
    Result of one NSS-1 diversity check.

    `nodes`                  the input declarations, in input order.
    `cloud_counts`           provider bucket -> node count.
    `threshold`              the K passed to the check.
    `max_nodes_per_cloud`    the computed `N - K` cap.
    `largest_cloud`          the provider with the most nodes.
    `largest_cloud_count`    how many nodes that provider hosts.
    `distinct_clouds`        number of distinct provider buckets.
    """
    nodes:                tuple[NodeCloud, ...]
    cloud_counts:         dict[str, int]
    threshold:            int
    max_nodes_per_cloud:  int
    largest_cloud:        str
    largest_cloud_count:  int
    distinct_clouds:      int

    @property
    def is_diverse(self) -> bool:
        return (
            self.largest_cloud_count <= self.max_nodes_per_cloud
            and self.distinct_clouds >= MIN_DISTINCT_CLOUD_PROVIDERS
        )


# =============================================================================
# Classifier
# =============================================================================

def classify_cloud_provider(label: str) -> str:
    """
    Bucket a free-form provider/region label into one of the
    `KNOWN_CLOUD_PROVIDERS`, or `"unknown:<label>"` on no match.

    Accepts either a provider-only label (`"aws"`) or a region label
    of the form `<provider>:<region>` (`"aws:us-east-1"`). The match is
    on the leading provider token, case-insensitive, with leading and
    trailing whitespace stripped.

    Unknown labels return `"unknown:<lowercased-stripped-label>"` so
    two distinct unknown labels never collide. This is conservative by
    design: a typo (`"aws-2"`) yields a different bucket from `"aws"`,
    so a misconfigured manifest CANNOT pretend to be diverse by
    accident.
    """
    if not isinstance(label, str):
        raise TypeError(
            f"NSS-1: cloud-provider label must be a string, got "
            f"{type(label).__name__}"
        )
    raw = label.strip().lower()
    if not raw:
        return "unknown:"
    head = raw.split(":", 1)[0].strip()
    if head in KNOWN_CLOUD_PROVIDERS:
        return head
    return f"unknown:{raw}"


# =============================================================================
# Diversity gate
# =============================================================================

def verify_cloud_diversity(
    nodes:               Sequence[NodeCloud],
    *,
    threshold:           int = DEFAULT_CLUSTER_THRESHOLD,
    min_distinct_clouds: int = MIN_DISTINCT_CLOUD_PROVIDERS,
) -> CloudDiversityReport:
    """
    Verify that the cluster's cloud-provider topology survives a
    single-provider compromise. Returns the report on success; raises
    `CloudDiversityError` (with the report attached) on failure.

    Parameters
    ----------
    nodes
        The per-node `NodeCloud` declarations. Order does not matter
        for the check; it is preserved in the report.
    threshold
        The K in K-of-N. The per-cloud cap is `len(nodes) - threshold`
        — i.e., losing all nodes hosted by any one cloud provider must
        leave at least K alive.
    min_distinct_clouds
        Floor on distinct provider buckets. Default
        `MIN_DISTINCT_CLOUD_PROVIDERS = 2`.

    Raises
    ------
    CloudDiversityError
        If one provider hosts more than `len(nodes) - threshold`
        nodes, OR if the topology spans fewer than
        `min_distinct_clouds` distinct provider buckets.
    """
    if not nodes:
        raise CloudDiversityError(
            "NSS-1: nodes must be non-empty",
            _empty_report(threshold),
        )
    if threshold < 1:
        raise CloudDiversityError(
            f"NSS-1: threshold must be >= 1, got {threshold}",
            _empty_report(threshold),
        )
    if threshold > len(nodes):
        raise CloudDiversityError(
            f"NSS-1: threshold ({threshold}) cannot exceed node count "
            f"({len(nodes)})",
            _empty_report(threshold),
        )

    seen_ids: set[str] = set()
    buckets: list[str] = []
    for n in nodes:
        if n.node_id in seen_ids:
            raise CloudDiversityError(
                f"NSS-1: duplicate node_id {n.node_id!r} — every "
                f"cluster member must declare a unique label",
                _empty_report(threshold),
            )
        seen_ids.add(n.node_id)
        if not n.cloud_provider.strip():
            raise CloudDiversityError(
                f"NSS-1: node {n.node_id!r} has an empty cloud provider "
                f"— operator must declare the compute substrate",
                _empty_report(threshold),
            )
        buckets.append(classify_cloud_provider(n.cloud_provider))

    counts = Counter(buckets)
    largest_cloud, largest_count = counts.most_common(1)[0]
    distinct = len(counts)
    max_per_cloud = len(nodes) - threshold

    report = CloudDiversityReport(
        nodes=tuple(nodes),
        cloud_counts=dict(counts),
        threshold=threshold,
        max_nodes_per_cloud=max_per_cloud,
        largest_cloud=largest_cloud,
        largest_cloud_count=largest_count,
        distinct_clouds=distinct,
    )

    if largest_count > max_per_cloud:
        raise CloudDiversityError(
            f"NSS-1: cloud provider {largest_cloud!r} hosts "
            f"{largest_count} of {len(nodes)} cluster nodes; max is "
            f"{max_per_cloud} for a {threshold}-of-{len(nodes)} "
            f"threshold (losing the provider must leave at least "
            f"{threshold} nodes alive). Per-cloud tally: "
            f"{dict(counts)!r}. Re-locate at least "
            f"{largest_count - max_per_cloud} node(s) off "
            f"{largest_cloud!r} before retrying.",
            report,
        )
    if distinct < min_distinct_clouds:
        raise CloudDiversityError(
            f"NSS-1: only {distinct} distinct cloud provider(s) across "
            f"{len(nodes)} nodes (need at least {min_distinct_clouds}). "
            f"A nation-state with a court order to {largest_cloud!r} "
            f"would compromise the cluster simultaneously. Per-cloud "
            f"tally: {dict(counts)!r}.",
            report,
        )
    return report


def _empty_report(threshold: int) -> CloudDiversityReport:
    return CloudDiversityReport(
        nodes=(),
        cloud_counts={},
        threshold=threshold,
        max_nodes_per_cloud=0,
        largest_cloud="",
        largest_cloud_count=0,
        distinct_clouds=0,
    )


__all__ = [
    "DEFAULT_CLUSTER_SIZE",
    "DEFAULT_CLUSTER_THRESHOLD",
    "KNOWN_CLOUD_PROVIDERS",
    "MIN_DISTINCT_CLOUD_PROVIDERS",
    "CloudDiversityError",
    "CloudDiversityReport",
    "NodeCloud",
    "classify_cloud_provider",
    "verify_cloud_diversity",
]
