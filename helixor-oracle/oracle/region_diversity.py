"""
oracle/region_diversity.py — HCR-2: cluster region diversity gate.

THE HIDDEN CENTRALIZATION RISK (audit)
--------------------------------------
    "If all oracle nodes and the database are in the same AWS region,
    a regional outage (AZ failure, network partition) takes down the
    whole system."

The 3-of-5 cluster threshold (`scoring/composite.py` + the on-chain
`advance_epoch` handler) is the math of fault tolerance. It assumes
node faults are INDEPENDENT. Co-locating all five nodes in one AWS
region turns the threshold from "any two nodes can fail" into "any
two correlated incidents in one region take the whole cluster down" —
the threshold's protection collapses to the region's MTBF, not the
node's.

THE MITIGATION (this file)
--------------------------
Every cluster operator declares its node's region in a
`NodeLocation` record. The cluster topology manifest is a tuple of
those records. `verify_region_diversity(nodes, threshold=K)` refuses
any topology where ONE region's failure would drop the live-node
count below `K`.

The math: for an N-of-N topology with K-of-N threshold, losing all
nodes in one region must leave AT LEAST K nodes alive elsewhere.
That is, no region may hold MORE than `N - K` nodes.

For the canonical 3-of-5 cluster:
  - N = 5, K = 3
  - max_nodes_per_region = N - K = 2
  - so 3 regions of {2, 2, 1} works; 2 regions of {3, 2} does NOT.

The check is PURE TOPOLOGY — it does not call AWS, GCP, or anyone's
metadata service. The operator's declaration is the input. The
operator-attestation manifest (HCR-4) is the chain of custody for
those declarations.

DETERMINISM
-----------
Pure stdlib (`collections.Counter`). No network, no clock, no
randomness. Two operators running the gate on the same manifest
produce byte-identical reports.

INTERACTION WITH HCR-1 / HCR-4
------------------------------
HCR-1 protects against PROVIDER monoculture; HCR-2 protects against
REGION monoculture; HCR-4 protects against ORG monoculture. All
three are necessary: an attacker who collapses any one axis
(provider, region, operator) gets a one-incident kill on the
cluster. A cluster that passes all three has independent fault
domains on every axis.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

#: The reference mainnet cluster topology: 5 nodes, 3-of-5 threshold.
#: The HCR-2 floor (`max_nodes_per_region = N - K = 2`) is computed
#: from these.
DEFAULT_CLUSTER_SIZE = 5
DEFAULT_CLUSTER_THRESHOLD = 3

#: HCR-2 also requires at least this many distinct regions across the
#: cluster — a 3-of-5 with two regions of {3, 2} satisfies the
#: per-region cap (max 2 per region is violated by the 3) so this is
#: technically redundant for the canonical config, but the floor is
#: pinned explicitly so a 4-of-7 cluster with regions {2, 2, 2, 1}
#: cannot degrade to {2, 2, 2, 1} -> {4, 3} via a "consolidation."
MIN_DISTINCT_REGIONS = 2


# =============================================================================
# Errors
# =============================================================================

class RegionDiversityError(RuntimeError):
    """
    Raised when a cluster topology violates HCR-2 — one region holds
    too many nodes, or the topology lists fewer distinct regions than
    `MIN_DISTINCT_REGIONS`.

    The exception's `.report` carries the per-region tally so the
    operator can see WHICH region over-concentrated.
    """

    def __init__(self, message: str, report: "RegionDiversityReport"):
        super().__init__(message)
        self.report = report


# =============================================================================
# NodeLocation / RegionDiversityReport
# =============================================================================

@dataclass(frozen=True, slots=True)
class NodeLocation:
    """
    One cluster operator's declaration of where their node runs.

    `node_id`    cluster-unique label (e.g. `"oracle-node-0"`).
    `region`     coarse failure-domain label (e.g. `"aws:us-east-1"`,
                 `"gcp:europe-west-2"`, `"hetzner:fsn1"`). The label
                 string is opaque to the gate — what matters is that
                 distinct strings mean distinct fault domains.
    """
    node_id: str
    region:  str


@dataclass(frozen=True, slots=True)
class RegionDiversityReport:
    """
    Result of one diversity check.

    `nodes`                  the input declarations, in input order.
    `region_counts`          region label -> node count.
    `threshold`              the K passed to the check.
    `max_nodes_per_region`   the computed `N - K` cap.
    `largest_region`         the region with the most nodes.
    `largest_region_count`   how many nodes that region holds.
    `distinct_regions`       number of distinct region labels.
    """
    nodes:                tuple[NodeLocation, ...]
    region_counts:        Mapping_str_int
    threshold:            int
    max_nodes_per_region: int
    largest_region:       str
    largest_region_count: int
    distinct_regions:     int

    @property
    def is_diverse(self) -> bool:
        return (
            self.largest_region_count <= self.max_nodes_per_region
            and self.distinct_regions >= MIN_DISTINCT_REGIONS
        )


# Forward-decl alias so the dataclass field type stays readable.
Mapping_str_int = dict[str, int]


# =============================================================================
# Diversity gate
# =============================================================================

def verify_region_diversity(
    nodes:           Sequence[NodeLocation],
    *,
    threshold:       int = DEFAULT_CLUSTER_THRESHOLD,
    min_distinct_regions: int = MIN_DISTINCT_REGIONS,
) -> RegionDiversityReport:
    """
    Verify that the cluster's region topology survives a single-region
    failure. Returns the report on success; raises
    `RegionDiversityError` (with the report attached) on failure.

    Parameters
    ----------
    nodes
        The per-node `NodeLocation` declarations. Order does not
        matter for the check; it is preserved in the report.
    threshold
        The K in K-of-N. The per-region cap is `len(nodes) - threshold`
        — i.e., losing all nodes in any one region must leave at least
        K alive.
    min_distinct_regions
        Floor on the number of distinct region labels across the
        cluster. Default `MIN_DISTINCT_REGIONS = 2`.

    Raises
    ------
    RegionDiversityError
        If a region holds more than `len(nodes) - threshold` nodes,
        OR if the topology spans fewer than `min_distinct_regions`
        distinct regions.
    """
    if not nodes:
        raise RegionDiversityError(
            "HCR-2: nodes must be non-empty",
            _empty_report(threshold, min_distinct_regions),
        )
    if threshold < 1:
        raise RegionDiversityError(
            f"HCR-2: threshold must be >= 1, got {threshold}",
            _empty_report(threshold, min_distinct_regions),
        )
    if threshold > len(nodes):
        raise RegionDiversityError(
            f"HCR-2: threshold ({threshold}) cannot exceed node count "
            f"({len(nodes)})",
            _empty_report(threshold, min_distinct_regions),
        )

    seen_ids: set[str] = set()
    for n in nodes:
        if n.node_id in seen_ids:
            raise RegionDiversityError(
                f"HCR-2: duplicate node_id {n.node_id!r} in topology — "
                f"every cluster member must have a unique label",
                _empty_report(threshold, min_distinct_regions),
            )
        seen_ids.add(n.node_id)
        if not n.region.strip():
            raise RegionDiversityError(
                f"HCR-2: node {n.node_id!r} has an empty region label — "
                f"the operator must declare an explicit fault domain",
                _empty_report(threshold, min_distinct_regions),
            )

    counts = Counter(n.region for n in nodes)
    largest_region, largest_count = counts.most_common(1)[0]
    distinct = len(counts)
    max_per_region = len(nodes) - threshold

    report = RegionDiversityReport(
        nodes=tuple(nodes),
        region_counts=dict(counts),
        threshold=threshold,
        max_nodes_per_region=max_per_region,
        largest_region=largest_region,
        largest_region_count=largest_count,
        distinct_regions=distinct,
    )

    if largest_count > max_per_region:
        raise RegionDiversityError(
            f"HCR-2: region {largest_region!r} holds {largest_count} of "
            f"{len(nodes)} cluster nodes; max is {max_per_region} for a "
            f"{threshold}-of-{len(nodes)} threshold (losing the region "
            f"must leave at least {threshold} nodes alive). "
            f"Per-region tally: {dict(counts)!r}. Re-locate at least "
            f"{largest_count - max_per_region} node(s) out of "
            f"{largest_region!r} before retrying.",
            report,
        )
    if distinct < min_distinct_regions:
        raise RegionDiversityError(
            f"HCR-2: only {distinct} distinct region(s) across "
            f"{len(nodes)} nodes (need at least {min_distinct_regions}). "
            f"A regional outage would take the cluster down. Per-region "
            f"tally: {dict(counts)!r}.",
            report,
        )
    return report


def _empty_report(threshold: int, min_distinct_regions: int) -> RegionDiversityReport:
    return RegionDiversityReport(
        nodes=(),
        region_counts={},
        threshold=threshold,
        max_nodes_per_region=0,
        largest_region="",
        largest_region_count=0,
        distinct_regions=0,
    )


__all__ = [
    "DEFAULT_CLUSTER_SIZE",
    "DEFAULT_CLUSTER_THRESHOLD",
    "MIN_DISTINCT_REGIONS",
    "NodeLocation",
    "RegionDiversityError",
    "RegionDiversityReport",
    "verify_region_diversity",
]
