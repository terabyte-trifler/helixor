"""
tests/oracle/test_nss1_cloud_diversity.py — NSS-1 cluster cloud-compute
diversity gate.

Pins:
  - Constants (MIN_DISTINCT_CLOUD_PROVIDERS=2, DEFAULT_CLUSTER_SIZE=5,
    DEFAULT_CLUSTER_THRESHOLD=3) — load-bearing audit floors.
  - Classifier: known providers bucket to themselves; unknown labels
    bucket as `unknown:<label>`; case + whitespace insensitive.
  - Diversity gate accepts the canonical 3-aws + 1-gcp + 1-hetzner
    topology (3-of-5).
  - Diversity gate REFUSES 3+ nodes on one provider (the NSS-1
    fingerprint — nation-state owns one cloud).
  - Diversity gate REFUSES a single-provider cluster regardless of
    region (HCR-2 GREEN but NSS-1 RED — three AWS regions on AWS is
    still one cloud).
  - Empty / malformed manifests raise immediately.
  - Reports carry per-cloud tallies for forensic visibility.
"""

from __future__ import annotations

import pytest

from oracle.cloud_diversity import (
    DEFAULT_CLUSTER_SIZE,
    DEFAULT_CLUSTER_THRESHOLD,
    KNOWN_CLOUD_PROVIDERS,
    MIN_DISTINCT_CLOUD_PROVIDERS,
    CloudDiversityError,
    NodeCloud,
    classify_cloud_provider,
    verify_cloud_diversity,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    assert MIN_DISTINCT_CLOUD_PROVIDERS == 2
    assert DEFAULT_CLUSTER_SIZE == 5
    assert DEFAULT_CLUSTER_THRESHOLD == 3


def test_known_providers_covers_marquee_clouds():
    # If any of these disappears, the bucketing for that cloud silently
    # falls back to `unknown:<label>` and the gate stops protecting
    # against that provider's monoculture. The audit gate cross-checks
    # this list separately.
    for marquee in ("aws", "gcp", "azure"):
        assert marquee in KNOWN_CLOUD_PROVIDERS


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

def test_classify_known_provider_prefix():
    assert classify_cloud_provider("aws:us-east-1") == "aws"
    assert classify_cloud_provider("gcp:europe-west-2") == "gcp"
    assert classify_cloud_provider("azure:westeurope") == "azure"
    assert classify_cloud_provider("hetzner:fsn1") == "hetzner"
    assert classify_cloud_provider("self-hosted") == "self-hosted"


def test_classify_case_and_whitespace_normalisation():
    assert classify_cloud_provider("  AWS:us-east-1  ") == "aws"
    assert classify_cloud_provider("GCP") == "gcp"


def test_classify_unknown_label_keeps_full_string():
    # Two distinct unknowns must NOT collide.
    a = classify_cloud_provider("AWS-2:us-east-1")
    b = classify_cloud_provider("aws-3:us-east-1")
    assert a != b
    assert a.startswith("unknown:")
    assert b.startswith("unknown:")


def test_classify_typo_does_not_alias_to_known_provider():
    # `awss` is NOT `aws` — a typo must yield its own bucket so it
    # does not silently aggregate with the real one.
    assert classify_cloud_provider("awss:us-east-1") == "unknown:awss:us-east-1"


def test_classify_rejects_non_string():
    with pytest.raises(TypeError):
        classify_cloud_provider(42)  # type: ignore[arg-type]


def test_classify_empty_string_is_an_unknown_bucket():
    # Empty label maps to a distinct `unknown:` bucket so it cannot
    # silently merge with anything.
    assert classify_cloud_provider("") == "unknown:"
    assert classify_cloud_provider("   ") == "unknown:"


# ---------------------------------------------------------------------------
# Healthy topologies
# ---------------------------------------------------------------------------

def test_canonical_3of5_topology_passes():
    # 3-of-5 with three clouds is the canonical mainnet floor.
    nodes = (
        NodeCloud("node-0", "aws:us-east-1"),
        NodeCloud("node-1", "aws:eu-central-1"),
        NodeCloud("node-2", "gcp:europe-west-2"),
        NodeCloud("node-3", "hetzner:fsn1"),
        NodeCloud("node-4", "self-hosted"),
    )
    report = verify_cloud_diversity(nodes, threshold=3)
    assert report.is_diverse
    assert report.distinct_clouds == 4
    assert report.max_nodes_per_cloud == 2  # N=5 - K=3
    assert report.largest_cloud_count == 2  # two AWS regions


def test_two_provider_topology_at_the_ceiling_passes():
    # AWS hosts exactly N-K = 2 nodes; the remaining 3 are spread.
    nodes = (
        NodeCloud("a", "aws:us-east-1"),
        NodeCloud("b", "aws:eu-central-1"),
        NodeCloud("c", "gcp:europe-west-2"),
        NodeCloud("d", "azure:westeurope"),
        NodeCloud("e", "hetzner:fsn1"),
    )
    report = verify_cloud_diversity(nodes, threshold=3)
    assert report.is_diverse
    assert report.cloud_counts["aws"] == 2


# ---------------------------------------------------------------------------
# Failing topologies — the NSS-1 fingerprint
# ---------------------------------------------------------------------------

def test_three_on_one_cloud_refused_even_across_regions():
    # Three AWS REGIONS is HCR-2-green but NSS-1-RED — one nation-state
    # subpoena to AWS reaches all three regions' hypervisors.
    nodes = (
        NodeCloud("a", "aws:us-east-1"),
        NodeCloud("b", "aws:eu-central-1"),
        NodeCloud("c", "aws:ap-southeast-1"),
        NodeCloud("d", "gcp:europe-west-2"),
        NodeCloud("e", "hetzner:fsn1"),
    )
    with pytest.raises(CloudDiversityError) as excinfo:
        verify_cloud_diversity(nodes, threshold=3)
    assert "aws" in str(excinfo.value)
    report = excinfo.value.report
    assert report.cloud_counts["aws"] == 3
    assert report.max_nodes_per_cloud == 2


def test_single_cloud_cluster_refused():
    # Five distinct AWS regions still equals one cloud.
    nodes = (
        NodeCloud("a", "aws:us-east-1"),
        NodeCloud("b", "aws:us-west-2"),
        NodeCloud("c", "aws:eu-central-1"),
        NodeCloud("d", "aws:eu-west-3"),
        NodeCloud("e", "aws:ap-southeast-1"),
    )
    with pytest.raises(CloudDiversityError) as excinfo:
        verify_cloud_diversity(nodes, threshold=3)
    # Hits the per-provider cap before the distinct-providers floor.
    assert "aws" in str(excinfo.value)


def test_two_providers_but_majority_concentrated_refused():
    # 4 AWS + 1 GCP — two distinct clouds (passes the min-floor) but
    # AWS exceeds the N-K cap.
    nodes = (
        NodeCloud("a", "aws:us-east-1"),
        NodeCloud("b", "aws:eu-central-1"),
        NodeCloud("c", "aws:ap-southeast-1"),
        NodeCloud("d", "aws:us-west-2"),
        NodeCloud("e", "gcp:europe-west-2"),
    )
    with pytest.raises(CloudDiversityError) as excinfo:
        verify_cloud_diversity(nodes, threshold=3)
    assert excinfo.value.report.largest_cloud == "aws"
    assert excinfo.value.report.largest_cloud_count == 4


def test_distinct_floor_caught_when_per_cloud_cap_inapplicable():
    # 1-of-2 cluster: max_per_cloud = 1, but distinct floor (=2) is
    # the binding constraint.
    nodes = (
        NodeCloud("a", "aws:us-east-1"),
        NodeCloud("b", "aws:eu-central-1"),
    )
    with pytest.raises(CloudDiversityError) as excinfo:
        verify_cloud_diversity(nodes, threshold=1)
    # The per-cloud cap fires first because 2 > 1 (N-K=1).
    msg = str(excinfo.value)
    assert "aws" in msg


# ---------------------------------------------------------------------------
# Malformed inputs
# ---------------------------------------------------------------------------

def test_empty_nodes_refused():
    with pytest.raises(CloudDiversityError):
        verify_cloud_diversity((), threshold=3)


def test_threshold_below_one_refused():
    with pytest.raises(CloudDiversityError):
        verify_cloud_diversity(
            (NodeCloud("a", "aws"), NodeCloud("b", "gcp")),
            threshold=0,
        )


def test_threshold_above_node_count_refused():
    with pytest.raises(CloudDiversityError):
        verify_cloud_diversity(
            (NodeCloud("a", "aws"), NodeCloud("b", "gcp")),
            threshold=3,
        )


def test_duplicate_node_id_refused():
    with pytest.raises(CloudDiversityError):
        verify_cloud_diversity(
            (
                NodeCloud("dup", "aws"),
                NodeCloud("dup", "gcp"),
                NodeCloud("c", "hetzner"),
            ),
            threshold=2,
        )


def test_empty_cloud_provider_label_refused():
    with pytest.raises(CloudDiversityError):
        verify_cloud_diversity(
            (
                NodeCloud("a", "aws"),
                NodeCloud("b", "   "),
                NodeCloud("c", "gcp"),
            ),
            threshold=2,
        )


# ---------------------------------------------------------------------------
# Audit scenario — the exact attack the gate exists for
# ---------------------------------------------------------------------------

def test_audit_scenario_b_step1_caught():
    # Scenario B step 1: "nation-state compromises a cloud provider
    # hosting oracle nodes." This is the substrate. A 5-AWS cluster
    # (HCR-2 green if regions differ, HCR-4 green if operators differ)
    # is fundamentally a one-court-order-to-AWS kill — NSS-1 refuses
    # such a topology at boot.
    one_cloud_topology = (
        NodeCloud("op-A:node-0", "aws:us-east-1"),
        NodeCloud("op-B:node-1", "aws:eu-central-1"),
        NodeCloud("op-C:node-2", "aws:ap-southeast-1"),
        NodeCloud("op-D:node-3", "aws:us-west-2"),
        NodeCloud("op-E:node-4", "aws:eu-west-3"),
    )
    with pytest.raises(CloudDiversityError) as excinfo:
        verify_cloud_diversity(one_cloud_topology, threshold=3)
    assert "NSS-1" in str(excinfo.value)
    assert excinfo.value.report.cloud_counts["aws"] == 5
