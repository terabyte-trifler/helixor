"""
tests/oracle/test_hcr2_region_diversity.py — HCR-2 region diversity tests.

Pins:
  - Canonical 3-of-5 cluster: max 2 nodes per region, ≥ 2 distinct regions
  - Two-region split {3, 2} fails (largest exceeds cap)
  - All-in-one-region fails on distinct-regions floor
  - Larger clusters (7 nodes 4-of-7) compute caps correctly
  - Duplicate node IDs rejected
  - Empty region label rejected
  - Report is attached to the exception with per-region tally
"""

from __future__ import annotations

import pytest

from oracle.region_diversity import (
    DEFAULT_CLUSTER_SIZE,
    DEFAULT_CLUSTER_THRESHOLD,
    MIN_DISTINCT_REGIONS,
    NodeLocation,
    RegionDiversityError,
    verify_region_diversity,
)


# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------

def test_default_cluster_is_three_of_five():
    assert DEFAULT_CLUSTER_SIZE == 5
    assert DEFAULT_CLUSTER_THRESHOLD == 3


def test_min_distinct_regions_is_two():
    assert MIN_DISTINCT_REGIONS == 2


# ----------------------------------------------------------------------------
# Happy-path topologies for the canonical 3-of-5 cluster
# ----------------------------------------------------------------------------

def test_three_regions_split_two_two_one_passes():
    nodes = [
        NodeLocation("oracle-node-0", "aws:us-east-1"),
        NodeLocation("oracle-node-1", "aws:us-east-1"),
        NodeLocation("oracle-node-2", "gcp:europe-west-2"),
        NodeLocation("oracle-node-3", "gcp:europe-west-2"),
        NodeLocation("oracle-node-4", "hetzner:fsn1"),
    ]
    report = verify_region_diversity(nodes)
    assert report.is_diverse
    assert report.max_nodes_per_region == 2
    assert report.largest_region_count == 2
    assert report.distinct_regions == 3


def test_five_regions_split_one_one_one_one_one_passes():
    nodes = [
        NodeLocation(f"oracle-node-{i}", region)
        for i, region in enumerate([
            "aws:us-east-1", "aws:eu-west-2", "gcp:us-central1",
            "hetzner:fsn1", "ovh:gra11",
        ])
    ]
    report = verify_region_diversity(nodes)
    assert report.is_diverse
    assert report.distinct_regions == 5


# ----------------------------------------------------------------------------
# Failure: per-region cap
# ----------------------------------------------------------------------------

def test_three_two_split_rejected_largest_exceeds_cap():
    nodes = [
        NodeLocation("a", "aws:us-east-1"),
        NodeLocation("b", "aws:us-east-1"),
        NodeLocation("c", "aws:us-east-1"),  # 3 in one region
        NodeLocation("d", "gcp:europe-west-2"),
        NodeLocation("e", "gcp:europe-west-2"),
    ]
    with pytest.raises(RegionDiversityError, match="HCR-2") as excinfo:
        verify_region_diversity(nodes)
    report = excinfo.value.report
    assert report.largest_region == "aws:us-east-1"
    assert report.largest_region_count == 3
    assert report.max_nodes_per_region == 2
    assert report.region_counts == {
        "aws:us-east-1": 3, "gcp:europe-west-2": 2,
    }


def test_all_in_one_region_rejected():
    nodes = [
        NodeLocation(f"n{i}", "aws:us-east-1")
        for i in range(5)
    ]
    with pytest.raises(RegionDiversityError) as excinfo:
        verify_region_diversity(nodes)
    report = excinfo.value.report
    assert report.largest_region_count == 5
    assert report.distinct_regions == 1


# ----------------------------------------------------------------------------
# Failure: distinct-region floor
# ----------------------------------------------------------------------------

def test_one_distinct_region_with_loose_cap_still_fails_on_floor():
    # If we somehow had a 1-of-5 threshold the per-region cap is 4 and
    # five nodes in one region passes the cap; HCR-2 still REFUSES on
    # the distinct-regions floor because a single regional outage =
    # whole cluster down, threshold or no.
    nodes = [NodeLocation(f"n{i}", "aws:us-east-1") for i in range(5)]
    with pytest.raises(RegionDiversityError):
        verify_region_diversity(nodes, threshold=1)


# ----------------------------------------------------------------------------
# Larger / smaller clusters
# ----------------------------------------------------------------------------

def test_seven_node_four_of_seven_cluster_passes_with_well_spread():
    nodes = [
        NodeLocation("a", "aws:us-east-1"),
        NodeLocation("b", "aws:us-east-1"),
        NodeLocation("c", "aws:us-east-1"),  # 3 max for N-K = 7-4 = 3
        NodeLocation("d", "gcp:eu-west-2"),
        NodeLocation("e", "gcp:eu-west-2"),
        NodeLocation("f", "hetzner:fsn1"),
        NodeLocation("g", "ovh:gra11"),
    ]
    report = verify_region_diversity(nodes, threshold=4)
    assert report.is_diverse
    assert report.max_nodes_per_region == 3


def test_seven_node_four_of_seven_with_four_in_one_region_rejected():
    nodes = [
        NodeLocation("a", "aws:us-east-1"),
        NodeLocation("b", "aws:us-east-1"),
        NodeLocation("c", "aws:us-east-1"),
        NodeLocation("d", "aws:us-east-1"),  # 4 > N-K=3
        NodeLocation("e", "gcp:eu-west-2"),
        NodeLocation("f", "hetzner:fsn1"),
        NodeLocation("g", "ovh:gra11"),
    ]
    with pytest.raises(RegionDiversityError):
        verify_region_diversity(nodes, threshold=4)


# ----------------------------------------------------------------------------
# Constructor invariants
# ----------------------------------------------------------------------------

def test_empty_nodes_rejected():
    with pytest.raises(RegionDiversityError, match="non-empty"):
        verify_region_diversity([])


def test_threshold_exceeding_node_count_rejected():
    with pytest.raises(RegionDiversityError, match="cannot exceed"):
        verify_region_diversity(
            [NodeLocation("a", "aws:us-east-1"),
             NodeLocation("b", "gcp:eu-west-2")],
            threshold=3,
        )


def test_duplicate_node_ids_rejected():
    with pytest.raises(RegionDiversityError, match="duplicate node_id"):
        verify_region_diversity([
            NodeLocation("dup", "aws:us-east-1"),
            NodeLocation("dup", "gcp:eu-west-2"),
            NodeLocation("c",   "hetzner:fsn1"),
        ])


def test_empty_region_label_rejected():
    with pytest.raises(RegionDiversityError, match="empty region"):
        verify_region_diversity([
            NodeLocation("a", "aws:us-east-1"),
            NodeLocation("b", "   "),
            NodeLocation("c", "gcp:eu-west-2"),
        ])


# ----------------------------------------------------------------------------
# Region label opacity
# ----------------------------------------------------------------------------

def test_region_label_strings_are_opaque():
    # The gate does not care what the label means — only that distinct
    # labels mean distinct fault domains. Mixed-provider labels are fine.
    nodes = [
        NodeLocation("a", "aws:us-east-1"),
        NodeLocation("b", "hetzner:fsn1"),
        NodeLocation("c", "self-hosted:basement-rack"),
        NodeLocation("d", "aws:eu-west-2"),
        NodeLocation("e", "gcp:asia-southeast-1"),
    ]
    report = verify_region_diversity(nodes)
    assert report.is_diverse
    assert report.distinct_regions == 5
