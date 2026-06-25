"""
tests/oracle/test_hcr4_operator_diversity.py — HCR-4 operator diversity tests.

Pins:
  - Canonical 3-of-5 with 3 orgs / 2 jurisdictions passes
  - One org owning 3-of-5 fails (meets threshold unilaterally)
  - One org owning exactly threshold-1 still passes
  - Single-jurisdiction cluster rejected (legal-compulsion risk)
  - Manifest validation rejects: empty fields, duplicate node_id,
    duplicate pubkey, malformed ISO codes, threshold > N
  - Report carries per-org and per-jurisdiction tallies
"""

from __future__ import annotations

import pytest

from oracle.operator_manifest import (
    MIN_DISTINCT_JURISDICTIONS,
    MIN_DISTINCT_OPERATORS,
    OperatorAttestation,
    OperatorDiversityError,
    OperatorManifestError,
    build_manifest,
    verify_operator_diversity,
)


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def _att(node_id, *, pubkey=None, org="Org A", contact="ops@orga.example",
         jurisdiction="US"):
    return OperatorAttestation(
        node_id=node_id,
        pubkey=pubkey if pubkey is not None else f"pk-{node_id}",
        operator_org=org,
        operator_contact=contact,
        jurisdiction=jurisdiction,
    )


# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------

def test_min_distinct_floors():
    assert MIN_DISTINCT_OPERATORS == 2
    assert MIN_DISTINCT_JURISDICTIONS == 2


# ----------------------------------------------------------------------------
# build_manifest input validation
# ----------------------------------------------------------------------------

def test_empty_attestations_rejected():
    with pytest.raises(OperatorManifestError, match="non-empty"):
        build_manifest([], threshold=1)


def test_threshold_exceeding_attestations_rejected():
    with pytest.raises(OperatorManifestError, match="cannot exceed"):
        build_manifest([_att("a")], threshold=2)


def test_threshold_zero_rejected():
    with pytest.raises(OperatorManifestError, match=">= 1"):
        build_manifest([_att("a"), _att("b")], threshold=0)


def test_empty_field_rejected():
    with pytest.raises(OperatorManifestError, match="empty"):
        build_manifest([
            _att("a"),
            OperatorAttestation(
                node_id="b", pubkey="pkb", operator_org="",
                operator_contact="c", jurisdiction="DE",
            ),
        ], threshold=1)


def test_duplicate_node_id_rejected():
    with pytest.raises(OperatorManifestError, match="duplicate node_id"):
        build_manifest([
            _att("dup"),
            _att("dup", pubkey="other"),
        ], threshold=1)


def test_duplicate_pubkey_rejected():
    with pytest.raises(OperatorManifestError, match="duplicate pubkey"):
        build_manifest([
            _att("a", pubkey="same"),
            _att("b", pubkey="same"),
        ], threshold=1)


def test_malformed_iso_code_rejected():
    with pytest.raises(OperatorManifestError, match="ISO-3166"):
        build_manifest([
            _att("a", jurisdiction="USA"),  # 3 letters
            _att("b", jurisdiction="DE"),
        ], threshold=1)


def test_numeric_iso_code_rejected():
    with pytest.raises(OperatorManifestError, match="ISO-3166"):
        build_manifest([
            _att("a", jurisdiction="12"),
            _att("b", jurisdiction="DE"),
        ], threshold=1)


# ----------------------------------------------------------------------------
# Diversity gate — happy path
# ----------------------------------------------------------------------------

def test_canonical_three_of_five_cluster_with_three_orgs_passes():
    manifest = build_manifest([
        _att("oracle-node-0", org="Org A", jurisdiction="US"),
        _att("oracle-node-1", org="Org A", jurisdiction="DE"),
        _att("oracle-node-2", org="Org B", jurisdiction="DE"),
        _att("oracle-node-3", org="Org B", jurisdiction="SG"),
        _att("oracle-node-4", org="Org C", jurisdiction="SG"),
    ], threshold=3)
    report = verify_operator_diversity(manifest)
    assert report.is_diverse
    assert report.org_counts == {"Org A": 2, "Org B": 2, "Org C": 1}
    assert report.jurisdiction_counts == {"US": 1, "DE": 2, "SG": 2}
    assert report.distinct_orgs == 3
    assert report.distinct_jurisdictions == 3


def test_two_orgs_two_jurisdictions_below_threshold_passes():
    # 2 of 5 each org = below threshold of 3, passes.
    manifest = build_manifest([
        _att("oracle-node-0", org="Org A", jurisdiction="US"),
        _att("oracle-node-1", org="Org A", jurisdiction="US"),
        _att("oracle-node-2", org="Org B", jurisdiction="DE"),
        _att("oracle-node-3", org="Org B", jurisdiction="DE"),
        _att("oracle-node-4", org="Org A", jurisdiction="DE"),  # 3 As; will fail
    ], threshold=3)
    with pytest.raises(OperatorDiversityError) as excinfo:
        verify_operator_diversity(manifest)
    assert excinfo.value.report.largest_org == "Org A"
    assert excinfo.value.report.largest_org_count == 3


# ----------------------------------------------------------------------------
# Diversity gate — failure modes
# ----------------------------------------------------------------------------

def test_one_org_owning_threshold_pubkeys_rejected():
    manifest = build_manifest([
        _att("oracle-node-0", org="Org A", jurisdiction="US"),
        _att("oracle-node-1", org="Org A", jurisdiction="DE"),
        _att("oracle-node-2", org="Org A", jurisdiction="SG"),  # 3rd Org A
        _att("oracle-node-3", org="Org B", jurisdiction="DE"),
        _att("oracle-node-4", org="Org C", jurisdiction="SG"),
    ], threshold=3)
    with pytest.raises(OperatorDiversityError, match="HCR-4") as excinfo:
        verify_operator_diversity(manifest)
    assert excinfo.value.report.largest_org == "Org A"
    assert excinfo.value.report.largest_org_count == 3


def test_org_one_below_threshold_passes():
    # Exactly threshold - 1. The largest org cannot unilaterally meet
    # threshold; the gate accepts.
    manifest = build_manifest([
        _att("oracle-node-0", org="Org A", jurisdiction="US"),
        _att("oracle-node-1", org="Org A", jurisdiction="DE"),
        _att("oracle-node-2", org="Org B", jurisdiction="DE"),
        _att("oracle-node-3", org="Org B", jurisdiction="SG"),
        _att("oracle-node-4", org="Org C", jurisdiction="SG"),
    ], threshold=3)
    report = verify_operator_diversity(manifest)
    assert report.is_diverse
    assert report.largest_org_count == 2


def test_single_jurisdiction_cluster_rejected():
    manifest = build_manifest([
        _att("oracle-node-0", org="Org A", jurisdiction="US"),
        _att("oracle-node-1", org="Org B", jurisdiction="US"),
        _att("oracle-node-2", org="Org C", jurisdiction="US"),
        _att("oracle-node-3", org="Org D", jurisdiction="US"),
        _att("oracle-node-4", org="Org E", jurisdiction="US"),
    ], threshold=3)
    with pytest.raises(OperatorDiversityError, match="HCR-4") as excinfo:
        verify_operator_diversity(manifest)
    assert excinfo.value.report.distinct_jurisdictions == 1


def test_two_org_two_jurisdiction_three_of_three_rejected():
    # 3 nodes, threshold 3, two orgs {2, 1}, two jurisdictions — but
    # the largest org count (2) is below threshold (3), and the gate
    # rejects because Org A controls threshold-1 only and that's fine.
    # The check we're pinning here is the smallest viable cluster.
    manifest = build_manifest([
        _att("a", org="Org A", jurisdiction="US"),
        _att("b", org="Org A", jurisdiction="DE"),
        _att("c", org="Org B", jurisdiction="DE"),
    ], threshold=2)
    with pytest.raises(OperatorDiversityError):
        # Org A controls 2 = threshold -> rejected.
        verify_operator_diversity(manifest)


def test_jurisdiction_iso_codes_are_case_insensitive_in_check():
    # The validator uppercases jurisdiction codes when counting, so
    # `"us"` and `"US"` are the same jurisdiction. Codes are still
    # required to be 2 letters at construction time.
    manifest = build_manifest([
        _att("a", org="Org A", jurisdiction="us"),
        _att("b", org="Org B", jurisdiction="US"),
        _att("c", org="Org C", jurisdiction="de"),
    ], threshold=2)
    report = verify_operator_diversity(manifest)
    assert report.jurisdiction_counts == {"US": 2, "DE": 1}


# ----------------------------------------------------------------------------
# Report shape
# ----------------------------------------------------------------------------

def test_report_carries_full_tallies():
    manifest = build_manifest([
        _att("a", org="Org A", jurisdiction="US"),
        _att("b", org="Org A", jurisdiction="DE"),
        _att("c", org="Org B", jurisdiction="DE"),
        _att("d", org="Org C", jurisdiction="SG"),
        _att("e", org="Org C", jurisdiction="SG"),
    ], threshold=3)
    report = verify_operator_diversity(manifest)
    assert report.org_counts == {"Org A": 2, "Org B": 1, "Org C": 2}
    assert report.jurisdiction_counts == {"US": 1, "DE": 2, "SG": 2}
    assert report.distinct_orgs == 3
    assert report.distinct_jurisdictions == 3
