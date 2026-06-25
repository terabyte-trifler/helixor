"""
tests/oracle/test_fhs3_rotation_overlap_guard.py — FHS-3 cluster-key
rotation overlap guard.

Pins:
  - Constants (MAX_KEYS_REPLACED_PER_ROTATION = 1).
  - Replacing exactly one key in a 3-of-5 cluster is OK.
  - Replacing two keys in a 3-of-5 cluster is REFUSED with
    WHOLESALE_REPLACEMENT.
  - Wholesale replacement (5 -> 5 disjoint) refused.
  - Replacing one key but keeping the rest is allowed for 5-of-9.
  - Identity rotation (no change) is OK.
  - Empty proposed set refused.
  - Duplicate inside proposed_keys refused.
  - threshold <= 0 refused with THRESHOLD_INVALID.
  - Enforcement raises RotationOverlapError on refusal.
  - Audit-scenario: attacker with K=3 compromised attestations
    proposes 5-key wholesale swap — REFUSED.
  - Adding a key without removing one (cluster growth) is OK:
    no key was REPLACED.
"""

from __future__ import annotations

import pytest

from oracle.rotation_overlap_guard import (
    MAX_KEYS_REPLACED_PER_ROTATION,
    OVERLAP_OK,
    OVERLAP_REFUSED,
    REASON_INSUFFICIENT_OVERLAP,
    REASON_NEW_KEYS_DUPLICATE,
    REASON_NEW_KEYS_EMPTY,
    REASON_THRESHOLD_INVALID,
    REASON_WHOLESALE_REPLACEMENT,
    RotationOverlapError,
    RotationProposal,
    enforce_rotation_overlap,
    verify_rotation_overlap,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    assert MAX_KEYS_REPLACED_PER_ROTATION == 1


# ---------------------------------------------------------------------------
# Single-key replacement (the canonical happy path)
# ---------------------------------------------------------------------------

def test_single_key_replacement_in_3_of_5_is_ok():
    proposal = RotationProposal(
        current_keys=("k0", "k1", "k2", "k3", "k4"),
        proposed_keys=("kNew", "k1", "k2", "k3", "k4"),
        threshold=3,
    )
    report = verify_rotation_overlap(proposal)
    assert report.is_allowed
    assert report.status == OVERLAP_OK
    assert report.replaced_size == 1
    assert report.added_size == 1
    assert report.keys_removed == ("k0",)
    assert report.keys_added == ("kNew",)


def test_identity_rotation_is_ok():
    # Cosmetic re-propose (no real change) is OK.
    proposal = RotationProposal(
        current_keys=("k0", "k1", "k2", "k3", "k4"),
        proposed_keys=("k0", "k1", "k2", "k3", "k4"),
        threshold=3,
    )
    report = verify_rotation_overlap(proposal)
    assert report.is_allowed
    assert report.replaced_size == 0


def test_single_key_replacement_in_5_of_9_is_ok():
    proposal = RotationProposal(
        current_keys=tuple(f"k{i}" for i in range(9)),
        proposed_keys=("kNew",) + tuple(f"k{i}" for i in range(1, 9)),
        threshold=5,
    )
    report = verify_rotation_overlap(proposal)
    assert report.is_allowed
    assert report.required_overlap == 4


# ---------------------------------------------------------------------------
# Multi-key replacement refusals
# ---------------------------------------------------------------------------

def test_two_keys_replaced_in_3_of_5_refused():
    proposal = RotationProposal(
        current_keys=("k0", "k1", "k2", "k3", "k4"),
        proposed_keys=("kNew0", "kNew1", "k2", "k3", "k4"),
        threshold=3,
    )
    report = verify_rotation_overlap(proposal)
    assert not report.is_allowed
    assert REASON_WHOLESALE_REPLACEMENT in report.reasons


def test_wholesale_5_for_5_refused_3_of_5():
    proposal = RotationProposal(
        current_keys=("k0", "k1", "k2", "k3", "k4"),
        proposed_keys=("kA0", "kA1", "kA2", "kA3", "kA4"),
        threshold=3,
    )
    report = verify_rotation_overlap(proposal)
    assert not report.is_allowed
    assert REASON_WHOLESALE_REPLACEMENT in report.reasons
    assert REASON_INSUFFICIENT_OVERLAP in report.reasons
    assert report.overlap_size == 0
    assert report.required_overlap == 2  # threshold - 1 = 3 - 1


# ---------------------------------------------------------------------------
# Pathological proposals
# ---------------------------------------------------------------------------

def test_empty_proposed_keys_refused():
    proposal = RotationProposal(
        current_keys=("k0", "k1", "k2", "k3", "k4"),
        proposed_keys=(),
        threshold=3,
    )
    report = verify_rotation_overlap(proposal)
    assert not report.is_allowed
    assert REASON_NEW_KEYS_EMPTY in report.reasons


def test_duplicate_inside_proposed_refused():
    proposal = RotationProposal(
        current_keys=("k0", "k1", "k2", "k3", "k4"),
        proposed_keys=("kNew", "k1", "k1", "k3", "k4"),  # k1 duplicated
        threshold=3,
    )
    report = verify_rotation_overlap(proposal)
    assert not report.is_allowed
    assert REASON_NEW_KEYS_DUPLICATE in report.reasons


def test_zero_threshold_refused():
    proposal = RotationProposal(
        current_keys=("k0", "k1"),
        proposed_keys=("k0", "k1"),
        threshold=0,
    )
    report = verify_rotation_overlap(proposal)
    assert not report.is_allowed
    assert REASON_THRESHOLD_INVALID in report.reasons


def test_negative_threshold_refused():
    proposal = RotationProposal(
        current_keys=("k0",),
        proposed_keys=("k0",),
        threshold=-1,
    )
    report = verify_rotation_overlap(proposal)
    assert not report.is_allowed
    assert REASON_THRESHOLD_INVALID in report.reasons


# ---------------------------------------------------------------------------
# Cluster growth (additions only)
# ---------------------------------------------------------------------------

def test_pure_growth_no_keys_removed_is_ok():
    # Adding one key to a 5-of-9 setup is OK: no key was replaced.
    proposal = RotationProposal(
        current_keys=("k0", "k1", "k2", "k3", "k4"),
        proposed_keys=("k0", "k1", "k2", "k3", "k4", "kNew"),
        threshold=3,
    )
    report = verify_rotation_overlap(proposal)
    assert report.is_allowed
    assert report.replaced_size == 0
    assert report.added_size == 1


# ---------------------------------------------------------------------------
# Enforcement wrapper
# ---------------------------------------------------------------------------

def test_enforce_returns_report_on_single_swap():
    proposal = RotationProposal(
        current_keys=("k0", "k1", "k2", "k3", "k4"),
        proposed_keys=("kNew", "k1", "k2", "k3", "k4"),
        threshold=3,
    )
    report = enforce_rotation_overlap(proposal)
    assert report.is_allowed


def test_enforce_raises_on_wholesale():
    proposal = RotationProposal(
        current_keys=("k0", "k1", "k2", "k3", "k4"),
        proposed_keys=("kA0", "kA1", "kA2", "kA3", "kA4"),
        threshold=3,
    )
    with pytest.raises(RotationOverlapError) as excinfo:
        enforce_rotation_overlap(proposal)
    assert "FHS-3" in str(excinfo.value)
    assert excinfo.value.report.status == OVERLAP_REFUSED


# ---------------------------------------------------------------------------
# Audit scenario — the exact attack the gate exists for
# ---------------------------------------------------------------------------

def test_audit_scenario_attacker_proposes_full_takeover():
    # Path 1 sub-leaf 1c: attacker has compromised K = 3 of the
    # 5 cluster keys (kA1, kA2, kA3). They can sign the propose
    # transaction with their 3 attestations, satisfying the on-chain
    # N-of-M gate. The proposal would wholesale-replace all 5 keys
    # with attacker-controlled keys. FHS-3 refuses BEFORE the 48h
    # timelock burns.
    proposal = RotationProposal(
        current_keys=("kH1", "kH2", "kA1", "kA2", "kA3"),
        proposed_keys=("kE1", "kE2", "kE3", "kE4", "kE5"),
        threshold=3,
    )
    with pytest.raises(RotationOverlapError) as excinfo:
        enforce_rotation_overlap(proposal)
    report = excinfo.value.report
    assert REASON_WHOLESALE_REPLACEMENT in report.reasons
    assert report.overlap_size == 0
    assert report.required_overlap == 2
