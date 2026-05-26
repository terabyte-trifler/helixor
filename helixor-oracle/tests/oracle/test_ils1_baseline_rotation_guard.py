"""
tests/oracle/test_ils1_baseline_rotation_guard.py — ILS-1 baseline
rotation cadence + co-attestation guard.

Pins:
  - Constants (MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS=30,
    MIN_BASELINE_COSIGNERS=2, BASELINE_FUTURE_TOLERANCE_EPOCHS=1).
  - First baseline (last_recorded_epoch=-1) accepted with 2
    cosigners.
  - 30-epoch gap accepted; 29-epoch gap refused with
    BASELINE_ROTATION_TOO_SOON.
  - Inclusive boundary: exactly 30 epochs is OK; 29 is refused.
  - Same-epoch rotation refused with BASELINE_EPOCH_NOT_MONOTONIC
    (mirrors on-chain check).
  - Single-cosigner refused with BASELINE_INSUFFICIENT_COSIGNERS.
  - Cluster-only cosigners (agent missing) refused with
    BASELINE_AGENT_MISSING_FROM_COSIGNERS.
  - Duplicate cosigner refused with BASELINE_DUPLICATE_COSIGNER.
  - Future-dated epoch (> current + 1) refused with
    BASELINE_EPOCH_IN_FUTURE.
  - Zero epoch refused with BASELINE_EPOCH_INVALID.
  - Multiple violations report all reason codes.
  - Enforcement raises BaselineRotationRefusedError on refusal.
  - Audit-scenario: attacker with one compromised cluster key
    tries to rotate baseline every epoch — REFUSED at the
    cadence floor.
"""

from __future__ import annotations

import pytest

from oracle.baseline_rotation_guard import (
    BASELINE_FUTURE_TOLERANCE_EPOCHS,
    BASELINE_OK,
    BASELINE_REFUSED,
    BaselineRotationProposal,
    BaselineRotationRefusedError,
    MIN_BASELINE_COSIGNERS,
    MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS,
    REASON_BASELINE_AGENT_MISSING_FROM_COSIGNERS,
    REASON_BASELINE_DUPLICATE_COSIGNER,
    REASON_BASELINE_EPOCH_INVALID,
    REASON_BASELINE_EPOCH_IN_FUTURE,
    REASON_BASELINE_EPOCH_NOT_MONOTONIC,
    REASON_BASELINE_INSUFFICIENT_COSIGNERS,
    REASON_BASELINE_ROTATION_TOO_SOON,
    enforce_baseline_rotation,
    verify_baseline_rotation,
)


AGENT = "agent-wallet"
CLUSTER_A = "cluster-key-a"
CLUSTER_B = "cluster-key-b"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    assert MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS == 30
    assert MIN_BASELINE_COSIGNERS == 2
    assert BASELINE_FUTURE_TOLERANCE_EPOCHS == 1


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_first_baseline_accepted_with_two_cosigners():
    report = verify_baseline_rotation(BaselineRotationProposal(
        agent_wallet=AGENT,
        proposed_epoch=1,
        last_recorded_epoch=-1,
        current_epoch=1,
        cosigners=(AGENT, CLUSTER_A),
    ))
    assert report.is_allowed
    assert report.status == BASELINE_OK
    assert report.cosigner_count == 2
    assert report.reasons == ()


def test_rotation_after_30_epochs_accepted():
    report = verify_baseline_rotation(BaselineRotationProposal(
        agent_wallet=AGENT,
        proposed_epoch=130,
        last_recorded_epoch=100,
        current_epoch=130,
        cosigners=(AGENT, CLUSTER_A),
    ))
    assert report.is_allowed
    assert report.epoch_delta == 30


# ---------------------------------------------------------------------------
# Cadence boundary
# ---------------------------------------------------------------------------

def test_exactly_30_epoch_gap_is_ok():
    # 30 is the floor — inclusive.
    report = verify_baseline_rotation(BaselineRotationProposal(
        agent_wallet=AGENT,
        proposed_epoch=130,
        last_recorded_epoch=100,
        current_epoch=130,
        cosigners=(AGENT, CLUSTER_A),
    ))
    assert report.is_allowed


def test_29_epoch_gap_refused():
    report = verify_baseline_rotation(BaselineRotationProposal(
        agent_wallet=AGENT,
        proposed_epoch=129,
        last_recorded_epoch=100,
        current_epoch=129,
        cosigners=(AGENT, CLUSTER_A),
    ))
    assert not report.is_allowed
    assert REASON_BASELINE_ROTATION_TOO_SOON in report.reasons


def test_same_epoch_rotation_refused_monotonic():
    report = verify_baseline_rotation(BaselineRotationProposal(
        agent_wallet=AGENT,
        proposed_epoch=100,
        last_recorded_epoch=100,
        current_epoch=100,
        cosigners=(AGENT, CLUSTER_A),
    ))
    assert not report.is_allowed
    assert REASON_BASELINE_EPOCH_NOT_MONOTONIC in report.reasons


def test_earlier_epoch_rotation_refused_monotonic():
    report = verify_baseline_rotation(BaselineRotationProposal(
        agent_wallet=AGENT,
        proposed_epoch=99,
        last_recorded_epoch=100,
        current_epoch=130,
        cosigners=(AGENT, CLUSTER_A),
    ))
    assert not report.is_allowed
    assert REASON_BASELINE_EPOCH_NOT_MONOTONIC in report.reasons


# ---------------------------------------------------------------------------
# Co-signer floor
# ---------------------------------------------------------------------------

def test_single_cosigner_refused():
    report = verify_baseline_rotation(BaselineRotationProposal(
        agent_wallet=AGENT,
        proposed_epoch=130,
        last_recorded_epoch=100,
        current_epoch=130,
        cosigners=(AGENT,),
    ))
    assert not report.is_allowed
    assert REASON_BASELINE_INSUFFICIENT_COSIGNERS in report.reasons


def test_cluster_only_no_agent_refused():
    report = verify_baseline_rotation(BaselineRotationProposal(
        agent_wallet=AGENT,
        proposed_epoch=130,
        last_recorded_epoch=100,
        current_epoch=130,
        cosigners=(CLUSTER_A, CLUSTER_B),
    ))
    assert not report.is_allowed
    assert REASON_BASELINE_AGENT_MISSING_FROM_COSIGNERS in report.reasons


def test_duplicate_cosigner_refused():
    report = verify_baseline_rotation(BaselineRotationProposal(
        agent_wallet=AGENT,
        proposed_epoch=130,
        last_recorded_epoch=100,
        current_epoch=130,
        cosigners=(AGENT, AGENT),  # duplicate, only 1 distinct
    ))
    assert not report.is_allowed
    assert REASON_BASELINE_DUPLICATE_COSIGNER in report.reasons
    assert REASON_BASELINE_INSUFFICIENT_COSIGNERS in report.reasons


# ---------------------------------------------------------------------------
# Time-travel defence
# ---------------------------------------------------------------------------

def test_future_epoch_refused():
    report = verify_baseline_rotation(BaselineRotationProposal(
        agent_wallet=AGENT,
        proposed_epoch=200,
        last_recorded_epoch=100,
        current_epoch=130,  # proposed is 70 epochs in the future
        cosigners=(AGENT, CLUSTER_A),
    ))
    assert not report.is_allowed
    assert REASON_BASELINE_EPOCH_IN_FUTURE in report.reasons


def test_one_epoch_future_within_tolerance():
    # current + 1 is INSIDE the tolerance window — accepted.
    report = verify_baseline_rotation(BaselineRotationProposal(
        agent_wallet=AGENT,
        proposed_epoch=131,
        last_recorded_epoch=100,
        current_epoch=130,
        cosigners=(AGENT, CLUSTER_A),
    ))
    assert report.is_allowed


def test_zero_epoch_refused():
    report = verify_baseline_rotation(BaselineRotationProposal(
        agent_wallet=AGENT,
        proposed_epoch=0,
        last_recorded_epoch=-1,
        current_epoch=10,
        cosigners=(AGENT, CLUSTER_A),
    ))
    assert not report.is_allowed
    assert REASON_BASELINE_EPOCH_INVALID in report.reasons


# ---------------------------------------------------------------------------
# Compound violations
# ---------------------------------------------------------------------------

def test_multiple_violations_reported_together():
    # Too-soon rotation AND single cosigner.
    report = verify_baseline_rotation(BaselineRotationProposal(
        agent_wallet=AGENT,
        proposed_epoch=105,
        last_recorded_epoch=100,
        current_epoch=105,
        cosigners=(CLUSTER_A,),
    ))
    assert not report.is_allowed
    assert REASON_BASELINE_ROTATION_TOO_SOON in report.reasons
    assert REASON_BASELINE_INSUFFICIENT_COSIGNERS in report.reasons
    assert REASON_BASELINE_AGENT_MISSING_FROM_COSIGNERS in report.reasons


# ---------------------------------------------------------------------------
# Enforcement wrapper
# ---------------------------------------------------------------------------

def test_enforce_returns_report_on_clean_rotation():
    report = enforce_baseline_rotation(BaselineRotationProposal(
        agent_wallet=AGENT,
        proposed_epoch=130,
        last_recorded_epoch=100,
        current_epoch=130,
        cosigners=(AGENT, CLUSTER_A),
    ))
    assert report.is_allowed


def test_enforce_raises_on_too_soon():
    with pytest.raises(BaselineRotationRefusedError) as excinfo:
        enforce_baseline_rotation(BaselineRotationProposal(
            agent_wallet=AGENT,
            proposed_epoch=101,
            last_recorded_epoch=100,
            current_epoch=101,
            cosigners=(AGENT, CLUSTER_A),
        ))
    assert "ILS-1" in str(excinfo.value)
    assert excinfo.value.report.status == BASELINE_REFUSED
    assert REASON_BASELINE_ROTATION_TOO_SOON in excinfo.value.report.reasons


# ---------------------------------------------------------------------------
# Audit scenario — the exact attack the gate exists for
# ---------------------------------------------------------------------------

def test_audit_scenario_per_epoch_baseline_grind_refused():
    # Path 2 sub-leaf 2a: attacker with one compromised cluster key
    # tries to rotate the baseline every epoch (mirroring the
    # VULN-06 grind attack). The on-chain monotonicity check would
    # accept epoch + 1, but ILS-1's 30-epoch cadence floor refuses
    # at 1.
    with pytest.raises(BaselineRotationRefusedError) as excinfo:
        enforce_baseline_rotation(BaselineRotationProposal(
            agent_wallet=AGENT,
            proposed_epoch=101,
            last_recorded_epoch=100,
            current_epoch=101,
            cosigners=(AGENT, CLUSTER_A),
        ))
    assert REASON_BASELINE_ROTATION_TOO_SOON in excinfo.value.report.reasons


def test_audit_scenario_compromised_cluster_solo_rotation_refused():
    # Path 2 sub-leaf 2a residual: an attacker who compromised
    # ONE cluster key tries to rotate alone. ILS-1's co-signer
    # floor requires the agent's signature too.
    with pytest.raises(BaselineRotationRefusedError) as excinfo:
        enforce_baseline_rotation(BaselineRotationProposal(
            agent_wallet=AGENT,
            proposed_epoch=200,
            last_recorded_epoch=100,
            current_epoch=200,
            cosigners=(CLUSTER_A,),  # cluster signer alone
        ))
    report = excinfo.value.report
    assert REASON_BASELINE_INSUFFICIENT_COSIGNERS in report.reasons
    assert REASON_BASELINE_AGENT_MISSING_FROM_COSIGNERS in report.reasons
