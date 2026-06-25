"""
tests/oracle/test_frp2_epoch_advance_liveness.py — FRP-2 epoch-
advance liveness floor (Path 3 sub-leaf 3b residual: attacker
withholds advance attestations to freeze epoch + freeze certs).

Pins:
  - Constants (MAX_EPOCH_ADVANCE_STALL_SECONDS = 36*3600,
    EXPECTED_EPOCH_DURATION_SECONDS = 24*3600,
    EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS = 60).
  - Fresh advance (seconds_since_last < floor) is OK.
  - Boundary: exactly MAX_EPOCH_ADVANCE_STALL_SECONDS is OK;
    floor + 1s is REFUSED with EPOCH_ADVANCE_STALL.
  - last_epoch_advance_unix=0 refused with TIMESTAMP_INVALID.
  - last_epoch_advance_unix > now + tolerance refused with
    TIMESTAMP_IN_FUTURE.
  - Negative last_advanced_epoch refused with EPOCH_INVALID.
  - current_epoch < last_advanced_epoch refused with
    EPOCH_NOT_MONOTONIC.
  - Enforcement raises EpochAdvanceStallError on refusal.
  - Audit-scenario: sustained 48h withholding (past Tier-2 fallback
    timing) — refused before AW-02 Tier-2 even needs to engage.
"""

from __future__ import annotations

import pytest

from oracle.epoch_advance_liveness import (
    EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS,
    EPOCH_ADVANCE_OK,
    EPOCH_ADVANCE_REFUSED,
    EXPECTED_EPOCH_DURATION_SECONDS,
    EpochAdvanceLivenessReport,  # noqa: F401 — imported for type pin
    EpochAdvanceStallError,
    EpochAdvanceState,
    MAX_EPOCH_ADVANCE_STALL_SECONDS,
    REASON_EPOCH_ADVANCE_EPOCH_INVALID,
    REASON_EPOCH_ADVANCE_EPOCH_NOT_MONOTONIC,
    REASON_EPOCH_ADVANCE_STALL,
    REASON_EPOCH_ADVANCE_TIMESTAMP_INVALID,
    REASON_EPOCH_ADVANCE_TIMESTAMP_IN_FUTURE,
    enforce_epoch_advance_liveness,
    verify_epoch_advance_liveness,
)


_T0 = 1_800_000_000  # arbitrary unix base


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    assert MAX_EPOCH_ADVANCE_STALL_SECONDS == 36 * 3600
    assert EXPECTED_EPOCH_DURATION_SECONDS == 24 * 3600
    assert EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS == 60


def test_stall_floor_is_one_and_a_half_epochs():
    # The 36h stall floor must be exactly 1.5× the 24h epoch
    # duration. If this ratio drifts the calibration story breaks.
    assert (
        MAX_EPOCH_ADVANCE_STALL_SECONDS * 2
        == EXPECTED_EPOCH_DURATION_SECONDS * 3
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_fresh_advance_is_ok():
    state = EpochAdvanceState(
        last_epoch_advance_unix=_T0,
        current_unix=_T0 + 3600,  # 1h ago
        last_advanced_epoch=100,
        current_epoch=100,
    )
    report = verify_epoch_advance_liveness(state)
    assert report.is_allowed
    assert report.status == EPOCH_ADVANCE_OK
    assert report.seconds_since_last == 3600
    assert report.reasons == ()


def test_recent_advance_with_epoch_match_is_ok():
    state = EpochAdvanceState(
        last_epoch_advance_unix=_T0,
        current_unix=_T0 + 60,  # 1 minute ago
        last_advanced_epoch=50,
        current_epoch=50,
    )
    report = verify_epoch_advance_liveness(state)
    assert report.is_allowed


# ---------------------------------------------------------------------------
# Stall boundary
# ---------------------------------------------------------------------------

def test_exactly_36h_stall_is_ok():
    # Inclusive at the floor.
    state = EpochAdvanceState(
        last_epoch_advance_unix=_T0,
        current_unix=_T0 + MAX_EPOCH_ADVANCE_STALL_SECONDS,
        last_advanced_epoch=10,
        current_epoch=10,
    )
    report = verify_epoch_advance_liveness(state)
    assert report.is_allowed
    assert report.seconds_since_last == MAX_EPOCH_ADVANCE_STALL_SECONDS


def test_one_second_past_36h_refused():
    state = EpochAdvanceState(
        last_epoch_advance_unix=_T0,
        current_unix=_T0 + MAX_EPOCH_ADVANCE_STALL_SECONDS + 1,
        last_advanced_epoch=10,
        current_epoch=10,
    )
    report = verify_epoch_advance_liveness(state)
    assert not report.is_allowed
    assert report.status == EPOCH_ADVANCE_REFUSED
    assert REASON_EPOCH_ADVANCE_STALL in report.reasons


# ---------------------------------------------------------------------------
# Pathological inputs
# ---------------------------------------------------------------------------

def test_zero_timestamp_refused():
    state = EpochAdvanceState(
        last_epoch_advance_unix=0,
        current_unix=_T0,
        last_advanced_epoch=10,
        current_epoch=10,
    )
    report = verify_epoch_advance_liveness(state)
    assert not report.is_allowed
    assert REASON_EPOCH_ADVANCE_TIMESTAMP_INVALID in report.reasons


def test_future_timestamp_refused():
    state = EpochAdvanceState(
        last_epoch_advance_unix=_T0 + 3600,
        current_unix=_T0,  # advance is 1h in the future
        last_advanced_epoch=10,
        current_epoch=10,
    )
    report = verify_epoch_advance_liveness(state)
    assert not report.is_allowed
    assert REASON_EPOCH_ADVANCE_TIMESTAMP_IN_FUTURE in report.reasons


def test_one_minute_future_timestamp_within_tolerance():
    # 60s tolerance — exactly +60s is INSIDE the window.
    state = EpochAdvanceState(
        last_epoch_advance_unix=_T0 + 60,
        current_unix=_T0,
        last_advanced_epoch=10,
        current_epoch=10,
    )
    report = verify_epoch_advance_liveness(state)
    assert report.is_allowed


def test_negative_last_advanced_epoch_refused():
    state = EpochAdvanceState(
        last_epoch_advance_unix=_T0,
        current_unix=_T0 + 60,
        last_advanced_epoch=-1,
        current_epoch=10,
    )
    report = verify_epoch_advance_liveness(state)
    assert not report.is_allowed
    assert REASON_EPOCH_ADVANCE_EPOCH_INVALID in report.reasons


def test_current_epoch_less_than_advanced_refused():
    state = EpochAdvanceState(
        last_epoch_advance_unix=_T0,
        current_unix=_T0 + 60,
        last_advanced_epoch=20,
        current_epoch=10,  # behind the advanced epoch
    )
    report = verify_epoch_advance_liveness(state)
    assert not report.is_allowed
    assert REASON_EPOCH_ADVANCE_EPOCH_NOT_MONOTONIC in report.reasons


# ---------------------------------------------------------------------------
# Compound violations
# ---------------------------------------------------------------------------

def test_multiple_violations_reported_together():
    # Stall + future timestamp is impossible (future implies short
    # gap), but stall + epoch_invalid is possible.
    state = EpochAdvanceState(
        last_epoch_advance_unix=_T0,
        current_unix=_T0 + MAX_EPOCH_ADVANCE_STALL_SECONDS + 1,
        last_advanced_epoch=-1,
        current_epoch=10,
    )
    report = verify_epoch_advance_liveness(state)
    assert not report.is_allowed
    assert REASON_EPOCH_ADVANCE_STALL in report.reasons
    assert REASON_EPOCH_ADVANCE_EPOCH_INVALID in report.reasons


# ---------------------------------------------------------------------------
# Enforcement wrapper
# ---------------------------------------------------------------------------

def test_enforce_returns_report_on_fresh_advance():
    state = EpochAdvanceState(
        last_epoch_advance_unix=_T0,
        current_unix=_T0 + 60,
        last_advanced_epoch=10,
        current_epoch=10,
    )
    report = enforce_epoch_advance_liveness(state)
    assert report.is_allowed


def test_enforce_raises_on_stall():
    state = EpochAdvanceState(
        last_epoch_advance_unix=_T0,
        current_unix=_T0 + MAX_EPOCH_ADVANCE_STALL_SECONDS + 1,
        last_advanced_epoch=10,
        current_epoch=10,
    )
    with pytest.raises(EpochAdvanceStallError) as excinfo:
        enforce_epoch_advance_liveness(state)
    assert "FRP-2" in str(excinfo.value)
    assert excinfo.value.report.status == EPOCH_ADVANCE_REFUSED
    assert REASON_EPOCH_ADVANCE_STALL in excinfo.value.report.reasons


# ---------------------------------------------------------------------------
# Audit scenarios — the exact attacks the gate exists for
# ---------------------------------------------------------------------------

def test_audit_scenario_48h_stall_refused_before_tier2():
    # Path 3 sub-leaf 3b: attacker withholds advance attestations
    # for 48h (the AW-02 Tier-2 fallback window). FRP-2 refuses at
    # 36h+1s, well before Tier-2 even engages.
    state = EpochAdvanceState(
        last_epoch_advance_unix=_T0,
        current_unix=_T0 + 48 * 3600,
        last_advanced_epoch=10,
        current_epoch=10,
    )
    with pytest.raises(EpochAdvanceStallError) as excinfo:
        enforce_epoch_advance_liveness(state)
    report = excinfo.value.report
    assert REASON_EPOCH_ADVANCE_STALL in report.reasons
    assert report.seconds_since_last == 48 * 3600


def test_audit_scenario_28h_outage_still_ok():
    # Historical legitimate outage window (~28h on devnet). FRP-2
    # must NOT refuse this — 28h < 36h floor.
    state = EpochAdvanceState(
        last_epoch_advance_unix=_T0,
        current_unix=_T0 + 28 * 3600,
        last_advanced_epoch=10,
        current_epoch=10,
    )
    report = enforce_epoch_advance_liveness(state)
    assert report.is_allowed
