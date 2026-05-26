"""
tests/oracle/test_sol3_operation_freshness.py — SOL-3 per-operation
freshness floor.

Pins:
  - Constants (LOAN_ISSUE=4h, LOAN_INCREASE=8h, LIQUIDATION_CHECK=12h,
    STATUS_READ=48h, future-skew tolerance=60s).
  - LOAN_ISSUE refuses a 5h-old cert; STATUS_READ accepts the same cert.
  - LOAN_INCREASE refuses 9h, accepts 7h.
  - LIQUIDATION_CHECK refuses 13h, accepts 11h.
  - STATUS_READ accepts up to 48h (matches TA-6); refuses past 48h.
  - Inclusive boundary: exactly max-age is allowed; strictly past is
    refused.
  - Future-dated cert refused with time-travel reason for every
    operation.
  - Small clock skew (< 60s) tolerated; age clamps to 0.
  - Enforcement raises StaleForOperationError with the report attached
    on refusal.
  - Mapping mirrors module: every Operation enum has an entry in
    OPERATION_MAX_AGE_SECONDS.
  - Audit-scenario: a 5h-old cert during a cluster outage refuses
    LOAN_ISSUE so a DeFi protocol cannot open a new loan against
    stale data.
"""

from __future__ import annotations

import pytest

from oracle.operation_freshness import (
    LIQUIDATION_CHECK_MAX_AGE_SECONDS,
    LOAN_INCREASE_MAX_AGE_SECONDS,
    LOAN_ISSUE_MAX_AGE_SECONDS,
    OPERATION_FUTURE_TOLERANCE_SECONDS,
    OPERATION_MAX_AGE_SECONDS,
    REASON_OPERATION_CERT_TOO_OLD,
    REASON_OPERATION_TIME_TRAVEL,
    STATUS_READ_MAX_AGE_SECONDS,
    Operation,
    StaleForOperationError,
    enforce_operation_freshness,
    verify_operation_freshness,
)


NOW = 1_700_000_000


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    assert LOAN_ISSUE_MAX_AGE_SECONDS == 4 * 3600
    assert LOAN_INCREASE_MAX_AGE_SECONDS == 8 * 3600
    assert LIQUIDATION_CHECK_MAX_AGE_SECONDS == 12 * 3600
    assert STATUS_READ_MAX_AGE_SECONDS == 48 * 3600
    assert OPERATION_FUTURE_TOLERANCE_SECONDS == 60


def test_status_read_floor_matches_ta6_48h():
    # STATUS_READ MUST equal TA-6's 48h backstop so SOL-3 never refuses
    # a cert TA-6 would accept for the most permissive operation.
    assert STATUS_READ_MAX_AGE_SECONDS == 48 * 3600


def test_operation_mapping_is_complete():
    # Every Operation enum value must have an entry in the mapping.
    for op in Operation:
        assert op in OPERATION_MAX_AGE_SECONDS, op


# ---------------------------------------------------------------------------
# Per-operation allow / deny matrix
# ---------------------------------------------------------------------------

def test_loan_issue_refuses_5h_cert():
    report = verify_operation_freshness(
        operation=Operation.LOAN_ISSUE,
        issued_at_unix=NOW - (5 * 3600),
        current_unix=NOW,
    )
    assert not report.is_allowed
    assert REASON_OPERATION_CERT_TOO_OLD in report.reasons


def test_status_read_accepts_5h_cert():
    # Same cert, different operation — accepted.
    report = verify_operation_freshness(
        operation=Operation.STATUS_READ,
        issued_at_unix=NOW - (5 * 3600),
        current_unix=NOW,
    )
    assert report.is_allowed
    assert report.reasons == ()


def test_loan_increase_refuses_9h_accepts_7h():
    refused = verify_operation_freshness(
        operation=Operation.LOAN_INCREASE,
        issued_at_unix=NOW - (9 * 3600),
        current_unix=NOW,
    )
    assert not refused.is_allowed
    allowed = verify_operation_freshness(
        operation=Operation.LOAN_INCREASE,
        issued_at_unix=NOW - (7 * 3600),
        current_unix=NOW,
    )
    assert allowed.is_allowed


def test_liquidation_check_refuses_13h_accepts_11h():
    refused = verify_operation_freshness(
        operation=Operation.LIQUIDATION_CHECK,
        issued_at_unix=NOW - (13 * 3600),
        current_unix=NOW,
    )
    assert not refused.is_allowed
    allowed = verify_operation_freshness(
        operation=Operation.LIQUIDATION_CHECK,
        issued_at_unix=NOW - (11 * 3600),
        current_unix=NOW,
    )
    assert allowed.is_allowed


def test_status_read_refuses_past_48h():
    report = verify_operation_freshness(
        operation=Operation.STATUS_READ,
        issued_at_unix=NOW - (49 * 3600),
        current_unix=NOW,
    )
    assert not report.is_allowed


# ---------------------------------------------------------------------------
# Boundary conditions
# ---------------------------------------------------------------------------

def test_loan_issue_at_exactly_4h_allowed():
    # Inclusive boundary: == max_age is allowed; > max_age is refused.
    report = verify_operation_freshness(
        operation=Operation.LOAN_ISSUE,
        issued_at_unix=NOW - LOAN_ISSUE_MAX_AGE_SECONDS,
        current_unix=NOW,
    )
    assert report.is_allowed


def test_loan_issue_one_second_past_boundary_refused():
    report = verify_operation_freshness(
        operation=Operation.LOAN_ISSUE,
        issued_at_unix=NOW - (LOAN_ISSUE_MAX_AGE_SECONDS + 1),
        current_unix=NOW,
    )
    assert not report.is_allowed


# ---------------------------------------------------------------------------
# Time-travel defense
# ---------------------------------------------------------------------------

def test_future_cert_refused_for_every_operation():
    for op in Operation:
        report = verify_operation_freshness(
            operation=op,
            issued_at_unix=NOW + 600,
            current_unix=NOW,
        )
        assert not report.is_allowed, op
        assert REASON_OPERATION_TIME_TRAVEL in report.reasons


def test_small_skew_within_tolerance_allowed():
    report = verify_operation_freshness(
        operation=Operation.LOAN_ISSUE,
        issued_at_unix=NOW + 30,
        current_unix=NOW,
    )
    assert report.is_allowed
    assert report.cert_age_seconds == 0


# ---------------------------------------------------------------------------
# Enforcement wrapper
# ---------------------------------------------------------------------------

def test_enforce_raises_on_stale_loan_issue():
    with pytest.raises(StaleForOperationError) as excinfo:
        enforce_operation_freshness(
            operation=Operation.LOAN_ISSUE,
            issued_at_unix=NOW - (5 * 3600),
            current_unix=NOW,
        )
    assert excinfo.value.report.operation == Operation.LOAN_ISSUE
    assert "SOL-3" in str(excinfo.value)


def test_enforce_returns_report_on_fresh_loan_issue():
    report = enforce_operation_freshness(
        operation=Operation.LOAN_ISSUE,
        issued_at_unix=NOW - 60,
        current_unix=NOW,
    )
    assert report.is_allowed


# ---------------------------------------------------------------------------
# Audit scenario — the exact attack the gate exists for
# ---------------------------------------------------------------------------

def test_audit_scenario_c_step5_caught():
    # Scenario C step 5: "mass defaults with no warning." The cluster
    # has been down for 5 hours. TA-6 (48h) would still accept the
    # cert; SOL-1's cluster-liveness signal has already gone SILENT.
    # SOL-3 closes the loop: a DeFi protocol attempting LOAN_ISSUE
    # against this cert is REFUSED at the operation layer regardless
    # of the cert's individual freshness.
    with pytest.raises(StaleForOperationError) as excinfo:
        enforce_operation_freshness(
            operation=Operation.LOAN_ISSUE,
            issued_at_unix=NOW - (5 * 3600),
            current_unix=NOW,
        )
    report = excinfo.value.report
    assert report.cert_age_seconds == 5 * 3600
    assert report.max_age_seconds == LOAN_ISSUE_MAX_AGE_SECONDS
    assert REASON_OPERATION_CERT_TOO_OLD in report.reasons
