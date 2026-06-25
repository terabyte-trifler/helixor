"""
tests/oracle/test_frp3_cert_reissue_cadence.py — FRP-3 cert-reissue
cadence floor (Path 3 sub-leaf 3c residual: DeFi consumer doesn't
check freshness, so the cluster must self-discipline its reissue
cadence).

Pins:
  - Constants (MAX_CERT_REISSUE_INTERVAL_SECONDS = 4*3600,
    CERT_REISSUE_FUTURE_TOLERANCE_SECONDS = 60,
    TA6_ONCHAIN_MAX_AGE_SECONDS = 48*3600).
  - Safety-margin factor (TA-6 ceiling / cluster floor) = 12 by
    construction.
  - Fresh reissue (seconds_since_last < floor) is OK.
  - Boundary: exactly MAX_CERT_REISSUE_INTERVAL_SECONDS is OK;
    floor + 1s is REFUSED with CERT_REISSUE_OVERDUE.
  - Empty agent_wallet refused with AGENT_WALLET_MISSING.
  - last_reissue_unix=0 refused with TIMESTAMP_INVALID.
  - last_reissue_unix > now + tolerance refused with
    TIMESTAMP_IN_FUTURE.
  - Enforcement raises CertReissueCadenceError on refusal.
  - Audit-scenario: sustained 12h reissue stall — refused
    (cluster fails closed long before TA-6's on-chain 48h
    ceiling fires).
"""

from __future__ import annotations

import pytest

from oracle.cert_reissue_cadence import (
    CERT_REISSUE_FUTURE_TOLERANCE_SECONDS,
    CERT_REISSUE_OK,
    CERT_REISSUE_REFUSED,
    CertReissueCadenceError,
    CertReissueSample,
    MAX_CERT_REISSUE_INTERVAL_SECONDS,
    REASON_CERT_REISSUE_AGENT_WALLET_MISSING,
    REASON_CERT_REISSUE_OVERDUE,
    REASON_CERT_REISSUE_TIMESTAMP_INVALID,
    REASON_CERT_REISSUE_TIMESTAMP_IN_FUTURE,
    TA6_ONCHAIN_MAX_AGE_SECONDS,
    enforce_cert_reissue_cadence,
    verify_cert_reissue_cadence,
)


_T0 = 1_800_000_000
AGENT = "agent-wallet"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    assert MAX_CERT_REISSUE_INTERVAL_SECONDS == 4 * 3600
    assert CERT_REISSUE_FUTURE_TOLERANCE_SECONDS == 60
    assert TA6_ONCHAIN_MAX_AGE_SECONDS == 48 * 3600


def test_safety_margin_factor_is_twelve():
    # The whole calibration story rests on the 12× margin between
    # the cluster-side floor and the on-chain TA-6 ceiling. Pin it.
    assert (
        TA6_ONCHAIN_MAX_AGE_SECONDS
        // MAX_CERT_REISSUE_INTERVAL_SECONDS
        == 12
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_fresh_reissue_is_ok():
    sample = CertReissueSample(
        agent_wallet=AGENT,
        last_reissue_unix=_T0,
        current_unix=_T0 + 600,  # 10 minutes ago
    )
    report = verify_cert_reissue_cadence(sample)
    assert report.is_allowed
    assert report.status == CERT_REISSUE_OK
    assert report.agent_wallet == AGENT
    assert report.seconds_since_last == 600
    assert report.reasons == ()


def test_report_carries_safety_margin_factor():
    sample = CertReissueSample(
        agent_wallet=AGENT,
        last_reissue_unix=_T0,
        current_unix=_T0 + 600,
    )
    report = verify_cert_reissue_cadence(sample)
    assert report.safety_margin_factor == 12
    assert report.ta6_onchain_ceiling == TA6_ONCHAIN_MAX_AGE_SECONDS
    assert report.reissue_floor == MAX_CERT_REISSUE_INTERVAL_SECONDS


# ---------------------------------------------------------------------------
# Cadence boundary
# ---------------------------------------------------------------------------

def test_exactly_4h_reissue_is_ok():
    sample = CertReissueSample(
        agent_wallet=AGENT,
        last_reissue_unix=_T0,
        current_unix=_T0 + MAX_CERT_REISSUE_INTERVAL_SECONDS,
    )
    report = verify_cert_reissue_cadence(sample)
    assert report.is_allowed
    assert report.seconds_since_last == MAX_CERT_REISSUE_INTERVAL_SECONDS


def test_one_second_past_4h_refused():
    sample = CertReissueSample(
        agent_wallet=AGENT,
        last_reissue_unix=_T0,
        current_unix=_T0 + MAX_CERT_REISSUE_INTERVAL_SECONDS + 1,
    )
    report = verify_cert_reissue_cadence(sample)
    assert not report.is_allowed
    assert report.status == CERT_REISSUE_REFUSED
    assert REASON_CERT_REISSUE_OVERDUE in report.reasons


# ---------------------------------------------------------------------------
# Pathological inputs
# ---------------------------------------------------------------------------

def test_empty_agent_wallet_refused():
    sample = CertReissueSample(
        agent_wallet="",
        last_reissue_unix=_T0,
        current_unix=_T0 + 60,
    )
    report = verify_cert_reissue_cadence(sample)
    assert not report.is_allowed
    assert REASON_CERT_REISSUE_AGENT_WALLET_MISSING in report.reasons


def test_zero_last_reissue_refused():
    sample = CertReissueSample(
        agent_wallet=AGENT,
        last_reissue_unix=0,
        current_unix=_T0,
    )
    report = verify_cert_reissue_cadence(sample)
    assert not report.is_allowed
    assert REASON_CERT_REISSUE_TIMESTAMP_INVALID in report.reasons


def test_future_reissue_refused():
    sample = CertReissueSample(
        agent_wallet=AGENT,
        last_reissue_unix=_T0 + 3600,  # 1h in future
        current_unix=_T0,
    )
    report = verify_cert_reissue_cadence(sample)
    assert not report.is_allowed
    assert REASON_CERT_REISSUE_TIMESTAMP_IN_FUTURE in report.reasons


def test_one_minute_future_reissue_within_tolerance():
    sample = CertReissueSample(
        agent_wallet=AGENT,
        last_reissue_unix=_T0 + 60,
        current_unix=_T0,
    )
    report = verify_cert_reissue_cadence(sample)
    assert report.is_allowed


# ---------------------------------------------------------------------------
# Compound violations
# ---------------------------------------------------------------------------

def test_multiple_violations_reported_together():
    # Empty agent + overdue + invalid timestamp (all three).
    sample = CertReissueSample(
        agent_wallet="",
        last_reissue_unix=0,
        current_unix=_T0,
    )
    report = verify_cert_reissue_cadence(sample)
    assert not report.is_allowed
    assert REASON_CERT_REISSUE_AGENT_WALLET_MISSING in report.reasons
    assert REASON_CERT_REISSUE_TIMESTAMP_INVALID in report.reasons


# ---------------------------------------------------------------------------
# Enforcement wrapper
# ---------------------------------------------------------------------------

def test_enforce_returns_report_on_fresh_reissue():
    sample = CertReissueSample(
        agent_wallet=AGENT,
        last_reissue_unix=_T0,
        current_unix=_T0 + 60,
    )
    report = enforce_cert_reissue_cadence(sample)
    assert report.is_allowed


def test_enforce_raises_on_overdue():
    sample = CertReissueSample(
        agent_wallet=AGENT,
        last_reissue_unix=_T0,
        current_unix=_T0 + MAX_CERT_REISSUE_INTERVAL_SECONDS + 1,
    )
    with pytest.raises(CertReissueCadenceError) as excinfo:
        enforce_cert_reissue_cadence(sample)
    assert "FRP-3" in str(excinfo.value)
    assert excinfo.value.report.status == CERT_REISSUE_REFUSED
    assert REASON_CERT_REISSUE_OVERDUE in excinfo.value.report.reasons


# ---------------------------------------------------------------------------
# Audit scenarios — the exact attacks the gate exists for
# ---------------------------------------------------------------------------

def test_audit_scenario_12h_reissue_stall_refused():
    # Path 3 sub-leaf 3c: cluster cert-reissue pipeline stalls for
    # 12h (3× the cluster floor). Long before TA-6's 48h ceiling
    # fires; a freshness-blind DeFi consumer would still be lending
    # against the cert. FRP-3 refuses at 4h+1s, far before that
    # exposure.
    sample = CertReissueSample(
        agent_wallet=AGENT,
        last_reissue_unix=_T0,
        current_unix=_T0 + 12 * 3600,
    )
    with pytest.raises(CertReissueCadenceError) as excinfo:
        enforce_cert_reissue_cadence(sample)
    report = excinfo.value.report
    assert REASON_CERT_REISSUE_OVERDUE in report.reasons
    assert report.seconds_since_last == 12 * 3600
    # Still well under the on-chain TA-6 ceiling, demonstrating
    # the cluster fails closed BEFORE on-chain protection fires.
    assert report.seconds_since_last < TA6_ONCHAIN_MAX_AGE_SECONDS


def test_audit_scenario_3h_reissue_lag_still_ok():
    # Cluster is mildly behind cadence but within the 4h floor.
    # Must NOT refuse — this is a normal operational lag.
    sample = CertReissueSample(
        agent_wallet=AGENT,
        last_reissue_unix=_T0,
        current_unix=_T0 + 3 * 3600,
    )
    report = enforce_cert_reissue_cadence(sample)
    assert report.is_allowed
