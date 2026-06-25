"""
tests/oracle/test_sol1_cluster_liveness.py — SOL-1 cluster-liveness
signal for Scenario C.

Pins:
  - Constants (WARN_QUIET_SECONDS=2h, SILENT_QUIET_SECONDS=4h,
    MIN_RECENT_NODES_FOR_ALIVE=3, future-skew tolerance=60s).
  - ALIVE band when the last cert is recent and quorum is healthy.
  - DEGRADED band when the cluster has been quiet past WARN but not
    past SILENT.
  - SILENT band when quiet past SILENT_QUIET_SECONDS.
  - SILENT band when nodes_recently_active falls below quorum even if
    a cert was recent (the cluster lost K-of-N capability).
  - SILENT band when the cluster has never signed (last_cert_unix=None).
  - SILENT band when last_cert_unix is meaningfully in the future
    (clock-rewind / time-travel defence).
  - Small clock skew (< 60s) is tolerated and the elapsed field clamps
    to zero rather than going negative.
  - Enforcement raises ClusterSilentError on SILENT with the report
    attached.
  - Audit scenario: a 5h cluster outage with healthy quorum is caught.
"""

from __future__ import annotations

import pytest

from oracle.cluster_liveness import (
    LIVENESS_ALIVE,
    LIVENESS_DEGRADED,
    LIVENESS_FUTURE_TOLERANCE_SECONDS,
    LIVENESS_SILENT,
    MIN_RECENT_NODES_FOR_ALIVE,
    REASON_LIVENESS_BELOW_QUORUM,
    REASON_LIVENESS_NO_CERTS_EVER,
    REASON_LIVENESS_QUIET_SILENT,
    REASON_LIVENESS_QUIET_WARN,
    REASON_LIVENESS_TIME_TRAVEL,
    SILENT_QUIET_SECONDS,
    WARN_QUIET_SECONDS,
    ClusterLivenessContext,
    ClusterSilentError,
    enforce_cluster_alive,
    verify_cluster_liveness,
)


NOW = 1_700_000_000


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    # Load-bearing audit floors. Any change must justify Scenario C
    # detectability against the new thresholds.
    assert WARN_QUIET_SECONDS == 2 * 3600
    assert SILENT_QUIET_SECONDS == 4 * 3600
    assert MIN_RECENT_NODES_FOR_ALIVE == 3
    assert LIVENESS_FUTURE_TOLERANCE_SECONDS == 60


# ---------------------------------------------------------------------------
# Healthy path — ALIVE
# ---------------------------------------------------------------------------

def test_recent_cert_with_quorum_is_alive():
    ctx = ClusterLivenessContext(
        last_cert_unix=NOW - 60,
        last_cert_epoch=10_000,
        nodes_recently_active=5,
    )
    report = verify_cluster_liveness(ctx, current_unix=NOW)
    assert report.is_alive
    assert report.band == LIVENESS_ALIVE
    assert report.reasons == ()
    assert report.seconds_since_last_cert == 60


def test_at_exactly_warn_boundary_is_alive():
    # Inclusive boundary: a cert exactly WARN_QUIET_SECONDS old is
    # still ALIVE; we want the warning to fire only strictly past the
    # boundary.
    ctx = ClusterLivenessContext(
        last_cert_unix=NOW - WARN_QUIET_SECONDS,
        last_cert_epoch=10_000,
        nodes_recently_active=5,
    )
    report = verify_cluster_liveness(ctx, current_unix=NOW)
    assert report.band == LIVENESS_ALIVE


# ---------------------------------------------------------------------------
# DEGRADED band
# ---------------------------------------------------------------------------

def test_quiet_past_warn_but_not_silent_is_degraded():
    ctx = ClusterLivenessContext(
        last_cert_unix=NOW - (WARN_QUIET_SECONDS + 600),
        last_cert_epoch=10_000,
        nodes_recently_active=5,
    )
    report = verify_cluster_liveness(ctx, current_unix=NOW)
    assert report.band == LIVENESS_DEGRADED
    assert REASON_LIVENESS_QUIET_WARN in report.reasons
    assert REASON_LIVENESS_QUIET_SILENT not in report.reasons
    assert not report.is_alive


def test_at_silent_boundary_is_degraded():
    # Inclusive boundary on the other side: exactly SILENT_QUIET_SECONDS
    # old is still DEGRADED. Strictly past becomes SILENT.
    ctx = ClusterLivenessContext(
        last_cert_unix=NOW - SILENT_QUIET_SECONDS,
        last_cert_epoch=10_000,
        nodes_recently_active=5,
    )
    report = verify_cluster_liveness(ctx, current_unix=NOW)
    assert report.band == LIVENESS_DEGRADED


# ---------------------------------------------------------------------------
# SILENT band
# ---------------------------------------------------------------------------

def test_quiet_past_silent_is_silent():
    ctx = ClusterLivenessContext(
        last_cert_unix=NOW - (SILENT_QUIET_SECONDS + 600),
        last_cert_epoch=10_000,
        nodes_recently_active=5,
    )
    report = verify_cluster_liveness(ctx, current_unix=NOW)
    assert report.band == LIVENESS_SILENT
    assert REASON_LIVENESS_QUIET_SILENT in report.reasons


def test_below_quorum_forces_silent_even_with_recent_cert():
    # A cluster that lost K-of-N capability cannot have produced an
    # honest cert; the recent cert is structurally suspect.
    ctx = ClusterLivenessContext(
        last_cert_unix=NOW - 60,
        last_cert_epoch=10_000,
        nodes_recently_active=2,  # below MIN_RECENT_NODES_FOR_ALIVE=3
    )
    report = verify_cluster_liveness(ctx, current_unix=NOW)
    assert report.band == LIVENESS_SILENT
    assert REASON_LIVENESS_BELOW_QUORUM in report.reasons


def test_never_signed_is_silent():
    ctx = ClusterLivenessContext(
        last_cert_unix=None,
        last_cert_epoch=None,
        nodes_recently_active=5,
    )
    report = verify_cluster_liveness(ctx, current_unix=NOW)
    assert report.band == LIVENESS_SILENT
    assert REASON_LIVENESS_NO_CERTS_EVER in report.reasons
    assert report.seconds_since_last_cert == -1


# ---------------------------------------------------------------------------
# Time-travel defense
# ---------------------------------------------------------------------------

def test_future_cert_past_tolerance_is_silent():
    # Last cert claims to be 10 minutes in the future — structurally
    # suspect, force SILENT.
    ctx = ClusterLivenessContext(
        last_cert_unix=NOW + 600,
        last_cert_epoch=10_001,
        nodes_recently_active=5,
    )
    report = verify_cluster_liveness(ctx, current_unix=NOW)
    assert report.band == LIVENESS_SILENT
    assert REASON_LIVENESS_TIME_TRAVEL in report.reasons


def test_small_clock_skew_within_tolerance_is_alive():
    # 30s of forward skew — within tolerance, treated as fresh.
    ctx = ClusterLivenessContext(
        last_cert_unix=NOW + 30,
        last_cert_epoch=10_001,
        nodes_recently_active=5,
    )
    report = verify_cluster_liveness(ctx, current_unix=NOW)
    assert report.band == LIVENESS_ALIVE
    assert report.seconds_since_last_cert == 0


# ---------------------------------------------------------------------------
# Enforcement wrapper
# ---------------------------------------------------------------------------

def test_enforce_returns_report_on_alive():
    ctx = ClusterLivenessContext(
        last_cert_unix=NOW - 60,
        last_cert_epoch=10_000,
        nodes_recently_active=5,
    )
    report = enforce_cluster_alive(ctx, current_unix=NOW)
    assert report.is_alive


def test_enforce_returns_report_on_degraded():
    # DEGRADED is NOT a refusal — only SILENT raises.
    ctx = ClusterLivenessContext(
        last_cert_unix=NOW - (WARN_QUIET_SECONDS + 600),
        last_cert_epoch=10_000,
        nodes_recently_active=5,
    )
    report = enforce_cluster_alive(ctx, current_unix=NOW)
    assert report.band == LIVENESS_DEGRADED


def test_enforce_raises_on_silent():
    ctx = ClusterLivenessContext(
        last_cert_unix=NOW - (SILENT_QUIET_SECONDS + 600),
        last_cert_epoch=10_000,
        nodes_recently_active=5,
    )
    with pytest.raises(ClusterSilentError) as excinfo:
        enforce_cluster_alive(ctx, current_unix=NOW)
    assert excinfo.value.report.band == LIVENESS_SILENT
    assert "SOL-1" in str(excinfo.value)


def test_enforce_raises_on_below_quorum():
    ctx = ClusterLivenessContext(
        last_cert_unix=NOW - 60,
        last_cert_epoch=10_000,
        nodes_recently_active=1,
    )
    with pytest.raises(ClusterSilentError) as excinfo:
        enforce_cluster_alive(ctx, current_unix=NOW)
    assert REASON_LIVENESS_BELOW_QUORUM in excinfo.value.report.reasons


# ---------------------------------------------------------------------------
# Audit scenario — the exact attack the gate exists for
# ---------------------------------------------------------------------------

def test_audit_scenario_c_step1_caught():
    # Scenario C step 1: "all 5 oracle nodes disrupted simultaneously."
    # 5 hours have elapsed since the last cert — well past
    # SILENT_QUIET_SECONDS but well INSIDE TA-6's 48h backstop. SOL-1
    # makes the cluster's silence visible to the consumer hours before
    # TA-6 would notice.
    ctx = ClusterLivenessContext(
        last_cert_unix=NOW - 5 * 3600,
        last_cert_epoch=10_000,
        nodes_recently_active=0,  # all 5 nodes unreachable
    )
    with pytest.raises(ClusterSilentError) as excinfo:
        enforce_cluster_alive(ctx, current_unix=NOW)
    report = excinfo.value.report
    assert report.band == LIVENESS_SILENT
    # BOTH the quiet-silent AND below-quorum reasons fire — defence in
    # depth.
    assert REASON_LIVENESS_QUIET_SILENT in report.reasons
    assert REASON_LIVENESS_BELOW_QUORUM in report.reasons
    assert report.seconds_since_last_cert == 5 * 3600
