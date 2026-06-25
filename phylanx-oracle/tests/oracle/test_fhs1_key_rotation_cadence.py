"""
tests/oracle/test_fhs1_key_rotation_cadence.py — FHS-1 cluster-key
rotation cadence floor.

Pins:
  - Constants (MAX_KEY_AGE=90d, WARN_KEY_AGE=60d, future-skew
    tolerance=60s).
  - 30d-old key is OK; 70d-old key is WARN; 100d-old key is OVERDUE.
  - Inclusive boundary: exactly MAX_KEY_AGE_SECONDS is OK, one
    second past is OVERDUE.
  - Inclusive boundary: exactly WARN_KEY_AGE_SECONDS is OK, one
    second past is WARN.
  - Future-dated key refused with KEY_BIRTH_IN_FUTURE for every
    cluster geometry.
  - Small clock skew (< 60s) tolerated; age clamps to 0.
  - Mixed report: a cluster with OK / WARN / OVERDUE keys reports
    all three statuses and refuses overall.
  - Enforcement raises KeyRotationOverdueError with the report
    attached on refusal.
  - Audit-scenario: a 3-key compromise sat silent for 95 days is
    REFUSED at the cadence floor.
"""

from __future__ import annotations

import pytest

from oracle.key_rotation_cadence import (
    CADENCE_FUTURE_TOLERANCE_SECONDS,
    CADENCE_OK,
    CADENCE_OVERDUE,
    CADENCE_WARN,
    ClusterKeySnapshot,
    KeyRotationOverdueError,
    MAX_KEY_AGE_SECONDS,
    REASON_KEY_BIRTH_IN_FUTURE,
    REASON_KEY_NEAR_ROTATION_FLOOR,
    REASON_KEY_PAST_ROTATION_FLOOR,
    WARN_KEY_AGE_SECONDS,
    enforce_key_rotation_cadence,
    verify_key_rotation_cadence,
)


NOW = 1_700_000_000
DAY = 24 * 3600


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    assert MAX_KEY_AGE_SECONDS == 90 * 24 * 3600
    assert WARN_KEY_AGE_SECONDS == 60 * 24 * 3600
    assert CADENCE_FUTURE_TOLERANCE_SECONDS == 60


def test_warn_strictly_below_max():
    # The WARN threshold must be strictly below MAX so operators have a
    # window to schedule the ceremony.
    assert WARN_KEY_AGE_SECONDS < MAX_KEY_AGE_SECONDS


# ---------------------------------------------------------------------------
# Single-key matrix
# ---------------------------------------------------------------------------

def _key(pubkey: str, age_days: int) -> ClusterKeySnapshot:
    return ClusterKeySnapshot(pubkey=pubkey, birth_unix=NOW - age_days * DAY)


def test_fresh_key_is_ok():
    report = verify_key_rotation_cadence([_key("kA", 30)], current_unix=NOW)
    assert report.is_allowed
    v = report.verdicts[0]
    assert v.status == CADENCE_OK
    assert v.reasons == ()


def test_warn_window_key():
    report = verify_key_rotation_cadence([_key("kA", 70)], current_unix=NOW)
    assert report.is_allowed  # WARN does not refuse
    v = report.verdicts[0]
    assert v.status == CADENCE_WARN
    assert REASON_KEY_NEAR_ROTATION_FLOOR in v.reasons


def test_overdue_key_refused():
    report = verify_key_rotation_cadence([_key("kA", 100)], current_unix=NOW)
    assert not report.is_allowed
    v = report.verdicts[0]
    assert v.status == CADENCE_OVERDUE
    assert REASON_KEY_PAST_ROTATION_FLOOR in v.reasons


# ---------------------------------------------------------------------------
# Boundary conditions
# ---------------------------------------------------------------------------

def test_at_exact_max_age_is_warn_not_overdue():
    # Inclusive boundary: exactly == MAX is NOT yet OVERDUE; the key
    # has been in the WARN window for the last 30 days and remains
    # accepted at the floor. Strictly past MAX is OVERDUE.
    key = ClusterKeySnapshot(pubkey="kA", birth_unix=NOW - MAX_KEY_AGE_SECONDS)
    report = verify_key_rotation_cadence([key], current_unix=NOW)
    assert report.verdicts[0].status == CADENCE_WARN
    assert report.is_allowed


def test_one_second_past_max_is_overdue():
    key = ClusterKeySnapshot(
        pubkey="kA", birth_unix=NOW - (MAX_KEY_AGE_SECONDS + 1),
    )
    report = verify_key_rotation_cadence([key], current_unix=NOW)
    assert report.verdicts[0].status == CADENCE_OVERDUE


def test_at_exact_warn_age_is_ok():
    key = ClusterKeySnapshot(
        pubkey="kA", birth_unix=NOW - WARN_KEY_AGE_SECONDS,
    )
    report = verify_key_rotation_cadence([key], current_unix=NOW)
    assert report.verdicts[0].status == CADENCE_OK


def test_one_second_past_warn_is_warn():
    key = ClusterKeySnapshot(
        pubkey="kA", birth_unix=NOW - (WARN_KEY_AGE_SECONDS + 1),
    )
    report = verify_key_rotation_cadence([key], current_unix=NOW)
    assert report.verdicts[0].status == CADENCE_WARN


# ---------------------------------------------------------------------------
# Time-travel defense
# ---------------------------------------------------------------------------

def test_future_dated_key_refused():
    key = ClusterKeySnapshot(pubkey="kA", birth_unix=NOW + 600)
    report = verify_key_rotation_cadence([key], current_unix=NOW)
    v = report.verdicts[0]
    assert v.status == CADENCE_OVERDUE
    assert REASON_KEY_BIRTH_IN_FUTURE in v.reasons
    assert v.age_seconds == 0  # clamped


def test_small_skew_within_tolerance_is_ok():
    key = ClusterKeySnapshot(pubkey="kA", birth_unix=NOW + 30)
    report = verify_key_rotation_cadence([key], current_unix=NOW)
    v = report.verdicts[0]
    assert v.status == CADENCE_OK
    assert v.age_seconds == 0


# ---------------------------------------------------------------------------
# Multi-key report
# ---------------------------------------------------------------------------

def test_mixed_cluster_reports_all_three_statuses():
    keys = [
        _key("ok",      30),
        _key("warn",    65),
        _key("overdue", 95),
    ]
    report = verify_key_rotation_cadence(keys, current_unix=NOW)
    assert not report.is_allowed
    assert "overdue" in report.overdue_keys
    assert "warn" in report.warning_keys
    statuses = {v.pubkey: v.status for v in report.verdicts}
    assert statuses == {
        "ok":      CADENCE_OK,
        "warn":    CADENCE_WARN,
        "overdue": CADENCE_OVERDUE,
    }


def test_empty_cluster_is_allowed():
    # Empty input never refuses — the on-chain handler refuses an
    # empty cluster on its own.
    report = verify_key_rotation_cadence([], current_unix=NOW)
    assert report.is_allowed
    assert report.verdicts == ()


# ---------------------------------------------------------------------------
# Enforcement wrapper
# ---------------------------------------------------------------------------

def test_enforce_returns_report_on_fresh_cluster():
    keys = [_key(f"k{i}", 10) for i in range(5)]
    report = enforce_key_rotation_cadence(keys, current_unix=NOW)
    assert report.is_allowed


def test_enforce_raises_on_overdue_key():
    keys = [_key(f"k{i}", 10) for i in range(4)] + [_key("k4_overdue", 100)]
    with pytest.raises(KeyRotationOverdueError) as excinfo:
        enforce_key_rotation_cadence(keys, current_unix=NOW)
    assert "FHS-1" in str(excinfo.value)
    assert "k4_overdue" in excinfo.value.report.overdue_keys


# ---------------------------------------------------------------------------
# Audit scenario — the exact attack the gate exists for
# ---------------------------------------------------------------------------

def test_audit_scenario_compromise_silent_for_95_days_refused():
    # Path 1 sub-leaf 1a: attacker compromises 3 keys, lets them sit
    # silent for ~3 months waiting for the optimal moment. FHS-1
    # refuses the cluster topology at the 90-day floor regardless of
    # whether the keys have signed anything yet.
    keys = [
        _key("kH1", 30),
        _key("kH2", 30),
        _key("kA1", 95),  # compromised, dwelling
        _key("kA2", 95),  # compromised, dwelling
        _key("kA3", 95),  # compromised, dwelling
    ]
    with pytest.raises(KeyRotationOverdueError) as excinfo:
        enforce_key_rotation_cadence(keys, current_unix=NOW)
    overdue = set(excinfo.value.report.overdue_keys)
    assert overdue == {"kA1", "kA2", "kA3"}
