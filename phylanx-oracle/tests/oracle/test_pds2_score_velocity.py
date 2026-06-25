"""
tests/oracle/test_pds2_score_velocity.py — PDS-2 score-velocity contract.

Pins:
  - Constants (MAX_SCORE_DELTA_PER_EPOCH=200, MAX_SCORE_VELOCITY_PER_HOUR=100,
    ABSURD_VELOCITY_PER_HOUR=500, MIN_ELAPSED_SECONDS_FOR_VELOCITY=60).
  - Healthy pairs are safe (delta within ±200, velocity within ±100/h).
  - Per-epoch delta > 200 fires REASON_DELTA.
  - Per-hour velocity > 100 fires REASON_VELOCITY (but < 500).
  - Per-hour velocity > 500 fires REASON_ABSURD.
  - Downward moves are gated by the same absolute caps.
  - Same-second pairs skip the velocity check but still enforce the
    per-epoch delta cap.
  - Time-travel (previous_issued_at > current_issued_at) flags
    REASON_TIME_TRAVEL.
  - enforce_score_velocity raises with the report attached.
"""

from __future__ import annotations

import math

import pytest

from oracle.score_velocity import (
    ABSURD_VELOCITY_PER_HOUR,
    MAX_SCORE_DELTA_PER_EPOCH,
    MAX_SCORE_VELOCITY_PER_HOUR,
    MIN_ELAPSED_SECONDS_FOR_VELOCITY,
    REASON_ABSURD,
    REASON_DELTA,
    REASON_TIME_TRAVEL,
    REASON_VELOCITY,
    ScoreVelocityError,
    enforce_score_velocity,
    verify_score_velocity,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    assert MAX_SCORE_DELTA_PER_EPOCH == 200
    assert MAX_SCORE_VELOCITY_PER_HOUR == 100
    assert ABSURD_VELOCITY_PER_HOUR == 500
    assert MIN_ELAPSED_SECONDS_FOR_VELOCITY == 60


# ---------------------------------------------------------------------------
# Healthy pairs
# ---------------------------------------------------------------------------

def test_modest_move_passes():
    report = verify_score_velocity(
        current_score=720, current_issued_at=10_000,
        previous_score=700, previous_issued_at=10_000 - 7200,  # 2h prior
    )
    assert report.is_safe
    assert report.score_delta == 20
    assert math.isclose(report.velocity_per_hour, 10.0, rel_tol=1e-6)


def test_zero_delta_passes():
    report = verify_score_velocity(
        current_score=800, current_issued_at=20_000,
        previous_score=800, previous_issued_at=10_000,
    )
    assert report.is_safe
    assert report.score_delta == 0
    assert report.velocity_per_hour == 0.0


# ---------------------------------------------------------------------------
# Per-epoch delta cap
# ---------------------------------------------------------------------------

def test_delta_at_cap_passes():
    # Exactly 200 — at the cap, not over.
    report = verify_score_velocity(
        current_score=900, current_issued_at=10_000,
        previous_score=700, previous_issued_at=10_000 - 7200,  # 2h
    )
    assert report.is_safe


def test_delta_over_cap_rejected():
    report = verify_score_velocity(
        current_score=920, current_issued_at=10_000,
        previous_score=700, previous_issued_at=10_000 - 7200,
    )
    assert REASON_DELTA in report.reasons


def test_downward_delta_over_cap_rejected():
    report = verify_score_velocity(
        current_score=400, current_issued_at=10_000,
        previous_score=700, previous_issued_at=10_000 - 7200,
    )
    assert REASON_DELTA in report.reasons


# ---------------------------------------------------------------------------
# Per-hour velocity cap
# ---------------------------------------------------------------------------

def test_velocity_over_cap_under_absurd_rejected():
    # 150 points in 1 hour -> 150 pts/h > 100 cap, < 500 absurd floor.
    report = verify_score_velocity(
        current_score=850, current_issued_at=10_000,
        previous_score=700, previous_issued_at=10_000 - 3600,
    )
    assert REASON_VELOCITY in report.reasons
    assert REASON_ABSURD not in report.reasons


def test_absurd_velocity_classified_separately():
    # 200 points in 5 minutes -> 2400 pts/h, well past 500 absurd floor.
    # But the per-epoch delta is exactly 200 — at the cap, not over.
    report = verify_score_velocity(
        current_score=700, current_issued_at=10_300,
        previous_score=500, previous_issued_at=10_000,  # 300s = 5m
    )
    assert REASON_ABSURD in report.reasons
    # The cluster's per-epoch cap is independent. 200 == cap, so REASON_DELTA
    # should NOT fire (strict >).
    assert REASON_DELTA not in report.reasons


def test_absurd_supersedes_velocity():
    # When the velocity is absurdly high, ONLY the absurd reason fires
    # (not VELOCITY) — they are mutually exclusive classifications of
    # the same underlying signal.
    report = verify_score_velocity(
        current_score=900, current_issued_at=10_300,
        previous_score=700, previous_issued_at=10_000,
    )
    assert REASON_ABSURD in report.reasons
    assert REASON_VELOCITY not in report.reasons


def test_downward_velocity_over_cap_rejected():
    # A sharp downward move is also a credibility anomaly.
    report = verify_score_velocity(
        current_score=550, current_issued_at=10_000,
        previous_score=700, previous_issued_at=10_000 - 3600,
    )
    assert REASON_VELOCITY in report.reasons


# ---------------------------------------------------------------------------
# Short elapsed window
# ---------------------------------------------------------------------------

def test_same_second_skips_velocity_but_keeps_delta_cap():
    # Elapsed = 0 — velocity math is undefined (NaN), but the per-epoch
    # delta still applies. A 300-point jump in zero seconds is rejected
    # via REASON_DELTA, not via velocity.
    report = verify_score_velocity(
        current_score=900, current_issued_at=10_000,
        previous_score=600, previous_issued_at=10_000,
    )
    assert math.isnan(report.velocity_per_hour)
    assert REASON_DELTA in report.reasons
    assert REASON_VELOCITY not in report.reasons


def test_elapsed_under_floor_skips_velocity():
    # 30 seconds — below MIN_ELAPSED_SECONDS_FOR_VELOCITY=60, velocity is
    # NaN. The per-epoch delta cap still applies.
    report = verify_score_velocity(
        current_score=720, current_issued_at=10_030,
        previous_score=700, previous_issued_at=10_000,
    )
    assert math.isnan(report.velocity_per_hour)
    assert report.is_safe  # 20-point delta is below the 200 cap


# ---------------------------------------------------------------------------
# Time travel
# ---------------------------------------------------------------------------

def test_previous_after_current_flagged():
    # Previous cert claims a later issued_at than the current cert.
    report = verify_score_velocity(
        current_score=700, current_issued_at=9_000,
        previous_score=600, previous_issued_at=10_000,
    )
    assert REASON_TIME_TRAVEL in report.reasons
    # elapsed is clamped to 0 in the report so consumers see a clean
    # "elapsed = 0" rather than a negative number.
    assert report.elapsed_seconds == 0


# ---------------------------------------------------------------------------
# enforce wrapper
# ---------------------------------------------------------------------------

def test_enforce_raises_on_anomaly():
    with pytest.raises(ScoreVelocityError) as excinfo:
        enforce_score_velocity(
            current_score=950, current_issued_at=10_000,
            previous_score=600, previous_issued_at=10_000 - 3600,
        )
    assert excinfo.value.report.score_delta == 350
    assert "PDS-2" in str(excinfo.value)


def test_enforce_returns_report_on_safe_pair():
    report = enforce_score_velocity(
        current_score=720, current_issued_at=10_000,
        previous_score=700, previous_issued_at=10_000 - 7200,
    )
    assert report.is_safe


# ---------------------------------------------------------------------------
# Death-spiral arithmetic — the regression case the gate exists for
# ---------------------------------------------------------------------------

def test_30_epoch_slow_drift_each_step_under_caps_overall_caught_by_per_epoch():
    # The death-spiral's attack model: drift +50 per epoch for 30 epochs.
    # Per-epoch delta 50 is below the 200 cap (so this gate alone does
    # NOT catch it — PDS-1 catches the system-wide saturation, and
    # VULN-03 catches the per-agent slow drift). Pinning this here so
    # that anyone reading the test suite SEES the design tradeoff: PDS-2
    # bounds the worst-case-PER-PAIR move; the slow drift across many
    # pairs is the responsibility of VULN-03 + PDS-1.
    report = verify_score_velocity(
        current_score=650, current_issued_at=10_000,
        previous_score=600, previous_issued_at=10_000 - 7200,
    )
    assert report.is_safe


def test_30_epoch_aggregate_inflation_each_step_explicit_attack():
    # Direct attack via ONE huge jump (1500 over 30 epochs collapsed into
    # one pair). PDS-2 catches the per-pair anomaly.
    report = verify_score_velocity(
        current_score=900, current_issued_at=10_000,
        previous_score=600, previous_issued_at=10_000 - 7200,
    )
    assert REASON_DELTA in report.reasons
