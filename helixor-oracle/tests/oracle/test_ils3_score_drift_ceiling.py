"""
tests/oracle/test_ils3_score_drift_ceiling.py — ILS-3 cumulative
score-drift ceiling.

Pins:
  - Constants (MAX_DRIFT_FROM_BASELINE_RATIO=0.30,
    MAX_MONOTONIC_DRIFT_EPOCHS=10, MAX_DRIFT_PER_EPOCH_RATIO=0.05,
    DRIFT_FUTURE_TOLERANCE_EPOCHS=1).
  - Stable score history (no drift) is OK.
  - Cumulative drift exactly at +30% is OK; +31% refused with
    DRIFT_OVER_CUMULATIVE_CEILING.
  - Per-epoch jump exactly +5% is OK; +6% refused with
    DRIFT_OVER_PER_EPOCH_CEILING.
  - 9-step monotonic upward run is OK; 10-step refused with
    DRIFT_MONOTONIC_TOO_LONG.
  - Downward drift never refuses on cumulative-ceiling axis.
  - Non-positive baseline refused with DRIFT_BASELINE_NON_POSITIVE.
  - Empty history refused with DRIFT_HISTORY_EMPTY.
  - Non-monotonic epochs refused with DRIFT_EPOCH_NOT_MONOTONIC.
  - Future-dated epoch refused with DRIFT_EPOCH_IN_FUTURE.
  - Enforcement raises ScoreDriftCeilingError on refusal.
  - Audit-scenario: 30-epoch slow drift of 4% per epoch
    (cumulative ~3.24x, well past 30%) — REFUSED at
    DRIFT_OVER_CUMULATIVE_CEILING.
  - Audit-scenario: 12-15% per-epoch attack — REFUSED at
    DRIFT_OVER_PER_EPOCH_CEILING (5% per-epoch belt-and-braces
    catches it on the first jump).
"""

from __future__ import annotations

import pytest

from oracle.score_drift_ceiling import (
    AgentScoreTrajectory,
    DRIFT_FUTURE_TOLERANCE_EPOCHS,
    DRIFT_OK,
    DRIFT_REFUSED,
    MAX_DRIFT_FROM_BASELINE_RATIO,
    MAX_DRIFT_PER_EPOCH_RATIO,
    MAX_MONOTONIC_DRIFT_EPOCHS,
    REASON_DRIFT_BASELINE_NON_POSITIVE,
    REASON_DRIFT_EPOCH_IN_FUTURE,
    REASON_DRIFT_EPOCH_NOT_MONOTONIC,
    REASON_DRIFT_HISTORY_EMPTY,
    REASON_DRIFT_MONOTONIC_TOO_LONG,
    REASON_DRIFT_OVER_CUMULATIVE_CEILING,
    REASON_DRIFT_OVER_PER_EPOCH_CEILING,
    ScoreDriftCeilingError,
    ScoreHistoryEntry,
    enforce_score_drift_ceiling,
    verify_score_drift_ceiling,
)


AGENT = "agent-wallet"


def _entry(epoch: int, score: float) -> ScoreHistoryEntry:
    return ScoreHistoryEntry(epoch=epoch, score=score)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    assert MAX_DRIFT_FROM_BASELINE_RATIO == 0.30
    assert MAX_MONOTONIC_DRIFT_EPOCHS == 10
    assert MAX_DRIFT_PER_EPOCH_RATIO == 0.05
    assert DRIFT_FUTURE_TOLERANCE_EPOCHS == 1


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_stable_history_is_ok():
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=100.0,
        history=tuple(_entry(i, 100.0) for i in range(1, 21)),
        current_epoch=21,
    )
    report = verify_score_drift_ceiling(traj)
    assert report.is_allowed
    assert report.status == DRIFT_OK
    assert report.cumulative_drift_ratio == 0.0


def test_modest_upward_drift_is_ok():
    # +10% cumulative over 5 epochs at 2% per epoch — well within
    # all three ceilings.
    history = (
        _entry(1, 100.0),
        _entry(2, 102.0),
        _entry(3, 104.0),
        _entry(4, 107.0),
        _entry(5, 110.0),
    )
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=100.0,
        history=history,
        current_epoch=5,
    )
    report = verify_score_drift_ceiling(traj)
    assert report.is_allowed


# ---------------------------------------------------------------------------
# Cumulative ceiling boundary
# ---------------------------------------------------------------------------

def test_exactly_30_percent_drift_is_ok():
    # baseline=100, latest=130 -> cumulative=0.30 — INCLUSIVE at
    # the ceiling.
    history = (
        _entry(1, 100.0),
        _entry(20, 130.0),  # one big step skipped past per-epoch
    )
    # We need to avoid tripping the per-epoch ceiling; use 7
    # gradual steps of 4% each over many epochs.
    history = (
        _entry(1, 100.0),
        _entry(11, 104.0),
        _entry(21, 108.16),
        _entry(31, 112.48),
        _entry(41, 117.0),
        _entry(51, 121.6),
        _entry(61, 126.5),
        _entry(71, 130.0),
    )
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=100.0,
        history=history,
        current_epoch=71,
    )
    report = verify_score_drift_ceiling(traj)
    # Cumulative is exactly 0.30 — inclusive at floor.
    assert abs(report.cumulative_drift_ratio - 0.30) < 1e-6
    # The per-epoch ratios are ~4% each; under 5%.
    # The monotonic run is 7, under 10.
    assert report.is_allowed


def test_just_past_30_percent_drift_refused():
    # baseline=100, latest=131 -> cumulative=0.31 — past ceiling.
    # Spread to avoid per-epoch trips.
    history = (
        _entry(1, 100.0),
        _entry(11, 104.0),
        _entry(21, 108.16),
        _entry(31, 112.5),
        _entry(41, 117.0),
        _entry(51, 122.0),
        _entry(61, 126.0),
        _entry(71, 131.0),
    )
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=100.0,
        history=history,
        current_epoch=71,
    )
    report = verify_score_drift_ceiling(traj)
    assert not report.is_allowed
    assert REASON_DRIFT_OVER_CUMULATIVE_CEILING in report.reasons


# ---------------------------------------------------------------------------
# Per-epoch ceiling boundary
# ---------------------------------------------------------------------------

def test_exactly_five_percent_per_epoch_is_ok():
    # +5% per step is the inclusive boundary; not refused.
    history = (
        _entry(1, 100.0),
        _entry(2, 105.0),  # exactly +5%
    )
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=100.0,
        history=history,
        current_epoch=2,
    )
    report = verify_score_drift_ceiling(traj)
    assert report.is_allowed


def test_six_percent_per_epoch_refused():
    history = (
        _entry(1, 100.0),
        _entry(2, 106.0),  # +6%
    )
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=100.0,
        history=history,
        current_epoch=2,
    )
    report = verify_score_drift_ceiling(traj)
    assert not report.is_allowed
    assert REASON_DRIFT_OVER_PER_EPOCH_CEILING in report.reasons


# ---------------------------------------------------------------------------
# Monotonic-run ceiling
# ---------------------------------------------------------------------------

def test_nine_step_monotonic_run_is_ok():
    # 9 strictly-upward consecutive transitions — under the floor of
    # 10. (10 entries -> 9 transitions.)
    history = tuple(
        _entry(i, 100.0 + i * 0.5) for i in range(1, 11)
    )
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=100.0,
        history=history,
        current_epoch=10,
    )
    report = verify_score_drift_ceiling(traj)
    assert report.is_allowed
    assert report.longest_monotonic_run == 9


def test_ten_step_monotonic_run_refused():
    # 10 strictly-upward transitions — refused even though each
    # step is 0.5% (no per-epoch or cumulative violation).
    history = tuple(
        _entry(i, 100.0 + i * 0.5) for i in range(1, 12)
    )
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=100.0,
        history=history,
        current_epoch=11,
    )
    report = verify_score_drift_ceiling(traj)
    assert not report.is_allowed
    assert REASON_DRIFT_MONOTONIC_TOO_LONG in report.reasons
    assert report.longest_monotonic_run >= 10


# ---------------------------------------------------------------------------
# Downward drift never refuses on cumulative axis
# ---------------------------------------------------------------------------

def test_downward_drift_never_refused_on_cumulative():
    # Score drops from 100 to 50 — cumulative is -0.5, but the
    # ceiling is asymmetric: refusal is only on UPWARD drift.
    history = (
        _entry(1, 100.0),
        _entry(2, 95.0),
        _entry(3, 80.0),
        _entry(4, 60.0),
        _entry(5, 50.0),
    )
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=100.0,
        history=history,
        current_epoch=5,
    )
    report = verify_score_drift_ceiling(traj)
    # Downward steps may trip per-epoch ratio if > 5% absolute
    # change; check by sign — the per-epoch check is on upward
    # steps only (we computed step as relative change, and
    # downward yields negative which never exceeds 0.05).
    assert REASON_DRIFT_OVER_CUMULATIVE_CEILING not in report.reasons


# ---------------------------------------------------------------------------
# Pathological inputs
# ---------------------------------------------------------------------------

def test_zero_baseline_refused():
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=0.0,
        history=(_entry(1, 100.0),),
        current_epoch=1,
    )
    report = verify_score_drift_ceiling(traj)
    assert not report.is_allowed
    assert REASON_DRIFT_BASELINE_NON_POSITIVE in report.reasons


def test_negative_baseline_refused():
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=-5.0,
        history=(_entry(1, 100.0),),
        current_epoch=1,
    )
    report = verify_score_drift_ceiling(traj)
    assert not report.is_allowed
    assert REASON_DRIFT_BASELINE_NON_POSITIVE in report.reasons


def test_empty_history_refused():
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=100.0,
        history=(),
        current_epoch=1,
    )
    report = verify_score_drift_ceiling(traj)
    assert not report.is_allowed
    assert REASON_DRIFT_HISTORY_EMPTY in report.reasons


def test_non_monotonic_epochs_refused():
    # Epoch goes 1 -> 5 -> 3 — refused.
    history = (
        _entry(1, 100.0),
        _entry(5, 102.0),
        _entry(3, 104.0),
    )
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=100.0,
        history=history,
        current_epoch=5,
    )
    report = verify_score_drift_ceiling(traj)
    assert not report.is_allowed
    assert REASON_DRIFT_EPOCH_NOT_MONOTONIC in report.reasons


def test_future_dated_epoch_refused():
    history = (
        _entry(1, 100.0),
        _entry(100, 102.0),  # current_epoch=5, far future
    )
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=100.0,
        history=history,
        current_epoch=5,
    )
    report = verify_score_drift_ceiling(traj)
    assert not report.is_allowed
    assert REASON_DRIFT_EPOCH_IN_FUTURE in report.reasons


# ---------------------------------------------------------------------------
# Enforcement wrapper
# ---------------------------------------------------------------------------

def test_enforce_returns_report_on_stable_history():
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=100.0,
        history=(_entry(1, 100.0), _entry(2, 100.5)),
        current_epoch=2,
    )
    report = enforce_score_drift_ceiling(traj)
    assert report.is_allowed


def test_enforce_raises_on_cumulative_breach():
    history = (
        _entry(1, 100.0),
        _entry(11, 104.0),
        _entry(21, 108.0),
        _entry(31, 112.0),
        _entry(41, 117.0),
        _entry(51, 122.0),
        _entry(61, 128.0),
        _entry(71, 135.0),
    )
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=100.0,
        history=history,
        current_epoch=71,
    )
    with pytest.raises(ScoreDriftCeilingError) as excinfo:
        enforce_score_drift_ceiling(traj)
    assert "ILS-3" in str(excinfo.value)
    assert excinfo.value.report.status == DRIFT_REFUSED


# ---------------------------------------------------------------------------
# Audit scenarios — the exact attacks the gate exists for
# ---------------------------------------------------------------------------

def test_audit_scenario_30_epoch_slow_drift_refused():
    # Path 2 sub-leaf 2c: attacker pushes score up by 4% per
    # epoch for 30 epochs. Each step (4%) stays under the
    # cluster's per-epoch velocity gate (~30%) AND under ILS-3's
    # per-epoch 5% ceiling. But the cumulative compounding
    # 1.04^30 - 1 = 2.24, far past the 30% cumulative ceiling.
    history = []
    score = 100.0
    for i in range(1, 31):
        score *= 1.04
        history.append(_entry(i, score))
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=100.0,
        history=tuple(history),
        current_epoch=30,
    )
    with pytest.raises(ScoreDriftCeilingError) as excinfo:
        enforce_score_drift_ceiling(traj)
    report = excinfo.value.report
    assert REASON_DRIFT_OVER_CUMULATIVE_CEILING in report.reasons
    # Monotonic-run >= 10 also fires for a 30-step climb.
    assert REASON_DRIFT_MONOTONIC_TOO_LONG in report.reasons


def test_audit_scenario_12_percent_per_epoch_refused():
    # Path 2 sub-leaf 2c audit value: attacker submits ~12% above
    # cluster median per epoch. ILS-3's 5% per-epoch ceiling
    # refuses on the very first jump.
    history = (
        _entry(1, 100.0),
        _entry(2, 112.0),  # +12%
    )
    traj = AgentScoreTrajectory(
        agent_wallet=AGENT,
        baseline_score=100.0,
        history=history,
        current_epoch=2,
    )
    with pytest.raises(ScoreDriftCeilingError) as excinfo:
        enforce_score_drift_ceiling(traj)
    assert REASON_DRIFT_OVER_PER_EPOCH_CEILING in excinfo.value.report.reasons
