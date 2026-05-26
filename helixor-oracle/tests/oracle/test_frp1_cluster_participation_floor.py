"""
tests/oracle/test_frp1_cluster_participation_floor.py — FRP-1
cluster participation floor (Path 3 sub-leaf 3a residual: cluster-
wide pattern of "barely-quorate" rounds when an attacker withholds
commit-reveal shares).

Pins:
  - Constants (MIN_HEALTHY_PARTICIPATION_RATIO=0.8,
    MAX_BARELY_QUORATE_ROUNDS=3, BARELY_QUORATE_MARGIN=1,
    PARTICIPATION_FUTURE_TOLERANCE_EPOCHS=1).
  - Healthy history (5/5 per round) is OK.
  - Single barely-quorate round in a healthy history is OK.
  - Trailing run of exactly 3 barely-quorate rounds is OK
    (inclusive cap); 4 consecutive is REFUSED.
  - Non-trailing barely-quorate run does NOT trip the trailing-run
    test (the gate is specifically about a SUSTAINED tail).
  - Empty history is REFUSED with PARTICIPATION_HISTORY_EMPTY.
  - Zero quorum or zero total refused with
    PARTICIPATION_INVALID_QUORUM.
  - Non-monotonic epoch order refused with
    PARTICIPATION_EPOCH_NOT_MONOTONIC.
  - Future-epoch sample (> current + 1) refused with
    PARTICIPATION_EPOCH_IN_FUTURE.
  - PARTICIPATION_BELOW_HEALTHY_FLOOR is a complementary flag
    raised when the min ratio is below 0.8 AND the trailing run
    is >= MAX_BARELY_QUORATE_ROUNDS.
  - Enforcement raises ClusterParticipationFloorError on refusal.
  - Audit-scenario: sustained 4-round barely-quorate attack is
    REFUSED.
"""

from __future__ import annotations

import pytest

from oracle.cluster_participation_floor import (
    BARELY_QUORATE_MARGIN,
    ClusterParticipationFloorError,
    ClusterParticipationHistory,
    ClusterParticipationSample,
    MAX_BARELY_QUORATE_ROUNDS,
    MIN_HEALTHY_PARTICIPATION_RATIO,
    PARTICIPATION_FUTURE_TOLERANCE_EPOCHS,
    PARTICIPATION_OK,
    PARTICIPATION_REFUSED,
    REASON_PARTICIPATION_BARELY_QUORATE_TOO_LONG,
    REASON_PARTICIPATION_BELOW_HEALTHY_FLOOR,
    REASON_PARTICIPATION_EPOCH_IN_FUTURE,
    REASON_PARTICIPATION_EPOCH_NOT_MONOTONIC,
    REASON_PARTICIPATION_HISTORY_EMPTY,
    REASON_PARTICIPATION_INVALID_QUORUM,
    enforce_cluster_participation_floor,
    verify_cluster_participation_floor,
)


def _sample(
    epoch: int,
    participating: int,
    total: int = 5,
    quorum: int = 3,
) -> ClusterParticipationSample:
    return ClusterParticipationSample(
        epoch=epoch,
        participating_node_count=participating,
        total_node_count=total,
        quorum_threshold=quorum,
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    assert MIN_HEALTHY_PARTICIPATION_RATIO == 0.8
    assert MAX_BARELY_QUORATE_ROUNDS == 3
    assert BARELY_QUORATE_MARGIN == 1
    assert PARTICIPATION_FUTURE_TOLERANCE_EPOCHS == 1


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_full_participation_is_ok():
    # Five rounds, all 5/5 — clean.
    history = tuple(_sample(i, 5) for i in range(1, 6))
    state = ClusterParticipationHistory(
        history=history,
        current_epoch=6,
    )
    report = verify_cluster_participation_floor(state)
    assert report.is_allowed
    assert report.status == PARTICIPATION_OK
    assert report.barely_quorate_run == 0
    assert report.reasons == ()


def test_single_barely_quorate_round_in_healthy_history_ok():
    # 5,5,5,4,5 — the 4-participant round IS barely quorate (quorum+1)
    # but the trailing tail (the last round) is 5/5 so the run is 0.
    history = (
        _sample(1, 5), _sample(2, 5), _sample(3, 5),
        _sample(4, 4), _sample(5, 5),
    )
    state = ClusterParticipationHistory(
        history=history,
        current_epoch=5,
    )
    report = verify_cluster_participation_floor(state)
    assert report.is_allowed
    assert report.barely_quorate_run == 0


# ---------------------------------------------------------------------------
# Trailing-run boundary
# ---------------------------------------------------------------------------

def test_exactly_three_trailing_barely_quorate_rounds_ok():
    # Trailing run = 3 — inclusive at the cap.
    history = (
        _sample(1, 5), _sample(2, 5),
        _sample(3, 4), _sample(4, 4), _sample(5, 4),
    )
    state = ClusterParticipationHistory(
        history=history,
        current_epoch=5,
    )
    report = verify_cluster_participation_floor(state)
    # Run is exactly at the cap — allowed.
    assert report.barely_quorate_run == 3
    # 4/5 = 0.8 — exactly at the healthy floor, not strictly below.
    assert not (
        report.min_participation_ratio_seen
        < MIN_HEALTHY_PARTICIPATION_RATIO
    )
    assert report.is_allowed


def test_four_trailing_barely_quorate_rounds_refused():
    # Trailing run = 4 — past the cap.
    history = (
        _sample(1, 5),
        _sample(2, 4), _sample(3, 4), _sample(4, 4), _sample(5, 4),
    )
    state = ClusterParticipationHistory(
        history=history,
        current_epoch=5,
    )
    report = verify_cluster_participation_floor(state)
    assert not report.is_allowed
    assert report.status == PARTICIPATION_REFUSED
    assert REASON_PARTICIPATION_BARELY_QUORATE_TOO_LONG in report.reasons
    assert report.barely_quorate_run == 4


def test_exactly_quorum_count_is_barely_quorate():
    # K=3, participating=3 — quorum_threshold + BARELY_QUORATE_MARGIN
    # = 4, so 3 <= 4 -> barely quorate.
    history = (
        _sample(1, 5), _sample(2, 5),
        _sample(3, 3), _sample(4, 3), _sample(5, 3), _sample(6, 3),
    )
    state = ClusterParticipationHistory(
        history=history,
        current_epoch=6,
    )
    report = verify_cluster_participation_floor(state)
    assert report.barely_quorate_run == 4
    assert REASON_PARTICIPATION_BARELY_QUORATE_TOO_LONG in report.reasons


def test_non_trailing_barely_quorate_run_does_not_trip():
    # The barely-quorate run is in the MIDDLE; trailing tail is
    # healthy (5/5). The gate only fires on a SUSTAINED tail.
    history = (
        _sample(1, 4), _sample(2, 4), _sample(3, 4), _sample(4, 4),
        _sample(5, 5), _sample(6, 5),
    )
    state = ClusterParticipationHistory(
        history=history,
        current_epoch=6,
    )
    report = verify_cluster_participation_floor(state)
    assert report.is_allowed
    assert report.barely_quorate_run == 0


# ---------------------------------------------------------------------------
# Pathological inputs
# ---------------------------------------------------------------------------

def test_empty_history_refused():
    state = ClusterParticipationHistory(
        history=(),
        current_epoch=5,
    )
    report = verify_cluster_participation_floor(state)
    assert not report.is_allowed
    assert REASON_PARTICIPATION_HISTORY_EMPTY in report.reasons


def test_zero_quorum_refused():
    history = (
        _sample(1, 5, total=5, quorum=0),
    )
    state = ClusterParticipationHistory(
        history=history,
        current_epoch=1,
    )
    report = verify_cluster_participation_floor(state)
    assert not report.is_allowed
    assert REASON_PARTICIPATION_INVALID_QUORUM in report.reasons


def test_zero_total_refused():
    history = (
        ClusterParticipationSample(
            epoch=1,
            participating_node_count=0,
            total_node_count=0,
            quorum_threshold=3,
        ),
    )
    state = ClusterParticipationHistory(
        history=history,
        current_epoch=1,
    )
    report = verify_cluster_participation_floor(state)
    assert not report.is_allowed
    assert REASON_PARTICIPATION_INVALID_QUORUM in report.reasons


def test_non_monotonic_epoch_refused():
    history = (
        _sample(1, 5), _sample(5, 5), _sample(3, 5),
    )
    state = ClusterParticipationHistory(
        history=history,
        current_epoch=5,
    )
    report = verify_cluster_participation_floor(state)
    assert not report.is_allowed
    assert REASON_PARTICIPATION_EPOCH_NOT_MONOTONIC in report.reasons


def test_future_epoch_refused():
    # An epoch sample 5 past current_epoch is well past the +1
    # tolerance.
    history = (
        _sample(1, 5), _sample(2, 5), _sample(20, 5),
    )
    state = ClusterParticipationHistory(
        history=history,
        current_epoch=2,
    )
    report = verify_cluster_participation_floor(state)
    assert not report.is_allowed
    assert REASON_PARTICIPATION_EPOCH_IN_FUTURE in report.reasons


def test_one_epoch_future_is_within_tolerance():
    # current + 1 is inside the +1 tolerance window.
    history = (
        _sample(1, 5), _sample(2, 5), _sample(3, 5),
    )
    state = ClusterParticipationHistory(
        history=history,
        current_epoch=2,  # sample.epoch=3 == current+1
    )
    report = verify_cluster_participation_floor(state)
    assert report.is_allowed


# ---------------------------------------------------------------------------
# Compound violations
# ---------------------------------------------------------------------------

def test_below_healthy_floor_companion_flag():
    # 4 trailing rounds at 3/5 (ratio 0.6 < 0.8 floor). The
    # BELOW_HEALTHY_FLOOR flag fires in addition to the trailing-run
    # cap.
    history = (
        _sample(1, 5),
        _sample(2, 3), _sample(3, 3), _sample(4, 3), _sample(5, 3),
    )
    state = ClusterParticipationHistory(
        history=history,
        current_epoch=5,
    )
    report = verify_cluster_participation_floor(state)
    assert not report.is_allowed
    assert REASON_PARTICIPATION_BARELY_QUORATE_TOO_LONG in report.reasons
    assert REASON_PARTICIPATION_BELOW_HEALTHY_FLOOR in report.reasons
    assert report.min_participation_ratio_seen == 0.6


# ---------------------------------------------------------------------------
# Enforcement wrapper
# ---------------------------------------------------------------------------

def test_enforce_returns_report_on_healthy_history():
    history = tuple(_sample(i, 5) for i in range(1, 6))
    state = ClusterParticipationHistory(
        history=history,
        current_epoch=6,
    )
    report = enforce_cluster_participation_floor(state)
    assert report.is_allowed


def test_enforce_raises_on_sustained_barely_quorate():
    history = (
        _sample(1, 5),
        _sample(2, 4), _sample(3, 4), _sample(4, 4), _sample(5, 4),
    )
    state = ClusterParticipationHistory(
        history=history,
        current_epoch=5,
    )
    with pytest.raises(ClusterParticipationFloorError) as excinfo:
        enforce_cluster_participation_floor(state)
    assert "FRP-1" in str(excinfo.value)
    assert excinfo.value.report.status == PARTICIPATION_REFUSED
    assert (
        REASON_PARTICIPATION_BARELY_QUORATE_TOO_LONG
        in excinfo.value.report.reasons
    )


# ---------------------------------------------------------------------------
# Audit scenario — the exact attack the gate exists for
# ---------------------------------------------------------------------------

def test_audit_scenario_sustained_withholding_refused():
    # Path 3 sub-leaf 3a: attacker compromises 2 of 5 cluster nodes
    # and withholds reveals — 3 nodes (exactly quorum) keep
    # contributing. The cluster keeps closing rounds and would mint
    # certs at minimum quorum forever; FRP-1 refuses at the 4th
    # consecutive barely-quorate round.
    history = (
        _sample(1, 5),
        _sample(2, 3), _sample(3, 3), _sample(4, 3), _sample(5, 3),
    )
    state = ClusterParticipationHistory(
        history=history,
        current_epoch=5,
    )
    with pytest.raises(ClusterParticipationFloorError) as excinfo:
        enforce_cluster_participation_floor(state)
    report = excinfo.value.report
    assert REASON_PARTICIPATION_BARELY_QUORATE_TOO_LONG in report.reasons
    assert REASON_PARTICIPATION_BELOW_HEALTHY_FLOOR in report.reasons
    assert report.barely_quorate_run == 4


def test_audit_scenario_transient_outage_recovered_is_ok():
    # Honest cluster sees a 3-round outage during a rolling upgrade
    # but recovers before round 4. FRP-1 must NOT refuse this
    # legitimate operational pattern.
    history = (
        _sample(1, 5),
        _sample(2, 4), _sample(3, 4), _sample(4, 4),  # rolling upgrade
        _sample(5, 5), _sample(6, 5),                 # recovered
    )
    state = ClusterParticipationHistory(
        history=history,
        current_epoch=6,
    )
    report = enforce_cluster_participation_floor(state)
    assert report.is_allowed
    assert report.barely_quorate_run == 0
