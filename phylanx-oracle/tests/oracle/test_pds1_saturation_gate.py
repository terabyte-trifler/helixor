"""
tests/oracle/test_pds1_saturation_gate.py — PDS-1 cluster saturation gate.

Pins:
  - Constants (HIGH_BAND_FLOOR=700, MAX_HIGH_BAND_MIGRATION_FRACTION=0.40,
    ABSOLUTE_HIGH_BAND_CEILING=0.80, VARIANCE_COLLAPSE_THRESHOLD=0.50).
  - Normal-distribution snapshots pass the gate.
  - Mass migration into HIGH band one epoch -> REASON_MIGRATION fires.
  - Absolute population density > 80% in HIGH -> REASON_ABSOLUTE fires.
  - Variance collapse against rolling baseline -> REASON_VARIANCE fires.
  - All three reasons can fire simultaneously.
  - enforce_saturation raises ScoreSaturationError with the report.
  - Tiny populations are NOT gated (below MIN_AGENTS_FOR_GATE).
  - Insufficient prior epochs skip variance check (no false fire).
"""

from __future__ import annotations

import math

import pytest

from oracle.cluster.saturation_gate import (
    ABSOLUTE_HIGH_BAND_CEILING,
    HIGH_BAND_FLOOR,
    MAX_HIGH_BAND_MIGRATION_FRACTION,
    MIN_AGENTS_FOR_GATE,
    MIN_PRIOR_EPOCHS_FOR_VARIANCE,
    REASON_ABSOLUTE,
    REASON_MIGRATION,
    REASON_VARIANCE,
    VARIANCE_COLLAPSE_THRESHOLD,
    AgentScore,
    EpochSnapshot,
    ScoreSaturationError,
    enforce_saturation,
    verify_saturation,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snap(epoch: int, scores: list[int]) -> EpochSnapshot:
    return EpochSnapshot(
        epoch=epoch,
        agents=tuple(
            AgentScore(agent_wallet=f"agent-{i}", score=s)
            for i, s in enumerate(scores)
        ),
    )


def _healthy_distribution(epoch: int, n: int = 20) -> EpochSnapshot:
    # Realistic spread: tier mix across RED/YELLOW/GREEN.
    base = [300, 350, 420, 480, 520, 560, 600, 640, 680, 700,
            720, 740, 760, 780, 800, 820, 840, 860, 880, 900]
    return _snap(epoch, base[:n])


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    assert HIGH_BAND_FLOOR == 700
    assert MAX_HIGH_BAND_MIGRATION_FRACTION == 0.40
    assert ABSOLUTE_HIGH_BAND_CEILING == 0.80
    assert VARIANCE_COLLAPSE_THRESHOLD == 0.50
    assert MIN_AGENTS_FOR_GATE == 5
    assert MIN_PRIOR_EPOCHS_FOR_VARIANCE == 3


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_healthy_distribution_passes():
    current = _healthy_distribution(10)
    prior = [_healthy_distribution(e) for e in range(7, 10)]
    report = verify_saturation(current, prior)
    assert not report.is_saturated
    assert report.reasons == ()


def test_stable_high_band_below_ceiling_passes():
    # 60% in HIGH band but stable across epochs - no migration, no
    # variance collapse, under absolute ceiling.
    stable = [400, 500, 600, 700, 720, 740, 800, 820, 850, 900]
    snaps = [_snap(e, stable) for e in range(7, 11)]
    report = verify_saturation(snaps[-1], snaps[:-1])
    assert not report.is_saturated


# ---------------------------------------------------------------------------
# Migration burst
# ---------------------------------------------------------------------------

def test_mass_migration_into_high_band_rejected():
    # Prior: only 1/10 in HIGH band. Current: 8/10 in HIGH band — 7 newly
    # entered = 70% migration in one epoch.
    prior = _snap(9, [400, 420, 450, 480, 500, 520, 540, 580, 600, 720])
    # New high-band entrants are wallets 0..6 (renumber to keep distinct).
    current_scores = [800, 820, 850, 870, 880, 900, 920, 600, 620, 720]
    current_agents = []
    for i, s in enumerate(current_scores):
        current_agents.append(AgentScore(agent_wallet=f"agent-{i}", score=s))
    current = EpochSnapshot(epoch=10, agents=tuple(current_agents))

    report = verify_saturation(current, [prior])
    assert REASON_MIGRATION in report.reasons
    assert report.migration_fraction > MAX_HIGH_BAND_MIGRATION_FRACTION


def test_legitimate_recovery_under_migration_cap_passes():
    # 3 of 10 newly entered (30%) — below the 40% cap.
    prior = _snap(9, [400, 420, 450, 480, 500, 520, 550, 600, 750, 780])
    current = _snap(10, [400, 420, 450, 480, 500, 720, 740, 760, 800, 820])
    report = verify_saturation(current, [prior])
    assert REASON_MIGRATION not in report.reasons


# ---------------------------------------------------------------------------
# Absolute ceiling
# ---------------------------------------------------------------------------

def test_absolute_ceiling_rejected_even_without_migration():
    # 9/10 already in HIGH band — exceeds 80% ceiling regardless of
    # what the prior epoch looked like.
    saturated = [720, 740, 760, 780, 800, 820, 840, 880, 900, 600]
    current = _snap(10, saturated)
    # Same prior so migration check is trivially zero.
    prior = _snap(9, saturated)
    report = verify_saturation(current, [prior])
    assert REASON_ABSOLUTE in report.reasons


def test_exactly_at_ceiling_passes():
    # 8/10 = 80% — at the ceiling, not over. Strict > guard.
    scores = [400, 500, 720, 740, 760, 780, 800, 820, 840, 900]
    current = _snap(10, scores)
    report = verify_saturation(current, [_snap(9, scores)])
    assert REASON_ABSOLUTE not in report.reasons


# ---------------------------------------------------------------------------
# Variance collapse
# ---------------------------------------------------------------------------

def test_variance_collapse_rejected():
    # 4 prior epochs with healthy spread, then one where everyone lands
    # on ~880 — variance collapses to near zero.
    healthy = [400, 500, 600, 700, 800, 900, 350, 450, 550, 650]
    priors = [_snap(e, healthy) for e in range(6, 10)]
    collapsed = _snap(10, [870, 880, 875, 885, 890, 870, 880, 875, 880, 885])
    report = verify_saturation(collapsed, priors)
    assert REASON_VARIANCE in report.reasons


def test_variance_check_skipped_with_too_few_priors():
    # Only 2 priors — variance check is gated by MIN_PRIOR_EPOCHS = 3.
    healthy = [400, 500, 600, 700, 800, 900, 350, 450, 550, 650]
    priors = [_snap(8, healthy), _snap(9, healthy)]
    collapsed = _snap(10, [880] * 10)
    report = verify_saturation(collapsed, priors)
    # Variance collapse must NOT fire (below the prior-epoch floor).
    assert REASON_VARIANCE not in report.reasons


# ---------------------------------------------------------------------------
# Composite failures
# ---------------------------------------------------------------------------

def test_all_three_reasons_can_fire_simultaneously():
    # Death-spiral signature: ~all agents in HIGH band, freshly migrated,
    # variance collapsed.
    healthy = [400, 500, 600, 350, 450, 550, 380, 420, 480, 580]
    priors = [_snap(e, healthy) for e in range(6, 10)]
    spiral = _snap(10, [890, 880, 895, 885, 875, 890, 880, 870, 885, 895])
    report = verify_saturation(spiral, priors)
    assert REASON_MIGRATION in report.reasons
    assert REASON_ABSOLUTE in report.reasons
    assert REASON_VARIANCE in report.reasons


# ---------------------------------------------------------------------------
# enforce wrapper
# ---------------------------------------------------------------------------

def test_enforce_raises_with_report_attached():
    saturated = [720, 740, 760, 780, 800, 820, 840, 880, 900, 920]
    current = _snap(10, saturated)
    prior = _snap(9, [400, 420, 450, 480, 500, 520, 540, 580, 600, 640])
    with pytest.raises(ScoreSaturationError) as excinfo:
        enforce_saturation(current, [prior])
    assert excinfo.value.report.is_saturated
    assert "PDS-1" in str(excinfo.value)


def test_enforce_returns_report_on_clean_snapshot():
    healthy = _healthy_distribution(10)
    priors = [_healthy_distribution(e) for e in range(7, 10)]
    report = enforce_saturation(healthy, priors)
    assert not report.is_saturated


# ---------------------------------------------------------------------------
# Bootstrap / edge cases
# ---------------------------------------------------------------------------

def test_tiny_population_not_gated():
    # 3 agents, all in HIGH band — below MIN_AGENTS_FOR_GATE=5 the gate
    # fails OPEN to avoid false positives on bootstrap.
    current = _snap(10, [800, 850, 900])
    prior = _snap(9, [400, 450, 500])
    report = verify_saturation(current, [prior])
    assert not report.is_saturated


def test_empty_snapshot_returns_clean_report():
    empty = EpochSnapshot(epoch=10, agents=())
    report = verify_saturation(empty, [])
    assert not report.is_saturated
    assert report.population_size == 0


def test_no_prior_snapshot_still_runs_absolute_ceiling():
    # Bootstrap epoch — no prior, but absolute ceiling still applies.
    saturated = [800, 820, 840, 860, 880, 900, 880, 870, 890, 850]
    current = _snap(0, saturated)
    report = verify_saturation(current, [])
    assert REASON_ABSOLUTE in report.reasons
    # Migration fraction is NaN — no prior to compare against.
    assert math.isnan(report.migration_fraction)


def test_migration_fraction_uses_new_entrants_only():
    # If the same wallet was ALREADY in HIGH band last epoch, it is NOT
    # counted as a new entrant — only fresh migrations contribute.
    prior_scores = [400, 450, 500, 550, 600, 720, 740, 760, 780, 800]
    # Wallets 5-9 stayed in HIGH; wallets 0-4 are still below.
    same = [400, 450, 500, 550, 600, 720, 740, 760, 780, 800]
    current = EpochSnapshot(
        epoch=10,
        agents=tuple(
            AgentScore(agent_wallet=f"agent-{i}", score=s)
            for i, s in enumerate(same)
        ),
    )
    prior = EpochSnapshot(
        epoch=9,
        agents=tuple(
            AgentScore(agent_wallet=f"agent-{i}", score=s)
            for i, s in enumerate(prior_scores)
        ),
    )
    report = verify_saturation(current, [prior])
    # Zero newly entered -> migration_fraction is 0.
    assert report.migration_fraction == 0.0
    assert REASON_MIGRATION not in report.reasons


# ---------------------------------------------------------------------------
# Threshold boundary
# ---------------------------------------------------------------------------

def test_score_exactly_at_high_band_floor_counts_as_high():
    # The boundary is INCLUSIVE — 700 itself is HIGH band (matches GREEN
    # tier floor in scoring/composite.py).
    current = _snap(0, [700] * 10)
    report = verify_saturation(current, [])
    assert report.current_high_fraction == 1.0
    assert REASON_ABSOLUTE in report.reasons


def test_score_one_below_floor_does_not_count():
    current = _snap(0, [699] * 10)
    report = verify_saturation(current, [])
    assert report.current_high_fraction == 0.0
