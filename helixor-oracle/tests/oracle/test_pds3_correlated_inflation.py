"""
tests/oracle/test_pds3_correlated_inflation.py — PDS-3 correlated movement
+ mass-failure detector.

Pins:
  - Constants (CORRELATION_WINDOW=5, MAX_DIRECTIONAL_SHARE=0.85,
    MASS_FAILURE_DROP=200, MASS_FAILURE_AGENT_FRACTION=0.50).
  - Healthy mixed movement passes (some agents up, some down).
  - Sustained UP-direction across the window fires correlation.
  - Sustained DOWN-direction across the window fires correlation.
  - Movements below the noise floor (<25 pts) don't count.
  - Evidence hash is deterministic — same input -> same hash.
  - Different inputs -> different hashes.
  - Mass failure: 50%+ agents lose 200+ in one epoch -> flagged.
  - Tiny population skips both checks.
  - enforce_no_correlated_inflation raises with the report attached.
"""

from __future__ import annotations

import pytest

from oracle.cluster.correlated_inflation import (
    CORRELATION_WINDOW,
    DIRECTIONAL_MIN_DELTA,
    MASS_FAILURE_AGENT_FRACTION,
    MASS_FAILURE_DROP,
    MAX_DIRECTIONAL_SHARE,
    MIN_AGENTS_FOR_CORRELATION,
    CorrelatedInflationError,
    enforce_no_correlated_inflation,
    verify_correlated_movement,
    verify_mass_failure,
)
from oracle.cluster.saturation_gate import AgentScore, EpochSnapshot


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


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants_pinned():
    assert CORRELATION_WINDOW == 5
    assert DIRECTIONAL_MIN_DELTA == 25
    assert MAX_DIRECTIONAL_SHARE == 0.85
    assert MASS_FAILURE_DROP == 200
    assert MASS_FAILURE_AGENT_FRACTION == 0.50
    assert MIN_AGENTS_FOR_CORRELATION == 5


# ---------------------------------------------------------------------------
# Healthy mixed movement
# ---------------------------------------------------------------------------

def test_mixed_movement_passes():
    # Some agents up, some down across the window — honest noise.
    snaps = []
    base = [400, 500, 600, 700, 800, 350, 450, 550, 650, 750]
    for e in range(5, 11):
        # Shuffle deltas slightly each epoch.
        shifted = [s + (-30 if i % 2 == 0 else 30) * (e % 2 or -1)
                   for i, s in enumerate(base)]
        snaps.append(_snap(e, shifted))
    report = verify_correlated_movement(snaps)
    assert not report.is_correlated


def test_single_epoch_no_correlation():
    # With only one snapshot, the window is empty — no correlation.
    report = verify_correlated_movement([_snap(1, [400, 500, 600, 700, 800])])
    assert not report.is_correlated
    assert report.window_size == 0


# ---------------------------------------------------------------------------
# Correlated UP / DOWN
# ---------------------------------------------------------------------------

def test_correlated_up_movement_flagged():
    # All 10 agents move up by 50 each epoch for 6 epochs — sustained
    # universal correlation.
    snaps = []
    base = [400, 420, 450, 480, 500, 520, 540, 580, 600, 640]
    for e in range(6):
        snaps.append(_snap(e, [s + 50 * e for s in base]))
    report = verify_correlated_movement(snaps)
    assert report.is_correlated
    assert report.direction == "UP"
    assert report.mean_up_share >= MAX_DIRECTIONAL_SHARE


def test_correlated_down_movement_flagged():
    # All 10 agents fall by 50 each epoch — the deflationary fingerprint.
    snaps = []
    base = [900, 880, 860, 840, 820, 800, 780, 760, 740, 720]
    for e in range(6):
        snaps.append(_snap(e, [s - 50 * e for s in base]))
    report = verify_correlated_movement(snaps)
    assert report.is_correlated
    assert report.direction == "DOWN"


def test_directional_share_below_floor_passes():
    # 70% UP movement — under the 85% floor.
    snaps = []
    base = [400, 450, 500, 550, 600, 650, 700, 750, 800, 850]
    for e in range(6):
        new = list(base)
        for i in range(7):  # 7/10 = 70% move up
            new[i] = base[i] + 50 * e
        # Other 3 oscillate ±50
        for i in range(7, 10):
            new[i] = base[i] + (50 if e % 2 == 0 else -50) * e
        snaps.append(_snap(e, new))
    report = verify_correlated_movement(snaps)
    assert not report.is_correlated


# ---------------------------------------------------------------------------
# Noise floor
# ---------------------------------------------------------------------------

def test_movements_below_noise_floor_dont_count():
    # All 10 agents move by 10 pts each epoch — under the 25 noise
    # floor. The detector treats them as noise and does NOT flag.
    snaps = []
    base = [400, 420, 450, 480, 500, 520, 540, 580, 600, 640]
    for e in range(6):
        snaps.append(_snap(e, [s + 10 * e for s in base]))
    report = verify_correlated_movement(snaps)
    assert not report.is_correlated


# ---------------------------------------------------------------------------
# Evidence hash determinism
# ---------------------------------------------------------------------------

def test_evidence_hash_deterministic():
    snaps_a = []
    snaps_b = []
    base = [400, 420, 450, 480, 500, 520, 540, 580, 600, 640]
    for e in range(6):
        scores = [s + 50 * e for s in base]
        snaps_a.append(_snap(e, scores))
        snaps_b.append(_snap(e, scores))
    report_a = verify_correlated_movement(snaps_a)
    report_b = verify_correlated_movement(snaps_b)
    assert report_a.evidence_hash == report_b.evidence_hash
    assert len(report_a.evidence_hash) == 64  # SHA-256 hex


def test_evidence_hash_changes_when_direction_changes():
    # The hash is a fingerprint of (epoch, up_count, down_count, movers)
    # — count-based, not magnitude-based, so two attacks that produce
    # the SAME count pattern produce the SAME hash. To force a hash
    # difference we change DIRECTION (one snap moves up, the other
    # down).
    base = [400, 420, 450, 480, 500, 520, 540, 580, 600, 640]
    snaps_up = [_snap(e, [s + 50 * e for s in base]) for e in range(6)]
    snaps_down = [_snap(e, [s - 50 * e for s in base]) for e in range(6)]
    report_up = verify_correlated_movement(snaps_up)
    report_down = verify_correlated_movement(snaps_down)
    assert report_up.evidence_hash != report_down.evidence_hash


# ---------------------------------------------------------------------------
# Mass failure
# ---------------------------------------------------------------------------

def test_mass_failure_flagged_when_half_population_crashes():
    prior = _snap(9, [800, 850, 880, 820, 870, 840, 860, 890, 830, 810])
    # 6/10 = 60% fall by 300+ points — exceeds the 50% fraction floor.
    current = _snap(10, [400, 450, 480, 420, 470, 440, 860, 890, 830, 810])
    report = verify_mass_failure(current, prior)
    assert report.is_mass_failure
    assert report.failed_agents == 6
    assert report.failure_fraction == 0.6


def test_mass_failure_below_threshold_not_flagged():
    prior = _snap(9, [800, 850, 880, 820, 870, 840, 860, 890, 830, 810])
    # Only 2/10 = 20% fall by 200+ — under the 50% floor.
    current = _snap(10, [400, 450, 880, 820, 870, 840, 860, 890, 830, 810])
    report = verify_mass_failure(current, prior)
    assert not report.is_mass_failure


def test_mass_failure_drops_under_200_dont_count():
    # 7/10 agents lose 150 each — below the MASS_FAILURE_DROP=200 floor.
    prior = _snap(9, [800, 850, 880, 820, 870, 840, 860, 890, 830, 810])
    current = _snap(10, [650, 700, 730, 670, 720, 690, 710, 890, 830, 810])
    report = verify_mass_failure(current, prior)
    assert report.failed_agents == 0
    assert not report.is_mass_failure


def test_mass_failure_evidence_hash_deterministic():
    prior = _snap(9, [800, 850, 880, 820, 870, 840, 860, 890, 830, 810])
    current = _snap(10, [400, 450, 480, 420, 470, 440, 860, 890, 830, 810])
    report_a = verify_mass_failure(current, prior)
    report_b = verify_mass_failure(current, prior)
    assert report_a.evidence_hash == report_b.evidence_hash


# ---------------------------------------------------------------------------
# Bootstrap / edge cases
# ---------------------------------------------------------------------------

def test_tiny_population_skips_correlation():
    # 3 agents — below MIN_AGENTS_FOR_CORRELATION=5.
    snaps = [
        _snap(e, [800 + 50 * e, 700 + 50 * e, 600 + 50 * e])
        for e in range(6)
    ]
    report = verify_correlated_movement(snaps)
    assert not report.is_correlated


def test_tiny_population_skips_mass_failure():
    prior = _snap(9, [800, 850, 880])
    current = _snap(10, [400, 450, 480])
    report = verify_mass_failure(current, prior)
    assert not report.is_mass_failure


def test_new_agents_in_snapshot_skipped_from_tally():
    # Agent-10 appears fresh in current — has no prior, so it doesn't
    # contribute to the directional tally.
    prior_scores = [400, 420, 450, 480, 500, 520, 540, 580, 600, 640]
    snaps = [_snap(0, prior_scores)]
    # Six follow-on epochs with all 10 originals up 50 each, plus a
    # new agent appearing in the last snapshot.
    base = list(prior_scores)
    for e in range(1, 6):
        scores = [s + 50 * e for s in base]
        snaps.append(_snap(e, scores))
    # In the last snapshot, add an 11th agent.
    last = snaps[-1]
    extended = EpochSnapshot(
        epoch=last.epoch,
        agents=last.agents + (AgentScore(agent_wallet="agent-10", score=500),),
    )
    snaps[-1] = extended
    report = verify_correlated_movement(snaps)
    # The detector still finds 100% of mature agents moving up.
    assert report.is_correlated
    assert report.direction == "UP"


# ---------------------------------------------------------------------------
# enforce wrapper
# ---------------------------------------------------------------------------

def test_enforce_raises_on_correlated_inflation():
    base = [400, 420, 450, 480, 500, 520, 540, 580, 600, 640]
    snaps = [_snap(e, [s + 50 * e for s in base]) for e in range(6)]
    with pytest.raises(CorrelatedInflationError) as excinfo:
        enforce_no_correlated_inflation(snaps)
    assert excinfo.value.report.is_correlated
    assert "PDS-3" in str(excinfo.value)
    assert "UP" in str(excinfo.value)


def test_enforce_returns_report_on_clean_history():
    base = [400, 500, 600, 700, 800, 350, 450, 550, 650, 750]
    snaps = []
    for e in range(6):
        shifted = [s + (-30 if i % 2 == 0 else 30) * (e % 2 or -1)
                   for i, s in enumerate(base)]
        snaps.append(_snap(e, shifted))
    report = enforce_no_correlated_inflation(snaps)
    assert not report.is_correlated


# ---------------------------------------------------------------------------
# Death-spiral simulation — the scenario this gate exists for
# ---------------------------------------------------------------------------

def test_audit_slow_drift_scenario_caught_in_rolling_window():
    # Audit scenario: VULN-03 inflates every agent's score by ~30 points
    # per epoch (above the 25-noise floor, below the 200 per-epoch hard
    # cap). The detector's window is CORRELATION_WINDOW=5 pairs, so a
    # multi-epoch slow drift that fills the rolling window with
    # consistent UP movement fires the flag — regardless of how many
    # epochs the drift has been running by that point.
    base = [200, 220, 240, 260, 280, 300, 320, 340, 360, 380]
    snaps = []
    for e in range(CORRELATION_WINDOW + 1):
        snaps.append(_snap(e, [s + 30 * e for s in base]))
    report = verify_correlated_movement(snaps)
    assert report.is_correlated
    assert report.direction == "UP"
