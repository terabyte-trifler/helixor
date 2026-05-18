"""
tests/scoring/test_gaming.py — Day-13 gaming / confidence / guard-rail primitives.
"""

from __future__ import annotations

import pytest

from scoring._gaming import (
    GAMING_ENTROPY_DROP_THRESHOLD,
    MAX_SCORE_DELTA,
    apply_delta_guard_rail,
    compute_confidence,
    detect_entropy_gaming,
)


# =============================================================================
# detect_entropy_gaming — Shannon-entropy collapse
# =============================================================================

class TestEntropyGaming:

    def test_entropy_collapse_is_gaming(self):
        # Entropy fell from 0.90 to 0.50 — a 44% drop, well past 25%.
        r = detect_entropy_gaming(current_entropy=0.50, baseline_entropy=0.90)
        assert r["gaming_detected"] is True
        assert r["drop_fraction"] > GAMING_ENTROPY_DROP_THRESHOLD

    def test_entropy_held_is_not_gaming(self):
        # A small dip — well within normal variation.
        r = detect_entropy_gaming(current_entropy=0.88, baseline_entropy=0.90)
        assert r["gaming_detected"] is False

    def test_entropy_rose_is_not_gaming(self):
        # Entropy RISING is not gaming — the agent is doing MORE varied things.
        r = detect_entropy_gaming(current_entropy=0.95, baseline_entropy=0.90)
        assert r["gaming_detected"] is False
        assert r["drop_fraction"] == 0.0

    def test_exactly_at_threshold_not_flagged(self):
        # A drop of exactly 25% is not "> 25%".
        r = detect_entropy_gaming(current_entropy=0.75, baseline_entropy=1.0)
        assert r["drop_fraction"] == pytest.approx(0.25)
        assert r["gaming_detected"] is False

    def test_just_past_threshold_flagged(self):
        r = detect_entropy_gaming(current_entropy=0.74, baseline_entropy=1.0)
        assert r["gaming_detected"] is True

    def test_abstains_on_low_baseline_entropy(self):
        # An agent already near-deterministic has no entropy to collapse.
        r = detect_entropy_gaming(current_entropy=0.0, baseline_entropy=0.02)
        assert r["abstained"] is True
        assert r["gaming_detected"] is False

    def test_drop_fraction_clamped(self):
        # Entropy to zero from a healthy baseline → drop_fraction 1.0.
        r = detect_entropy_gaming(current_entropy=0.0, baseline_entropy=0.9)
        assert r["drop_fraction"] == pytest.approx(1.0)

    def test_nan_handled(self):
        r = detect_entropy_gaming(current_entropy=float("nan"), baseline_entropy=0.9)
        assert r["gaming_detected"] is False
        assert r["abstained"] is True


# =============================================================================
# compute_confidence — data sufficiency
# =============================================================================

class TestConfidence:

    def test_full_data_high_confidence(self):
        c = compute_confidence(
            transaction_count=150, days_with_activity=30,
            is_provisional=False, degraded_baseline=False,
        )
        assert c >= 950

    def test_sparse_agent_low_confidence(self):
        c = compute_confidence(
            transaction_count=12, days_with_activity=3,
            is_provisional=False, degraded_baseline=False,
        )
        assert c < 200

    def test_provisional_caps_confidence(self):
        # Even with abundant data, a provisional baseline caps at ~500.
        c = compute_confidence(
            transaction_count=500, days_with_activity=60,
            is_provisional=True, degraded_baseline=False,
        )
        assert c <= 500

    def test_degraded_baseline_reduces_confidence(self):
        full = compute_confidence(
            transaction_count=150, days_with_activity=30,
            is_provisional=False, degraded_baseline=False,
        )
        degraded = compute_confidence(
            transaction_count=150, days_with_activity=30,
            is_provisional=False, degraded_baseline=True,
        )
        assert degraded < full

    def test_both_ratios_matter(self):
        # 150 tx but only 1 active day → not well-sampled → confidence low.
        lopsided = compute_confidence(
            transaction_count=150, days_with_activity=1,
            is_provisional=False, degraded_baseline=False,
        )
        balanced = compute_confidence(
            transaction_count=150, days_with_activity=30,
            is_provisional=False, degraded_baseline=False,
        )
        assert lopsided < balanced

    def test_confidence_bounded(self):
        c = compute_confidence(
            transaction_count=10_000, days_with_activity=10_000,
            is_provisional=False, degraded_baseline=False,
        )
        assert 0 <= c <= 1000

    def test_zero_data(self):
        c = compute_confidence(
            transaction_count=0, days_with_activity=0,
            is_provisional=False, degraded_baseline=False,
        )
        assert c == 0


# =============================================================================
# apply_delta_guard_rail — the 200-point rate limit
# =============================================================================

class TestDeltaGuardRail:

    def test_first_score_no_clamp(self):
        # No previous score — the rail does not apply.
        r = apply_delta_guard_rail(new_score=950, previous_score=None)
        assert r["score"] == 950
        assert r["clamped"] is False

    def test_within_rail_unchanged(self):
        r = apply_delta_guard_rail(new_score=850, previous_score=800)
        assert r["score"] == 850
        assert r["clamped"] is False

    def test_upward_jump_clamped(self):
        # 500 → 950 is a 450-point jump; clamped to +200.
        r = apply_delta_guard_rail(new_score=950, previous_score=500)
        assert r["score"] == 700
        assert r["clamped"] is True
        assert r["raw_delta"] == 450

    def test_downward_jump_clamped(self):
        # 800 → 150 is a 650-point drop; clamped to -200.
        r = apply_delta_guard_rail(new_score=150, previous_score=800)
        assert r["score"] == 600
        assert r["clamped"] is True
        assert r["raw_delta"] == -650

    def test_exactly_200_not_clamped(self):
        # A move of exactly MAX_SCORE_DELTA is allowed.
        r = apply_delta_guard_rail(new_score=700, previous_score=500)
        assert r["score"] == 700
        assert r["clamped"] is False

    def test_just_over_200_clamped(self):
        r = apply_delta_guard_rail(new_score=701, previous_score=500)
        assert r["score"] == 700
        assert r["clamped"] is True

    def test_max_delta_is_200(self):
        assert MAX_SCORE_DELTA == 200
