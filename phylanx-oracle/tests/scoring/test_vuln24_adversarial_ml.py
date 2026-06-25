"""
tests/scoring/test_vuln24_adversarial_ml.py — VULN-24 oracle-side guards.

Pins three of the four audit-mandated mitigations:

  - timing-window jitter (detection/window_jitter.py): deterministic,
    per-(agent, epoch), seed-dependent so an attacker cannot precompute
    future-epoch offsets;
  - per-dimension velocity guard (scoring/_gaming.py): clamps any single
    dimension's swing to ±DIM_MAX_SCORE_DELTA so a pump-and-offset
    (drift +200, anomaly -200, composite flat) can't slip past the
    composite-level rail;
  - ensemble-coverage quorum (scoring/composite.py): if too few
    detectors actually fired (others returned INSUFFICIENT_DATA), the
    composite raises FlagBit.ENSEMBLE_INCOMPLETE so downstream
    consumers (SafeCertReader, safe_score endpoint) can refuse.

The fourth mitigation (public-flag obfuscation) lives on the API and is
pinned by `phylanx-api/tests/test_vuln24_flag_obfuscation.py`.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from detection.types import (
    DIMENSION_MAX_SCORES,
    DimensionId,
    DimensionResult,
    FlagBit,
)
from detection.window_jitter import (
    JITTER_ALGO_VERSION,
    MAX_JITTER_SECONDS,
    EvaluationWindow,
    compute_window_jitter,
)
from scoring._gaming import (
    DIM_MAX_SCORE_DELTA,
    apply_dimension_delta_guard_rail,
)
from scoring.composite import (
    MIN_ACTIVE_DETECTORS,
    compute_composite_score,
)


# =============================================================================
# Mitigation #1 — timing-window jitter
# =============================================================================

AGENT_A = b"\x01" * 32
AGENT_B = b"\x02" * 32
SEED_A  = b"\xaa\xbb\xcc\xdd"


class TestWindowJitter:

    def test_deterministic_same_inputs(self):
        a = compute_window_jitter(
            agent_pubkey=AGENT_A, epoch_number=42,
            epoch_advance_seed=SEED_A, scoring_algo_version=2,
        )
        b = compute_window_jitter(
            agent_pubkey=AGENT_A, epoch_number=42,
            epoch_advance_seed=SEED_A, scoring_algo_version=2,
        )
        assert a == b
        assert a.jitter_algo_version == JITTER_ALGO_VERSION

    def test_different_agents_get_different_jitters(self):
        a = compute_window_jitter(
            agent_pubkey=AGENT_A, epoch_number=42,
            epoch_advance_seed=SEED_A, scoring_algo_version=2,
        )
        b = compute_window_jitter(
            agent_pubkey=AGENT_B, epoch_number=42,
            epoch_advance_seed=SEED_A, scoring_algo_version=2,
        )
        # Possible (low probability) for offsets to coincide; check the
        # WHOLE tuple — at least one of the two offsets must differ.
        assert (a.start_offset_seconds, a.end_offset_seconds) != \
               (b.start_offset_seconds, b.end_offset_seconds)

    def test_different_epochs_get_different_jitters(self):
        a = compute_window_jitter(
            agent_pubkey=AGENT_A, epoch_number=42,
            epoch_advance_seed=SEED_A, scoring_algo_version=2,
        )
        b = compute_window_jitter(
            agent_pubkey=AGENT_A, epoch_number=43,
            epoch_advance_seed=SEED_A, scoring_algo_version=2,
        )
        assert (a.start_offset_seconds, a.end_offset_seconds) != \
               (b.start_offset_seconds, b.end_offset_seconds)

    def test_different_seed_breaks_attacker_precomputation(self):
        """The whole point — the attacker who knows agent+epoch+algo
        but cannot guess the on-chain seed gets a different jitter."""
        a = compute_window_jitter(
            agent_pubkey=AGENT_A, epoch_number=42,
            epoch_advance_seed=b"\xaa\xbb\xcc\xdd",
            scoring_algo_version=2,
        )
        b = compute_window_jitter(
            agent_pubkey=AGENT_A, epoch_number=42,
            epoch_advance_seed=b"\xff\xee\xdd\xcc",
            scoring_algo_version=2,
        )
        assert (a.start_offset_seconds, a.end_offset_seconds) != \
               (b.start_offset_seconds, b.end_offset_seconds)

    def test_algo_version_change_rotates_jitter(self):
        a = compute_window_jitter(
            agent_pubkey=AGENT_A, epoch_number=42,
            epoch_advance_seed=SEED_A, scoring_algo_version=2,
        )
        b = compute_window_jitter(
            agent_pubkey=AGENT_A, epoch_number=42,
            epoch_advance_seed=SEED_A, scoring_algo_version=3,
        )
        assert (a.start_offset_seconds, a.end_offset_seconds) != \
               (b.start_offset_seconds, b.end_offset_seconds)

    def test_offsets_in_bounds(self):
        # Hammer the helper across 1000 (agent, epoch) pairs and assert
        # every offset stays inside [0, MAX_JITTER_SECONDS].
        for epoch in range(100):
            for agent_byte in range(10):
                w = compute_window_jitter(
                    agent_pubkey=bytes([agent_byte]) * 32,
                    epoch_number=epoch,
                    epoch_advance_seed=SEED_A,
                    scoring_algo_version=2,
                )
                assert 0 <= w.start_offset_seconds <= MAX_JITTER_SECONDS
                assert 0 <= w.end_offset_seconds   <= MAX_JITTER_SECONDS

    def test_rejects_bad_inputs(self):
        with pytest.raises(TypeError, match="agent_pubkey"):
            compute_window_jitter(
                agent_pubkey="not-bytes",     # type: ignore[arg-type]
                epoch_number=1, epoch_advance_seed=SEED_A,
                scoring_algo_version=1,
            )
        with pytest.raises(TypeError, match="epoch_advance_seed"):
            compute_window_jitter(
                agent_pubkey=AGENT_A, epoch_number=1,
                epoch_advance_seed="not-bytes",   # type: ignore[arg-type]
                scoring_algo_version=1,
            )
        with pytest.raises(ValueError, match="epoch_number"):
            compute_window_jitter(
                agent_pubkey=AGENT_A, epoch_number=-1,
                epoch_advance_seed=SEED_A, scoring_algo_version=1,
            )
        with pytest.raises(ValueError, match="scoring_algo_version"):
            compute_window_jitter(
                agent_pubkey=AGENT_A, epoch_number=1,
                epoch_advance_seed=SEED_A, scoring_algo_version=0,
            )


# =============================================================================
# Mitigation #2 — ensemble-coverage quorum
# =============================================================================

def _real_dim(dim: DimensionId, score: int, flags: int = 0) -> DimensionResult:
    return DimensionResult(
        dimension=dim, score=score,
        max_score=DIMENSION_MAX_SCORES[dim],
        flags=flags, sub_scores={}, algo_version=1,
    )


def _silent_dim(dim: DimensionId) -> DimensionResult:
    """A detector that returned INSUFFICIENT_DATA — does not count toward
    the ensemble quorum."""
    return DimensionResult(
        dimension=dim, score=0,
        max_score=DIMENSION_MAX_SCORES[dim],
        flags=int(FlagBit.INSUFFICIENT_DATA),
        sub_scores={}, algo_version=1,
    )


class TestEnsembleCoverage:

    def test_min_active_is_three(self):
        # Audit mandate: the floor is 3 of 5.
        assert MIN_ACTIVE_DETECTORS == 3

    def test_all_active_no_flag(self, baseline):
        dims = {d: _real_dim(d, score=100) for d in DimensionId.ordered()}
        r = compute_composite_score(dims, baseline)
        assert not (r.aggregated_flags & int(FlagBit.ENSEMBLE_INCOMPLETE))

    def test_three_active_two_silent_no_flag(self, baseline):
        # 3 active + 2 silent = quorum met.
        ordered = DimensionId.ordered()
        dims = {
            ordered[0]: _real_dim(ordered[0], score=100),
            ordered[1]: _real_dim(ordered[1], score=100),
            ordered[2]: _real_dim(ordered[2], score=100),
            ordered[3]: _silent_dim(ordered[3]),
            ordered[4]: _silent_dim(ordered[4]),
        }
        r = compute_composite_score(dims, baseline)
        assert not (r.aggregated_flags & int(FlagBit.ENSEMBLE_INCOMPLETE))

    def test_two_active_three_silent_trips_flag(self, baseline):
        # Only 2 detectors fired — adversary likely silenced 3.
        ordered = DimensionId.ordered()
        dims = {
            ordered[0]: _real_dim(ordered[0], score=100),
            ordered[1]: _real_dim(ordered[1], score=100),
            ordered[2]: _silent_dim(ordered[2]),
            ordered[3]: _silent_dim(ordered[3]),
            ordered[4]: _silent_dim(ordered[4]),
        }
        r = compute_composite_score(dims, baseline)
        assert (r.aggregated_flags & int(FlagBit.ENSEMBLE_INCOMPLETE)), (
            "ENSEMBLE_INCOMPLETE flag should fire when fewer than "
            f"{MIN_ACTIVE_DETECTORS} detectors are active"
        )

    def test_all_silent_trips_flag(self, baseline):
        dims = {d: _silent_dim(d) for d in DimensionId.ordered()}
        r = compute_composite_score(dims, baseline)
        assert (r.aggregated_flags & int(FlagBit.ENSEMBLE_INCOMPLETE))


# =============================================================================
# Mitigation #3 — per-dimension velocity guard
# =============================================================================

class TestDimensionDeltaGuardRail:

    def test_default_cap_is_250(self):
        # Audit calibration: 250 per-dim is wider than the 200 composite
        # cap because single dimensions naturally swing more.
        assert DIM_MAX_SCORE_DELTA == 250

    def test_no_previous_no_clamp(self):
        new = {DimensionId.DRIFT: 199, DimensionId.ANOMALY: 199}
        r = apply_dimension_delta_guard_rail(
            new_dimensions=new, previous_dimensions=None,
        )
        assert r["clamped_dimensions"] == new
        assert r["clamped_keys"] == frozenset()

    def test_small_swing_passes(self):
        new  = {DimensionId.DRIFT: 150}
        prev = {DimensionId.DRIFT: 100}
        r = apply_dimension_delta_guard_rail(
            new_dimensions=new, previous_dimensions=prev,
        )
        assert r["clamped_dimensions"] == new
        assert r["clamped_keys"] == frozenset()

    def test_exactly_at_cap_passes(self):
        new  = {DimensionId.DRIFT: 250 + 100}
        prev = {DimensionId.DRIFT: 100}
        r = apply_dimension_delta_guard_rail(
            new_dimensions=new, previous_dimensions=prev,
        )
        # exactly +250 — at the cap, not over.
        assert r["clamped_keys"] == frozenset()

    def test_pump_clamped_and_flagged(self):
        new  = {DimensionId.DRIFT: 400}
        prev = {DimensionId.DRIFT: 100}
        r = apply_dimension_delta_guard_rail(
            new_dimensions=new, previous_dimensions=prev,
        )
        assert r["clamped_dimensions"][DimensionId.DRIFT] == 100 + 250
        assert DimensionId.DRIFT in r["clamped_keys"]

    def test_dump_clamped_and_flagged(self):
        new  = {DimensionId.ANOMALY: 50}
        prev = {DimensionId.ANOMALY: 400}
        r = apply_dimension_delta_guard_rail(
            new_dimensions=new, previous_dimensions=prev,
        )
        assert r["clamped_dimensions"][DimensionId.ANOMALY] == 400 - 250
        assert DimensionId.ANOMALY in r["clamped_keys"]

    def test_pump_and_offset_attack_caught(self):
        """The attack composite-level rail misses: drift pumps +300,
        anomaly offsets -300, aggregate flat. Per-dim catches both."""
        new  = {DimensionId.DRIFT: 500, DimensionId.ANOMALY: 0}
        prev = {DimensionId.DRIFT: 100, DimensionId.ANOMALY: 200}
        r = apply_dimension_delta_guard_rail(
            new_dimensions=new, previous_dimensions=prev,
        )
        assert DimensionId.DRIFT   in r["clamped_keys"]
        # anomaly is exactly -200 (within ±250); not clamped
        assert DimensionId.ANOMALY not in r["clamped_keys"]

    def test_unrelated_dims_unaffected(self):
        new  = {DimensionId.DRIFT: 999, DimensionId.ANOMALY: 50}
        prev = {DimensionId.DRIFT: 100, DimensionId.ANOMALY: 50}
        r = apply_dimension_delta_guard_rail(
            new_dimensions=new, previous_dimensions=prev,
        )
        assert r["clamped_dimensions"][DimensionId.ANOMALY] == 50
        assert DimensionId.ANOMALY not in r["clamped_keys"]

    def test_missing_prev_for_one_dim_skips_that_dim(self):
        new  = {DimensionId.DRIFT: 999, DimensionId.ANOMALY: 50}
        # ANOMALY missing from prev → fresh dim, no clamp comparison
        prev = {DimensionId.DRIFT: 100}
        r = apply_dimension_delta_guard_rail(
            new_dimensions=new, previous_dimensions=prev,
        )
        assert DimensionId.DRIFT   in r["clamped_keys"]
        assert DimensionId.ANOMALY not in r["clamped_keys"]
        assert r["clamped_dimensions"][DimensionId.ANOMALY] == 50

    def test_rejects_negative_cap(self):
        with pytest.raises(ValueError, match="max_delta"):
            apply_dimension_delta_guard_rail(
                new_dimensions={}, previous_dimensions={}, max_delta=-1,
            )
