"""
tests/scoring/test_weights.py — the V2 weight vector + scoring fingerprint.

The fingerprint protects against silent re-weighting. If anyone changes
the weights, the max scores, or the algo version without bumping the
appropriate version constant, the fingerprint changes and downstream
consumers can detect the drift.
"""

from __future__ import annotations

from detection.types import DIMENSION_MAX_SCORES, DimensionId
from scoring.weights import (
    SCORING_WEIGHTS_VERSION,
    WEIGHTS,
    scoring_schema_fingerprint,
)


# =============================================================================
# Weight vector invariants
# =============================================================================

class TestWeights:

    def test_weights_cover_all_five_dimensions(self):
        assert set(WEIGHTS.keys()) == set(DimensionId.ordered())

    def test_weights_sum_to_one(self):
        assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9

    def test_weights_in_unit_range(self):
        for w in WEIGHTS.values():
            assert 0.0 <= w <= 1.0

    def test_weights_are_immutable(self):
        import pytest
        with pytest.raises((TypeError, AttributeError)):
            WEIGHTS[DimensionId.DRIFT] = 0.5  # type: ignore[index]

    def test_day4_default_is_flat_20pct(self):
        # Documented Day-4 default. Changing this requires SCORING_WEIGHTS_VERSION bump.
        for dim in DimensionId.ordered():
            assert WEIGHTS[dim] == 0.20


# =============================================================================
# Fingerprint
# =============================================================================

class TestFingerprint:

    def test_fingerprint_is_64_hex(self):
        fp = scoring_schema_fingerprint()
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_fingerprint_is_stable(self):
        assert scoring_schema_fingerprint() == scoring_schema_fingerprint()

    def test_fingerprint_covers_weights_version(self):
        # Reconstruct manually to prove what the fingerprint covers.
        import hashlib
        from scoring.composite import SCORING_ALGO_VERSION
        parts = [f"algo=v{SCORING_ALGO_VERSION}", f"weights=v{SCORING_WEIGHTS_VERSION}"]
        for dim in DimensionId.ordered():
            parts.append(
                f"{dim.value}:max={DIMENSION_MAX_SCORES[dim]}:w={WEIGHTS[dim]:.6f}"
            )
        expected = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
        assert scoring_schema_fingerprint() == expected
