"""
tests/detection/test_types.py — DimensionResult contract enforcement.

If any of these break, the engine's invariants break — that's why the
constructor is strict, and that's why these tests exist.
"""

from __future__ import annotations

from types import MappingProxyType

import pytest

from detection.types import (
    DIMENSION_MAX_SCORES,
    DimensionId,
    DimensionResult,
    FlagBit,
)


def _valid(**overrides):
    kw = dict(
        dimension=DimensionId.DRIFT,
        score=100,
        max_score=200,
        flags=0,
        sub_scores={"psi_normalised": 0.3, "ks_rejection_rate": 0.0},
        algo_version=1,
    )
    kw.update(overrides)
    return kw


# =============================================================================
# Frozen identities
# =============================================================================

class TestFrozenIdentities:

    def test_five_dimensions(self):
        assert len(DimensionId.ordered()) == 5
        assert DimensionId.ordered() == (
            DimensionId.DRIFT,
            DimensionId.ANOMALY,
            DimensionId.PERFORMANCE,
            DimensionId.CONSISTENCY,
            DimensionId.SECURITY,
        )

    def test_max_scores_frozen(self):
        assert DIMENSION_MAX_SCORES[DimensionId.DRIFT] == 200
        assert DIMENSION_MAX_SCORES[DimensionId.ANOMALY] == 200
        assert DIMENSION_MAX_SCORES[DimensionId.PERFORMANCE] == 200
        assert DIMENSION_MAX_SCORES[DimensionId.CONSISTENCY] == 200
        assert DIMENSION_MAX_SCORES[DimensionId.SECURITY] == 150

    def test_max_scores_total(self):
        # The composite spec assumes drift+anomaly+performance+consistency = 800,
        # security = 150, total raw capacity = 950 — scaled to 0-1000 via weights.
        assert sum(DIMENSION_MAX_SCORES.values()) == 950

    def test_max_scores_is_immutable(self):
        with pytest.raises((TypeError, AttributeError)):
            DIMENSION_MAX_SCORES[DimensionId.DRIFT] = 999  # type: ignore[index]


# =============================================================================
# Construction validation
# =============================================================================

class TestConstruction:

    def test_valid_result(self):
        r = DimensionResult(**_valid())
        assert r.dimension is DimensionId.DRIFT
        assert r.score == 100
        assert r.max_score == 200

    def test_wrong_dimension_type_rejected(self):
        with pytest.raises(TypeError, match="must be DimensionId"):
            DimensionResult(**_valid(dimension="drift"))

    def test_wrong_max_score_for_dimension_rejected(self):
        with pytest.raises(ValueError, match="max_score for security must be 150"):
            DimensionResult(**_valid(dimension=DimensionId.SECURITY, max_score=200))

    def test_score_above_max_rejected(self):
        with pytest.raises(ValueError, match="out of range"):
            DimensionResult(**_valid(score=201, max_score=200))

    def test_negative_score_rejected(self):
        with pytest.raises(ValueError, match="out of range"):
            DimensionResult(**_valid(score=-1))

    def test_float_score_rejected(self):
        with pytest.raises(TypeError, match="must be int"):
            DimensionResult(**_valid(score=100.0))

    def test_bool_score_rejected(self):
        # bool is a subclass of int; we explicitly forbid it for clarity.
        with pytest.raises(TypeError, match="must be int"):
            DimensionResult(**_valid(score=True))   # type: ignore[arg-type]

    def test_sub_score_outside_unit_rejected(self):
        with pytest.raises(ValueError, match="outside .0, 1."):
            DimensionResult(**_valid(sub_scores={"psi_normalised": 1.5}))

    def test_nan_sub_score_rejected(self):
        with pytest.raises(ValueError, match="not finite"):
            DimensionResult(**_valid(sub_scores={"psi_normalised": float("nan")}))

    def test_inf_sub_score_rejected(self):
        with pytest.raises(ValueError, match="not finite"):
            DimensionResult(**_valid(sub_scores={"psi_normalised": float("inf")}))

    def test_sub_score_non_float_rejected(self):
        with pytest.raises(TypeError, match="must be float"):
            DimensionResult(**_valid(sub_scores={"psi_normalised": 1}))

    def test_flags_out_of_u32_rejected(self):
        with pytest.raises(ValueError, match="u32"):
            DimensionResult(**_valid(flags=2**33))

    def test_negative_flags_rejected(self):
        with pytest.raises(ValueError, match="u32"):
            DimensionResult(**_valid(flags=-1))

    def test_algo_version_zero_rejected(self):
        with pytest.raises(ValueError, match="algo_version"):
            DimensionResult(**_valid(algo_version=0))

    def test_is_frozen(self):
        r = DimensionResult(**_valid())
        with pytest.raises((AttributeError, Exception)):
            r.score = 50  # type: ignore[misc]


# =============================================================================
# Behaviour
# =============================================================================

class TestBehaviour:

    def test_score_normalised(self):
        r = DimensionResult(**_valid(score=100, max_score=200))
        assert r.score_normalised == 0.5

    def test_score_normalised_at_extremes(self):
        assert DimensionResult(**_valid(score=0)).score_normalised == 0.0
        assert DimensionResult(**_valid(score=200, max_score=200)).score_normalised == 1.0

    def test_empty_factory(self):
        e = DimensionResult.empty(DimensionId.SECURITY)
        assert e.dimension is DimensionId.SECURITY
        assert e.score == 0
        assert e.max_score == 150
        assert e.has_flag(FlagBit.INSUFFICIENT_DATA)
        assert e.algo_version == 1

    def test_empty_factory_carries_algo_version(self):
        e = DimensionResult.empty(DimensionId.DRIFT, algo_version=3)
        assert e.algo_version == 3

    def test_has_flag(self):
        r = DimensionResult(**_valid(
            flags=int(FlagBit.PROVISIONAL | FlagBit.IMMEDIATE_RED),
        ))
        assert r.has_flag(FlagBit.PROVISIONAL)
        assert r.has_flag(FlagBit.IMMEDIATE_RED)
        assert not r.has_flag(FlagBit.INSUFFICIENT_DATA)

    def test_sub_scores_sorted_canonically(self):
        # Construction sorts sub_scores by key so two equal-content results
        # serialise identically regardless of insertion order.
        a = DimensionResult(**_valid(sub_scores={"b": 0.2, "a": 0.1}))
        b = DimensionResult(**_valid(sub_scores={"a": 0.1, "b": 0.2}))
        assert list(a.sub_scores.keys()) == ["a", "b"]
        assert list(b.sub_scores.keys()) == ["a", "b"]

    def test_sub_scores_is_immutable(self):
        r = DimensionResult(**_valid())
        assert isinstance(r.sub_scores, MappingProxyType)
        with pytest.raises(TypeError):
            r.sub_scores["new"] = 0.1  # type: ignore[index]
