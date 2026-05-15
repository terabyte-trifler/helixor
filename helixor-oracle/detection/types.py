"""
detection/types.py — the typed contract every Phase-1 detector implements.

A `DimensionResult` is the ONLY thing a detector returns. The composite
scorer combines exactly five of them (one per `DimensionId`) into the
0-1000 score. Every invariant the engine depends on is enforced at
construction-time — there is no path through the system that produces an
invalid `DimensionResult`.

DESIGN CONTRACT
---------------
1. Five dimensions. Fixed set. Their IDs and `MAX_SCORE` are frozen here.
2. Score in [0, MAX_SCORE] — clamped at construction, never silently truncated.
3. Every numeric field is a finite float. No NaN, no inf. Same rule as Day 1+2.
4. `sub_scores` is an immutable mapping with deterministic key order.
5. `flags` is a u32 bitmask. Per-dimension flag semantics live in each
   dimension module, but the BIT POSITIONS are frozen here so the composite
   can serialise them uniformly.
6. The frozen dataclass + slots = cheap, hashable, immutable.
"""

from __future__ import annotations

import enum
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType


# =============================================================================
# Frozen dimension IDs + their max scores
# =============================================================================

class DimensionId(enum.Enum):
    """
    The five Phase-1 scoring dimensions.

    Order here IS the canonical order — used by the composite scorer for
    deterministic serialisation. DO NOT REORDER.
    """
    DRIFT       = "drift"        # statistical drift from baseline (PSI, KS, CUSUM, ADWIN, DDM)
    ANOMALY     = "anomaly"      # 5-method anomaly ensemble + Isolation Forest
    PERFORMANCE = "performance"  # dual fading factors, Pyth profit-quality
    CONSISTENCY = "consistency"  # tool stability, rhythm regularity, domain
    SECURITY    = "security"     # attack patterns, integrity, Sybil

    @classmethod
    def ordered(cls) -> tuple["DimensionId", ...]:
        return (cls.DRIFT, cls.ANOMALY, cls.PERFORMANCE, cls.CONSISTENCY, cls.SECURITY)


# Per-dimension maximum score. From the Day-1-14 V2 plan:
#   drift 200 + anomaly 200 + performance 200 + consistency 200 + security 150
#   = 950 total dimension capacity (composite scaled to 0-1000)
DIMENSION_MAX_SCORES: Mapping[DimensionId, int] = MappingProxyType({
    DimensionId.DRIFT:       200,
    DimensionId.ANOMALY:     200,
    DimensionId.PERFORMANCE: 200,
    DimensionId.CONSISTENCY: 200,
    DimensionId.SECURITY:    150,
})


# =============================================================================
# Universal flag bits — frozen positions, used uniformly across dimensions
# =============================================================================

class FlagBit(enum.IntFlag):
    """
    32-bit flag layout. Bits 0-7 are universal; bits 8-31 are
    per-dimension and defined inside each detector module.

    Universal bits are the ones the COMPOSITE scorer can act on without
    knowing which dimension produced them.
    """
    # ── Universal (bits 0-7) ───────────────────────────────────────────────
    PROVISIONAL          = 1 << 0     # detector ran with thin data — low confidence
    INSUFFICIENT_DATA    = 1 << 1     # detector did not run; score is a default
    INCOMPATIBLE_INPUT   = 1 << 2     # baseline or features rejected — score is a default
    IMMEDIATE_RED        = 1 << 3     # fast-path: composite should immediately flag the agent
    DEGRADED_BASELINE    = 1 << 4     # baseline.is_provisional == True
    # bits 5-7 reserved for future universal flags

    # ── Per-dimension bits (8-31) ─────────────────────────────────────────
    # Drift (bits 8-12):    8=PSI, 9=KS, 10=CUSUM, 11=ADWIN, 12=DDM
    # Anomaly (16-21):     16=METHOD_1, 17=METHOD_2, 18=METHOD_3, 19=METHOD_4, 20=METHOD_5, 21=ISOFOREST
    # Performance, Consistency, Security — defined in their detectors.


# =============================================================================
# DimensionResult — the typed return value
# =============================================================================

@dataclass(frozen=True, slots=True)
class DimensionResult:
    """
    A single dimension's contribution to the composite score.

    Constructor enforces every invariant the engine depends on:
      - `dimension` is a known DimensionId
      - `score` is in [0, max_score] (silently clamped to the bounds)
      - `max_score` matches DIMENSION_MAX_SCORES[dimension]
      - every sub-score value is a finite float in [0, 1]
      - `flags` fits in u32
      - `algo_version >= 1`
    """
    dimension:     DimensionId
    score:         int             # in [0, max_score]
    max_score:     int             # must equal DIMENSION_MAX_SCORES[dimension]
    flags:         int             # u32 bitmask (FlagBit | per-dimension bits)
    sub_scores:    Mapping[str, float]   # named diagnostic outputs, each in [0, 1]
    algo_version:  int             # detector algorithm version (>= 1)

    def __post_init__(self) -> None:
        # 1. Known dimension + matching max.
        if not isinstance(self.dimension, DimensionId):
            raise TypeError(f"dimension must be DimensionId, got {type(self.dimension).__name__}")
        expected_max = DIMENSION_MAX_SCORES[self.dimension]
        if self.max_score != expected_max:
            raise ValueError(
                f"max_score for {self.dimension.value} must be {expected_max}, "
                f"got {self.max_score}"
            )

        # 2. Score type + range.
        if not isinstance(self.score, int) or isinstance(self.score, bool):
            raise TypeError(
                f"score must be int, got {type(self.score).__name__}. "
                f"Detector authors: cast with round(...) to int explicitly."
            )
        if not (0 <= self.score <= self.max_score):
            raise ValueError(
                f"score {self.score} out of range [0, {self.max_score}] for {self.dimension.value}"
            )

        # 3. Flags fit in u32.
        if not isinstance(self.flags, int) or isinstance(self.flags, bool):
            raise TypeError(f"flags must be int, got {type(self.flags).__name__}")
        if not (0 <= self.flags <= 0xFFFFFFFF):
            raise ValueError(f"flags must be u32 (0..2^32-1), got {self.flags}")

        # 4. algo_version sanity.
        if not isinstance(self.algo_version, int) or self.algo_version < 1:
            raise ValueError(f"algo_version must be int >= 1, got {self.algo_version!r}")

        # 5. sub_scores: every value finite, in [0,1], no NaN.
        if not isinstance(self.sub_scores, Mapping):
            raise TypeError(f"sub_scores must be a Mapping, got {type(self.sub_scores).__name__}")
        for name, value in self.sub_scores.items():
            if not isinstance(name, str) or not name:
                raise ValueError(f"sub_score key must be a non-empty str, got {name!r}")
            if not isinstance(value, float):
                raise TypeError(
                    f"sub_score '{name}' must be float, got {type(value).__name__}"
                )
            if not math.isfinite(value):
                raise ValueError(f"sub_score '{name}' is not finite: {value!r}")
            if not (0.0 <= value <= 1.0):
                raise ValueError(
                    f"sub_score '{name}' = {value} is outside [0, 1]; "
                    f"detector authors: normalise before constructing the result"
                )

        # 6. Freeze the sub_scores mapping so the result is fully immutable.
        if not isinstance(self.sub_scores, MappingProxyType):
            # Sort keys for canonical order — required by the composite for
            # deterministic serialisation and identical bytes across runs.
            sorted_dict = dict(sorted(self.sub_scores.items()))
            object.__setattr__(self, "sub_scores", MappingProxyType(sorted_dict))

    # ─── Convenience constructors ────────────────────────────────────────────

    @classmethod
    def empty(cls, dimension: DimensionId, *, algo_version: int = 1) -> "DimensionResult":
        """
        A valid 0-score result — used by stub detectors today, and by real
        detectors when they refuse to run (insufficient data, incompatible
        baseline, etc.). The `INSUFFICIENT_DATA` flag is set so the composite
        knows the score isn't real.
        """
        return cls(
            dimension=dimension,
            score=0,
            max_score=DIMENSION_MAX_SCORES[dimension],
            flags=int(FlagBit.INSUFFICIENT_DATA),
            sub_scores={},
            algo_version=algo_version,
        )

    @property
    def score_normalised(self) -> float:
        """Score in [0, 1] for the composite to re-weight. Always finite."""
        if self.max_score == 0:
            return 0.0
        return self.score / self.max_score

    def has_flag(self, bit: FlagBit | int) -> bool:
        b = int(bit)
        return (self.flags & b) == b
