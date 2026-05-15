"""
detection/engine.py — run all five detectors + the composite.

    run_detection_engine(features, baseline, registry) -> ScoreResult

This is the END-TO-END Phase-1 pipeline. The Day-3 oracle's epoch runner
will call exactly this after computing the baseline. Today (Day 4) the
detectors are stubs returning empty results — the pipeline still produces a
valid 0-1000 ScoreResult.

ERROR HANDLING
--------------
Each detector is called inside an isolation barrier:
  - DetectorContractError    -> empty result with INSUFFICIENT_DATA + INCOMPATIBLE_INPUT
  - DetectorInternalError    -> empty result with INSUFFICIENT_DATA (logged)
  - any other exception      -> empty result with INSUFFICIENT_DATA (logged)

One broken detector NEVER prevents the other four from running. The composite
scorer aggregates whatever it gets; the resulting ScoreResult's flags tell
the consumer which dimensions actually scored.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from baseline import BaselineStats
from detection.base import (
    DetectorContractError,
    DetectorInternalError,
)
from detection.registry import DetectorRegistry
from detection.types import DimensionId, DimensionResult, FlagBit
from features import FeatureVector
from scoring.composite import ScoreResult, compute_composite_score


log = logging.getLogger(__name__)


def run_detection_engine(
    features:    FeatureVector,
    baseline:    BaselineStats,
    registry:    DetectorRegistry,
    *,
    computed_at: datetime | None = None,
) -> ScoreResult:
    """
    Run all five detectors against (features, baseline) and produce the
    composite ScoreResult.

    Pure given the registry (no I/O). Errors in any single detector are
    contained — the function ALWAYS returns a valid ScoreResult.
    """
    results: dict[DimensionId, DimensionResult] = {}
    for dim in DimensionId.ordered():
        detector = registry.get(dim)
        results[dim] = _safe_score(detector, features, baseline)

    return compute_composite_score(
        results,
        baseline,
        computed_at=computed_at or datetime.now(timezone.utc),
    )


def _safe_score(detector, features: FeatureVector, baseline: BaselineStats) -> DimensionResult:
    """Call detector.score() in an isolation barrier; substitute empty on failure."""
    try:
        result = detector.score(features, baseline)
    except DetectorContractError as e:
        log.warning(
            "detector_contract_error dim=%s err=%s",
            detector.dimension.value, e,
        )
        return _empty_with_flags(
            detector.dimension,
            FlagBit.INSUFFICIENT_DATA | FlagBit.INCOMPATIBLE_INPUT,
            detector.algo_version,
        )
    except DetectorInternalError as e:
        log.error(
            "detector_internal_error dim=%s err=%s",
            detector.dimension.value, e,
        )
        return _empty_with_flags(
            detector.dimension,
            FlagBit.INSUFFICIENT_DATA,
            detector.algo_version,
        )
    except Exception as e:  # noqa: BLE001 — engine MUST NOT crash on a detector bug
        log.exception(
            "detector_unexpected_error dim=%s",
            detector.dimension.value,
        )
        return _empty_with_flags(
            detector.dimension,
            FlagBit.INSUFFICIENT_DATA,
            detector.algo_version,
        )

    # Defensive: validate the detector actually returned a DimensionResult.
    # An author returning a tuple / dict / None gets caught here, not later.
    if not isinstance(result, DimensionResult):
        log.error(
            "detector_returned_non_DimensionResult dim=%s type=%s",
            detector.dimension.value, type(result).__name__,
        )
        return _empty_with_flags(
            detector.dimension,
            FlagBit.INSUFFICIENT_DATA,
            detector.algo_version,
        )
    if result.dimension is not detector.dimension:
        log.error(
            "detector_dimension_mismatch slot=%s returned=%s",
            detector.dimension.value, result.dimension.value,
        )
        return _empty_with_flags(
            detector.dimension,
            FlagBit.INSUFFICIENT_DATA,
            detector.algo_version,
        )
    return result


def _empty_with_flags(
    dimension:    DimensionId,
    flags:        FlagBit | int,
    algo_version: int,
) -> DimensionResult:
    from detection.types import DIMENSION_MAX_SCORES
    return DimensionResult(
        dimension=dimension,
        score=0,
        max_score=DIMENSION_MAX_SCORES[dimension],
        flags=int(flags),
        sub_scores={},
        algo_version=algo_version,
    )
