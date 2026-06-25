"""
detection/base.py — the Detector protocol every Phase-1 dimension implements.

CONTRACT
--------
A Detector is a PURE function from (FeatureVector, BaselineStats) to a
DimensionResult of a fixed `dimension`. "Pure" means:
  - no I/O (no DB, no RPC, no system clock)
  - given the same inputs, same bytes out — every machine, every run
  - no shared mutable state (instance attributes ok if set in __init__)

The Protocol is `@runtime_checkable` so the engine can assert that whatever
it's about to call actually conforms — at startup, not at the end of an epoch.

This module also defines two errors detectors raise instead of silently
returning a meaningless score:

  - DetectorContractError    — features/baseline are unusable; the detector
                                will not run. The engine catches this and
                                substitutes DimensionResult.empty(...) with
                                INSUFFICIENT_DATA + INCOMPATIBLE_INPUT flags.

  - DetectorInternalError    — the detector ran but something went wrong
                                that isn't a contract violation. The engine
                                catches this, sets INSUFFICIENT_DATA, and
                                logs structured failure metadata.

Detector authors SHOULD raise the appropriate error rather than silently
returning a 0 — that lets the composite scorer flag the agent's score as
unreliable rather than mistakenly trusting a default.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from baseline import BaselineStats
from detection.types import DimensionId, DimensionResult
from features import FeatureVector


# =============================================================================
# Errors
# =============================================================================

class DetectorError(Exception):
    """Base class for detector failures."""


class DetectorContractError(DetectorError):
    """
    The detector refuses to run because its inputs violate the contract:
    incompatible baseline schema, missing required features, provisional
    baseline when the detector requires a real one, etc.

    The engine substitutes DimensionResult.empty(...) with
    INSUFFICIENT_DATA | INCOMPATIBLE_INPUT.
    """


class DetectorInternalError(DetectorError):
    """
    The detector ran but encountered an internal failure (numerical error,
    library exception, etc.). The engine substitutes DimensionResult.empty(...)
    with INSUFFICIENT_DATA and logs the error for monitoring.
    """


# =============================================================================
# Detector protocol
# =============================================================================

@runtime_checkable
class Detector(Protocol):
    """
    The interface every Phase-1 detector implements.

    A Detector instance is bound to ONE dimension (`detector.dimension`).
    The engine wires each dimension to exactly one Detector at startup
    via `detection.registry.DetectorRegistry`.
    """

    @property
    def dimension(self) -> DimensionId:
        """Which dimension this detector produces. Frozen at construction."""
        ...

    @property
    def algo_version(self) -> int:
        """The detector's algorithm version. Stamped into every DimensionResult."""
        ...

    def score(
        self,
        features: FeatureVector,
        baseline: BaselineStats,
    ) -> DimensionResult:
        """
        Compute this dimension's contribution.

        Pure. Same inputs → byte-identical DimensionResult.

        Raises:
            DetectorContractError      inputs unusable; engine substitutes empty
            DetectorInternalError      internal failure; engine substitutes empty
        """
        ...


# =============================================================================
# Helpers detector authors can lean on
# =============================================================================

def assert_baseline_compatible(baseline: BaselineStats) -> None:
    """
    Convenience: raise DetectorContractError if the baseline isn't compatible
    with the current feature schema + algo version. Every real detector
    should call this at the top of its score() method.
    """
    try:
        baseline.assert_compatible()
    except Exception as e:  # IncompatibleBaselineError, subclass of BaselineError
        raise DetectorContractError(
            f"baseline incompatible: {e}"
        ) from e


def assert_features_finite(features: FeatureVector) -> None:
    """
    Sanity check the FeatureVector contract holds at the detector boundary.
    `FeatureVector.__post_init__` already guarantees this — this function
    exists so detectors can defensively assert it without depending on the
    internal class invariants.
    """
    # FeatureVector's own __post_init__ rejects non-finite values, so simply
    # constructing one guarantees this — but if a future code path bypasses
    # the constructor (e.g. unpickling), this catches it.
    import math
    for name, value in features.to_dict().items():
        if not math.isfinite(value):
            raise DetectorContractError(
                f"FeatureVector.{name} is not finite ({value}); cannot score"
            )
