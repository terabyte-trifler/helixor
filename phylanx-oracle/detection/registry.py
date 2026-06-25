"""
detection/registry.py — the explicit detector→dimension wiring.

This is the single place that says "Drift dimension is computed by
DriftDetector." When Day 5 replaces the DriftDetector stub with the real
algorithm, only this file (and the import) changes.

The registry validates at construction:
  - exactly five detectors, one per DimensionId
  - each detector's `.dimension` matches the slot it's registered in
  - each detector conforms to the Detector Protocol (runtime check)
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from detection.anomaly import AnomalyDetector
from detection.base import Detector
from detection.consistency import ConsistencyDetector
from detection.drift import DriftDetector
from detection.performance import PerformanceDetector
from detection.security import SecurityDetector
from detection.types import DimensionId


class DetectorRegistry:
    """
    A fully-validated map from DimensionId -> Detector.

    Instantiate ONCE at engine startup. Errors raised here surface as a hard
    fail at boot, which is what we want — a misconfigured detection engine
    must never silently run with the wrong detectors.
    """

    def __init__(self, detectors: Mapping[DimensionId, Detector]) -> None:
        # 1. Exactly five entries.
        expected = set(DimensionId.ordered())
        got = set(detectors.keys())
        if got != expected:
            missing = expected - got
            extra   = got - expected
            raise ValueError(
                f"DetectorRegistry must have exactly the five DimensionIds. "
                f"missing={missing}, extra={extra}"
            )

        # 2. Each detector conforms + reports the slot it was registered into.
        for dim, det in detectors.items():
            if not isinstance(det, Detector):
                raise TypeError(
                    f"detector for {dim.value} does not conform to Detector Protocol "
                    f"(missing dimension/algo_version/score?)"
                )
            if det.dimension is not dim:
                raise ValueError(
                    f"detector for slot {dim.value} reports dimension "
                    f"{det.dimension.value} — mismatched wiring"
                )
            if not isinstance(det.algo_version, int) or det.algo_version < 1:
                raise ValueError(
                    f"detector for {dim.value} has invalid algo_version "
                    f"{det.algo_version!r}"
                )

        # 3. Freeze. The registry is immutable after construction.
        self._detectors: Mapping[DimensionId, Detector] = MappingProxyType(dict(detectors))

    def get(self, dimension: DimensionId) -> Detector:
        return self._detectors[dimension]

    def all(self) -> Mapping[DimensionId, Detector]:
        return self._detectors

    def algo_versions(self) -> Mapping[DimensionId, int]:
        """The detector algo version per dimension — stamped into ScoreResult."""
        return MappingProxyType({
            dim: det.algo_version for dim, det in self._detectors.items()
        })


def default_registry() -> DetectorRegistry:
    """
    The default registry: Day-4 stubs for all five dimensions.

    As days land, this function is updated to instantiate the real detector.
    Example after Day 6: `DimensionId.DRIFT: RealDriftDetector(...)`.
    """
    return DetectorRegistry({
        DimensionId.DRIFT:       DriftDetector(),
        DimensionId.ANOMALY:     AnomalyDetector(),
        DimensionId.PERFORMANCE: PerformanceDetector(),
        DimensionId.CONSISTENCY: ConsistencyDetector(),
        DimensionId.SECURITY:    SecurityDetector(),
    })
