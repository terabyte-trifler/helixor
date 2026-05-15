"""
helixor-oracle / detection — Phase-1 detection engine.

Public API (Day 4 scaffolding):
    DimensionId, DIMENSION_MAX_SCORES, FlagBit
    DimensionResult            frozen, validated per-dimension output
    Detector                   runtime-checkable Protocol
    DetectorContractError      raise when inputs are unusable
    DetectorInternalError      raise on internal failure
    DetectorRegistry           validated DimensionId -> Detector
    default_registry()         Day-4 stubs; updated as detectors land
"""

from __future__ import annotations

from detection.base import (
    Detector,
    DetectorContractError,
    DetectorError,
    DetectorInternalError,
    assert_baseline_compatible,
    assert_features_finite,
)
from detection.types import (
    DIMENSION_MAX_SCORES,
    DimensionId,
    DimensionResult,
    FlagBit,
)

__all__ = [
    "DimensionId",
    "DIMENSION_MAX_SCORES",
    "DimensionResult",
    "FlagBit",
    "Detector",
    "DetectorError",
    "DetectorContractError",
    "DetectorInternalError",
    "DetectorRegistry",
    "default_registry",
    "run_detection_engine",
    "assert_baseline_compatible",
    "assert_features_finite",
]


def __getattr__(name: str):
    """
    Keep the public `from detection import run_detection_engine` API without
    eagerly importing detection.engine during package initialisation.

    That matters because scoring.composite imports detection.types. If
    detection.__init__ imports detection.engine at that moment, the engine
    imports scoring.composite back while it is still initialising.
    """
    if name == "run_detection_engine":
        from detection.engine import run_detection_engine
        return run_detection_engine
    if name in {"DetectorRegistry", "default_registry"}:
        from detection.registry import DetectorRegistry, default_registry
        return {
            "DetectorRegistry": DetectorRegistry,
            "default_registry": default_registry,
        }[name]
    raise AttributeError(f"module 'detection' has no attribute {name!r}")
