"""
detection/drift.py — Dimension 1: statistical drift from baseline.

STATUS: Day 4 STUB. The real implementation lands in Days 5-6.

REAL IMPLEMENTATION (Days 5-6) will produce:
  - PSI    on tx-type distribution            (Day 5)
  - KS-test on success-rate windows           (Day 5)
  - CUSUM   change-point on success rate      (Day 6)
  - ADWIN   adaptive windowing                (Day 6)
  - DDM     Drift Detection Method            (Day 6)

Output: drift score 0..MAX_SCORE (200) + per-algorithm flag bits.

DIMENSION-SPECIFIC FLAG BITS (8..12) — frozen here, set by the real detector:
    8  = PSI       triggered (PSI > 0.25 = "definitively shifted")
    9  = KS        triggered (rejection at Bonferroni-corrected alpha)
   10  = CUSUM     change-point detected
   11  = ADWIN     adaptive window split
   12  = DDM       drift level reached

DIMENSION-SPECIFIC SUB-SCORES (all in [0, 1]) the real detector emits:
    psi_normalised        clipped PSI / 1.0 saturation point
    ks_rejection_rate     fraction of KS tests rejecting H0
    cusum_normalised      sigmoid of |CUSUM stat| / threshold
    adwin_drift_score     adwin width-loss ratio
    ddm_warning_ratio     ddm warning-level position
"""

from __future__ import annotations

from baseline import BaselineStats
from detection.base import Detector
from detection.types import DimensionId, DimensionResult
from features import FeatureVector


# Dimension-specific flag bit positions (universal bits 0-7 live in detection.types.FlagBit)
FLAG_PSI    = 1 << 8
FLAG_KS     = 1 << 9
FLAG_CUSUM  = 1 << 10
FLAG_ADWIN  = 1 << 11
FLAG_DDM    = 1 << 12

# Sub-score keys this detector will eventually emit. Stub returns an empty mapping.
SUB_SCORE_KEYS: tuple[str, ...] = (
    "psi_normalised",
    "ks_rejection_rate",
    "cusum_normalised",
    "adwin_drift_score",
    "ddm_warning_ratio",
)


class DriftDetector:
    """Day-4 stub. Returns an empty result so the pipeline is wireable end-to-end."""

    dimension:    DimensionId = DimensionId.DRIFT
    algo_version: int         = 1   # bumps to 2 in Days 5-6 when the real algos land

    @property
    def dimension(self) -> DimensionId:  # type: ignore[override]
        return DimensionId.DRIFT

    @property
    def algo_version(self) -> int:       # type: ignore[override]
        return 1

    def score(self, features: FeatureVector, baseline: BaselineStats) -> DimensionResult:
        return DimensionResult.empty(DimensionId.DRIFT, algo_version=self.algo_version)


# Static check: the stub conforms to the Detector protocol.
_: Detector = DriftDetector()
