"""
detection/performance.py — Dimension 3: performance scoring.

STATUS: Day 4 STUB. The real implementation lands in Day 11.

REAL IMPLEMENTATION (Day 11) will produce:
  - Dual fading factors (α fast = 0.10, α slow = 0.01) of performance signals
  - Profit Quality Score — agent outcomes cross-referenced against Pyth feeds
  - Z-scored returns against the agent's own history

Output: performance score 0..MAX_SCORE (200).

DIMENSION-SPECIFIC FLAG BITS (8..11 reused in this dimension's namespace,
no overlap because the composite reads flags PER DIMENSION):
   24 = FADING_DIVERGENCE   fast/slow EMA diverged > threshold
   25 = PROFIT_QUALITY_LOW  Pyth cross-reference flagged low-quality profit
   26 = ZSCORE_OUTLIER      |z| > 3 against own history
"""

from __future__ import annotations

from baseline import BaselineStats
from detection.base import Detector
from detection.types import DimensionId, DimensionResult
from features import FeatureVector


FLAG_FADING_DIVERGENCE  = 1 << 24
FLAG_PROFIT_QUALITY_LOW = 1 << 25
FLAG_ZSCORE_OUTLIER     = 1 << 26

SUB_SCORE_KEYS: tuple[str, ...] = (
    "fading_factor_divergence",
    "profit_quality_score",
    "zscore_normalised",
)


class PerformanceDetector:
    """Day-4 stub."""

    @property
    def dimension(self) -> DimensionId:
        return DimensionId.PERFORMANCE

    @property
    def algo_version(self) -> int:
        return 1

    def score(self, features: FeatureVector, baseline: BaselineStats) -> DimensionResult:
        return DimensionResult.empty(DimensionId.PERFORMANCE, algo_version=self.algo_version)


_: Detector = PerformanceDetector()
