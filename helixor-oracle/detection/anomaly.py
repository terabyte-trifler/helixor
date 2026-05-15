"""
detection/anomaly.py — Dimension 2: anomaly ensemble + Isolation Forest.

STATUS: Day 4 STUB. The real implementation lands in Days 7-8.

REAL IMPLEMENTATION (Days 7-8) will produce:
  - Method 1: prediction uncertainty
  - Method 2: Mahalanobis distance vs baseline
  - Method 3: per-feature z-score aggregation
  - Method 4: n-gram sequence deviation
  - Method 5: adversarial-signal (sudden feature-space jumps)
  - Isolation Forest over the 100-feature vector (contamination=0.01)

Output: anomaly score 0..MAX_SCORE (200) + `IMMEDIATE_RED` fast-path flag
for severe anomalies (the security detector also uses IMMEDIATE_RED).

DIMENSION-SPECIFIC FLAG BITS (16..21):
   16  = METHOD_1 fired
   17  = METHOD_2 fired
   18  = METHOD_3 fired
   19  = METHOD_4 fired
   20  = METHOD_5 fired
   21  = ISOFOREST flagged
"""

from __future__ import annotations

from baseline import BaselineStats
from detection.base import Detector
from detection.types import DimensionId, DimensionResult
from features import FeatureVector


FLAG_METHOD_1  = 1 << 16
FLAG_METHOD_2  = 1 << 17
FLAG_METHOD_3  = 1 << 18
FLAG_METHOD_4  = 1 << 19
FLAG_METHOD_5  = 1 << 20
FLAG_ISOFOREST = 1 << 21

SUB_SCORE_KEYS: tuple[str, ...] = (
    "method_1_uncertainty",
    "method_2_mahalanobis",
    "method_3_zscore",
    "method_4_ngram_deviation",
    "method_5_adversarial",
    "isoforest_score",
)


class AnomalyDetector:
    """Day-4 stub."""

    @property
    def dimension(self) -> DimensionId:
        return DimensionId.ANOMALY

    @property
    def algo_version(self) -> int:
        return 1

    def score(self, features: FeatureVector, baseline: BaselineStats) -> DimensionResult:
        return DimensionResult.empty(DimensionId.ANOMALY, algo_version=self.algo_version)


_: Detector = AnomalyDetector()
