"""
detection/consistency.py — Dimension 4: behavioural consistency.

STATUS: Day 4 STUB. The real implementation lands in Day 12.

REAL IMPLEMENTATION (Day 12) will produce:
  - Tool-stability: how consistent the agent's tool-invocation mix is over time
  - Activity-rhythm regularity (entropy of time-of-day / inter-tx timing)
  - Counterparty-outcome consistency
  - Domain classifier — does the agent behave within its declared domain?

Output: consistency score 0..MAX_SCORE (200).

DIMENSION-SPECIFIC FLAG BITS (27..30):
   27 = TOOL_INSTABILITY     tool mix shifted significantly
   28 = RHYTHM_BROKEN        activity rhythm broke vs baseline
   29 = COUNTERPARTY_FLIP    same counterparty, different outcome pattern
   30 = DOMAIN_DRIFT         observed behaviour outside declared domain
"""

from __future__ import annotations

from baseline import BaselineStats
from detection.base import Detector
from detection.types import DimensionId, DimensionResult
from features import FeatureVector


FLAG_TOOL_INSTABILITY  = 1 << 27
FLAG_RHYTHM_BROKEN     = 1 << 28
FLAG_COUNTERPARTY_FLIP = 1 << 29
FLAG_DOMAIN_DRIFT      = 1 << 30

SUB_SCORE_KEYS: tuple[str, ...] = (
    "tool_stability",
    "rhythm_regularity",
    "counterparty_consistency",
    "domain_alignment",
)


class ConsistencyDetector:
    """Day-4 stub."""

    @property
    def dimension(self) -> DimensionId:
        return DimensionId.CONSISTENCY

    @property
    def algo_version(self) -> int:
        return 1

    def score(self, features: FeatureVector, baseline: BaselineStats) -> DimensionResult:
        return DimensionResult.empty(DimensionId.CONSISTENCY, algo_version=self.algo_version)


_: Detector = ConsistencyDetector()
