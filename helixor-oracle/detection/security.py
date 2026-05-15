"""
detection/security.py — Dimension 5: security signals.

STATUS: Day 4 STUB. The real implementation lands in Days 9-10.

REAL IMPLEMENTATION (Days 9-10) will produce:
  - Day 9: the 31 MCP attack-vector pattern library
           (prompt-injection patterns, exfiltration shapes, tool-abuse signatures)
  - Day 10: model-hash integrity check, behavioural-baseline anomaly,
           Sybil cluster signal (graph analysis over shared counterparties)

Output: security score 0..MAX_SCORE (150). Severe findings also set the
UNIVERSAL `IMMEDIATE_RED` bit so the composite can short-circuit straight to RED.

DIMENSION-SPECIFIC FLAG BITS — uses a different range to avoid overlap with
other dimensions (each dimension owns its own bit range — see detection/types.py).
Day-9-10 will lock down the exact bit assignments; the universal IMMEDIATE_RED
bit is the primary signal the composite acts on.
"""

from __future__ import annotations

from baseline import BaselineStats
from detection.base import Detector
from detection.types import DimensionId, DimensionResult
from features import FeatureVector


SUB_SCORE_KEYS: tuple[str, ...] = (
    "attack_pattern_score",
    "integrity_score",
    "sybil_cluster_signal",
)


class SecurityDetector:
    """Day-4 stub."""

    @property
    def dimension(self) -> DimensionId:
        return DimensionId.SECURITY

    @property
    def algo_version(self) -> int:
        return 1

    def score(self, features: FeatureVector, baseline: BaselineStats) -> DimensionResult:
        return DimensionResult.empty(DimensionId.SECURITY, algo_version=self.algo_version)


_: Detector = SecurityDetector()
