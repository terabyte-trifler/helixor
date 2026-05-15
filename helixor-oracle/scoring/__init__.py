"""
helixor-oracle / scoring — V2 composite scorer.

Public API (Day 4 scaffolding):
    compute_composite_score(dimension_results, baseline) -> ScoreResult
    ScoreResult, AlertTier
    WEIGHTS, SCORING_ALGO_VERSION, SCORING_WEIGHTS_VERSION
    scoring_schema_fingerprint()
    GREEN_THRESHOLD, YELLOW_THRESHOLD
"""

from __future__ import annotations

from scoring.composite import (
    GREEN_THRESHOLD,
    SCORING_ALGO_VERSION,
    YELLOW_THRESHOLD,
    AlertTier,
    ScoreResult,
    compute_composite_score,
)
from scoring.weights import (
    SCORING_WEIGHTS_VERSION,
    WEIGHTS,
    scoring_schema_fingerprint,
)

__all__ = [
    "compute_composite_score",
    "ScoreResult",
    "AlertTier",
    "WEIGHTS",
    "SCORING_ALGO_VERSION",
    "SCORING_WEIGHTS_VERSION",
    "scoring_schema_fingerprint",
    "GREEN_THRESHOLD",
    "YELLOW_THRESHOLD",
]
