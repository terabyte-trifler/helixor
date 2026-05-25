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
from scoring._gaming import (
    GAMING_ENTROPY_DROP_THRESHOLD,
    MAX_SCORE_DELTA,
    apply_delta_guard_rail,
    compute_confidence,
    detect_entropy_gaming,
)
from scoring.determinism import (
    BANNED_MATH_BACKENDS,
    SUPPORTED_PYTHON_VERSIONS,
    DeterminismVerdict,
    ScoringDeterminismRefused,
    enforce_scoring_determinism,
    evaluate as evaluate_scoring_determinism,
    quantize_to_int,
    scan_source_for_banned_imports,
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
    # Day-13 — gaming detection, confidence, delta guard rail
    "detect_entropy_gaming",
    "compute_confidence",
    "apply_delta_guard_rail",
    "GAMING_ENTROPY_DROP_THRESHOLD",
    "MAX_SCORE_DELTA",
    # VULN-18 — scoring determinism guard
    "quantize_to_int",
    "enforce_scoring_determinism",
    "evaluate_scoring_determinism",
    "scan_source_for_banned_imports",
    "DeterminismVerdict",
    "ScoringDeterminismRefused",
    "SUPPORTED_PYTHON_VERSIONS",
    "BANNED_MATH_BACKENDS",
]
