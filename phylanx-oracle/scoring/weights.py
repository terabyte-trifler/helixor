"""
scoring/weights.py — the V2 weight vector across the five dimensions.

RECONCILING DOC 2'S NUMBERS WITH THE V2 ARCHITECTURE
----------------------------------------------------
Doc 2 specifies a 25/25/20/15/15 split across these labels:
    tx success 25%, behavioural consistency 25%, tool stability 20%,
    activity rhythm 15%, counterparty outcomes 15%.

Those are SIGNALS, not the five DETECTION DIMENSIONS the engine is built
around (drift, anomaly, performance, consistency, security). The mapping
isn't 1:1 — most of Doc 2's signals live INSIDE the consistency and
performance detectors as sub-scores, not as separate dimensions.

The V2 detection-engine architecture re-expresses Doc 2's priorities as
the five-dimension vector below. Rationale per dimension:

  DRIFT       0.20  — "did the agent's behaviour shift" subsumes Doc 2's
                       "tx success change" + "activity rhythm change".
  ANOMALY     0.20  — catches statistical outliers / sudden jumps; this is
                       what Doc 2 calls "behavioural consistency" at the
                       quantitative end.
  PERFORMANCE 0.20  — Doc 2's "tx success" + profit-quality vs Pyth.
  CONSISTENCY 0.20  — Doc 2's "tool stability" + "counterparty outcomes" +
                       domain alignment.
  SECURITY    0.20  — Doc 2 does not weight security in its 5-bucket spec;
                       V2 elevates it to a peer dimension because security
                       signals are existential (one prompt-injection = trust
                       gone). Equal weight here, plus the IMMEDIATE_RED
                       fast-path bit that can short-circuit the whole score.

A flat 20% across all five is the right Day-4 default. It is documented +
versioned: any future re-weighting bumps SCORING_WEIGHTS_VERSION and the
fingerprint, so detectors and the composite can refuse a stale weighting.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from types import MappingProxyType

from detection.types import DIMENSION_MAX_SCORES, DimensionId


# Version of the weight vector itself. Bumped if WEIGHTS changes.
SCORING_WEIGHTS_VERSION = 1


WEIGHTS: Mapping[DimensionId, float] = MappingProxyType({
    DimensionId.DRIFT:       0.20,
    DimensionId.ANOMALY:     0.20,
    DimensionId.PERFORMANCE: 0.20,
    DimensionId.CONSISTENCY: 0.20,
    DimensionId.SECURITY:    0.20,
})


# Hard import-time check: weights cover all five dimensions and sum to 1.
def _validate_weights() -> None:
    if set(WEIGHTS.keys()) != set(DimensionId.ordered()):
        raise AssertionError(
            f"WEIGHTS must cover every DimensionId. "
            f"missing={set(DimensionId.ordered()) - set(WEIGHTS.keys())}"
        )
    total = sum(WEIGHTS.values())
    if abs(total - 1.0) > 1e-9:
        raise AssertionError(f"WEIGHTS must sum to 1.0, got {total!r}")
    for dim, w in WEIGHTS.items():
        if not (0.0 <= w <= 1.0):
            raise AssertionError(f"WEIGHTS[{dim.value}] = {w} outside [0,1]")


_validate_weights()


def scoring_schema_fingerprint() -> str:
    """
    SHA-256 fingerprint of (weights version, ordered (dim_id, max_score, weight))
    plus SCORING_ALGO_VERSION. Stamped into every ScoreResult so a future
    weight or max-score change is CAUGHT instead of silently shifting scores.

    Mirrors the FeatureVector.feature_schema_fingerprint() pattern from Day 1.
    """
    from scoring.composite import SCORING_ALGO_VERSION
    payload_parts = [f"algo=v{SCORING_ALGO_VERSION}", f"weights=v{SCORING_WEIGHTS_VERSION}"]
    for dim in DimensionId.ordered():
        max_s = DIMENSION_MAX_SCORES[dim]
        w     = WEIGHTS[dim]
        payload_parts.append(f"{dim.value}:max={max_s}:w={w:.6f}")
    payload = "|".join(payload_parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
