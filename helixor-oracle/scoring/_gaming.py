"""
scoring/_gaming.py — gaming detection + confidence scoring, pure stdlib.

Two Day-13 primitives that turn the Day-4 weighted aggregate into the real
composite scorer:

GAMING CHECK — Shannon-entropy collapse
---------------------------------------
An agent that games the trust score optimises for the METRIC, not for real
performance. The tell: it stops doing varied things and repeats whatever
the score rewards. Behavioural diversity collapses — and behavioural
diversity IS Shannon entropy over the action distribution.

So the gaming check compares the agent's CURRENT behavioural entropy
against its BASELINE behavioural entropy. A drop beyond a threshold (>25%)
is the gaming signal: the agent narrowed its own behaviour to chase the
score.

This is intentionally one-directional. Entropy RISING is not gaming —
an agent doing MORE varied things is not optimising for a metric. Only a
COLLAPSE counts.

CONFIDENCE SCORE — how much data backs the score
------------------------------------------------
A score computed from 30 days and 150 transactions deserves more trust
than one computed from 3 days and 12 transactions. Confidence is a
0-1000-scaled measure of data sufficiency, combining transaction count,
active-day count, and the provisional / degraded-baseline flags. A
low-confidence score is still emitted — but consumers can see it is thin.
"""

from __future__ import annotations

import math


# =============================================================================
# Gaming check — entropy collapse
# =============================================================================

# A behavioural-entropy drop beyond this FRACTION of the baseline entropy
# flags gaming. 0.25 = "entropy fell by more than a quarter".
GAMING_ENTROPY_DROP_THRESHOLD = 0.25

# Below this absolute baseline entropy the check abstains: an agent that was
# already near-deterministic has no meaningful entropy to "collapse", and a
# percentage drop on a tiny base is noise.
GAMING_MIN_BASELINE_ENTROPY = 0.05


def detect_entropy_gaming(
    *,
    current_entropy:  float,
    baseline_entropy: float,
    threshold:        float = GAMING_ENTROPY_DROP_THRESHOLD,
) -> dict:
    """
    Detect score-gaming via behavioural-entropy collapse.

    Both entropies are normalised Shannon entropies in [0, 1] (0 = fully
    deterministic behaviour, 1 = maximally diverse).

    Returns a dict:
      gaming_detected — True iff entropy dropped by more than `threshold`
                        of the baseline
      drop_fraction   — (baseline - current) / baseline, clamped to [0, 1];
                        0.0 if entropy held or rose
      abstained       — True iff the baseline entropy was too low to assess

    Pure, deterministic.
    """
    # Guard non-finite inputs.
    if not (math.isfinite(current_entropy) and math.isfinite(baseline_entropy)):
        return {"gaming_detected": False, "drop_fraction": 0.0, "abstained": True}

    # An agent that was already near-deterministic — nothing to collapse.
    if baseline_entropy < GAMING_MIN_BASELINE_ENTROPY:
        return {"gaming_detected": False, "drop_fraction": 0.0, "abstained": True}

    drop = baseline_entropy - current_entropy
    if drop <= 0.0:
        # Entropy held or rose — not gaming, by construction.
        return {"gaming_detected": False, "drop_fraction": 0.0, "abstained": False}

    drop_fraction = min(1.0, drop / baseline_entropy)
    return {
        "gaming_detected": drop_fraction > threshold,
        "drop_fraction":   drop_fraction,
        "abstained":       False,
    }


# =============================================================================
# Confidence score — data sufficiency
# =============================================================================

# Data bars at which confidence is considered FULL. Below these it scales down.
CONFIDENCE_FULL_TX_COUNT   = 150     # transactions
CONFIDENCE_FULL_DAYS       = 30      # active days
# A provisional baseline caps confidence at this fraction of full.
PROVISIONAL_CONFIDENCE_CAP = 0.50
# A degraded-baseline flag multiplies confidence by this.
DEGRADED_CONFIDENCE_FACTOR = 0.70

CONFIDENCE_MAX = 1000


def compute_confidence(
    *,
    transaction_count:  int,
    days_with_activity: int,
    is_provisional:     bool,
    degraded_baseline:  bool,
) -> int:
    """
    A 0-1000 confidence score: how much data backs this trust score.

    Combines two data-sufficiency ratios (transaction count, active days),
    each saturating at its full-data bar, then applies the provisional cap
    and degraded-baseline factor.

      30 days + 150 tx, clean      → ~1000
      3 days + 12 tx               → low
      provisional baseline         → capped at 500
      degraded baseline flag       → x0.70

    Pure, deterministic. Returns an int in [0, 1000].
    """
    tx_ratio   = min(1.0, max(0, transaction_count) / CONFIDENCE_FULL_TX_COUNT)
    day_ratio  = min(1.0, max(0, days_with_activity) / CONFIDENCE_FULL_DAYS)

    # Geometric mean of the two ratios — BOTH must be healthy for high
    # confidence (an agent with 150 tx all in one day is not well-sampled).
    base = math.sqrt(tx_ratio * day_ratio)

    confidence = base
    if is_provisional:
        confidence = min(confidence, PROVISIONAL_CONFIDENCE_CAP)
    if degraded_baseline:
        confidence *= DEGRADED_CONFIDENCE_FACTOR

    return max(0, min(CONFIDENCE_MAX, int(round(confidence * CONFIDENCE_MAX))))


# =============================================================================
# 200-point delta guard rail
# =============================================================================

# The maximum a score may move in a single update. Preserved from the MVP:
# it bounds oracle instability and blocks single-update score manipulation.
MAX_SCORE_DELTA = 200


def apply_delta_guard_rail(
    *,
    new_score:      int,
    previous_score: int | None,
) -> dict:
    """
    Clamp a freshly computed score so it cannot move more than
    MAX_SCORE_DELTA from the previous score in a single update.

    `previous_score` is None for an agent's first-ever score — the guard
    rail does not apply to the first score (there is nothing to move FROM).

    Returns:
      score        — the final, guard-railed score
      clamped      — True iff the guard rail actually moved the score
      raw_delta    — (new_score - previous_score), 0 if no previous score

    This is NOT optional and NOT bypassable: every score that leaves
    compute_composite_score has passed through here.
    """
    if previous_score is None:
        return {"score": new_score, "clamped": False, "raw_delta": 0}

    raw_delta = new_score - previous_score
    if raw_delta > MAX_SCORE_DELTA:
        return {"score": previous_score + MAX_SCORE_DELTA,
                "clamped": True, "raw_delta": raw_delta}
    if raw_delta < -MAX_SCORE_DELTA:
        return {"score": previous_score - MAX_SCORE_DELTA,
                "clamped": True, "raw_delta": raw_delta}
    return {"score": new_score, "clamped": False, "raw_delta": raw_delta}
