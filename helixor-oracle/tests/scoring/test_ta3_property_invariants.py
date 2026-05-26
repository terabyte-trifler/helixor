"""
tests/scoring/test_ta3_property_invariants.py — TA-3 property-based invariants.

THE TRUST ASSUMPTION (audit)
-----------------------------
    "Scoring algorithm is correct — no formal verification; only unit tests."

The kernel is already:
  * Hashed and pinned on-chain (AW-04 bundle_hash)
  * Determinism-guarded (banker's rounding, banned numpy/scipy, pinned Py)
  * Unit-tested for fixtures and boundaries

What was missing: PROPERTY tests that hammer many random inputs against
arithmetic invariants the scorer MUST satisfy. We do this with a
deterministic PRNG (seeded `random.Random(seed)`) instead of pulling in
`hypothesis` — same coverage, zero new runtime deps, and reproducibility
that matches the rest of the determinism contract.

THE INVARIANTS
--------------
For every randomly-sampled set of (drift, anomaly, performance, consistency,
security) inputs over their full legal ranges:

  P1. SCORE BOUND        — score ∈ [0, 1000]                       (composite.py:140)
  P2. CONFIDENCE BOUND   — confidence ∈ [0, 1000]                  (composite.py:192)
  P3. TYPE CONTRACT      — score is `int`, alert is `AlertTier`    (composite.py:139)
  P4. ALERT BOUNDARY     — alert ↔ score per GREEN/YELLOW/RED      (composite.py:144)
  P5. IMMEDIATE_RED      — IMMEDIATE_RED flag ⇒ alert = RED        (composite.py:151)
  P6. CONTRIB SUM        — Σ contributions ≈ score (±5 rounding,
                            unless delta-clamped)                   (composite.py:171)
  P7. DETERMINISM        — same inputs → byte-identical output     (Phase-4 BFT)
  P8. ZERO IDENTITY      — all-zero inputs → score 0, alert RED    (boundary)
  P9. MONOTONICITY       — raising any single dim's input never
                            DECREASES the score (unless delta-clamped)

Why these properties?

P1-P5 are the type-level guard rails the composite already enforces in
`ScoreResult.__post_init__`; the property tests exercise the FULL legal
input space rather than the small set of fixtures, catching e.g. an
off-by-one that only shows up at the extremes.

P6 is the Day-13 "weighted contributions sum to score" invariant — the
audit's reproducibility hook for "explain why this score is what it is".

P7 is the BFT consensus requirement — two nodes computing the same inputs
must produce byte-identical outputs.

P8 pins the boundary so a future weight tweak cannot accidentally promote
the all-zero corner above the RED threshold.

P9 is the directional invariant a consumer reasonably assumes: a more-
suspicious dimension should never make the AGENT look healthier. Violating
this would silently invert the meaning of a detector.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone

import pytest

from detection.types import DIMENSION_MAX_SCORES, DimensionId, DimensionResult, FlagBit
from scoring import AlertTier, compute_composite_score
from scoring.composite import GREEN_THRESHOLD, YELLOW_THRESHOLD, _alert_for


REF_TIME = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)

#: Number of random samples per property. Bumped if a regression slips
#: through; deterministic seed keeps reproduction trivial.
SAMPLES = 200


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def _result(dim: DimensionId, score: int, *, immediate_red: bool = False) -> DimensionResult:
    flags = int(FlagBit.IMMEDIATE_RED) if immediate_red else 0
    return DimensionResult(
        dimension=dim,
        score=score,
        max_score=DIMENSION_MAX_SCORES[dim],
        flags=flags,
        sub_scores={},
        algo_version=1,
    )


def _random_inputs(rng: random.Random) -> dict[DimensionId, DimensionResult]:
    """One random sample across every dimension's legal score range."""
    return {
        dim: _result(dim, rng.randint(0, DIMENSION_MAX_SCORES[dim]))
        for dim in DimensionId.ordered()
    }


# ----------------------------------------------------------------------------
# P1, P2, P3, P4 — type + bound + alert consistency under random inputs
# ----------------------------------------------------------------------------

def test_property_score_and_alert_bounds_hold_for_random_inputs(baseline):
    rng = random.Random(0xC0FFEE)
    for i in range(SAMPLES):
        dims = _random_inputs(rng)
        r = compute_composite_score(dims, baseline, computed_at=REF_TIME)
        # P1
        assert 0 <= r.score <= 1000, f"sample {i}: score {r.score} out of bounds"
        assert isinstance(r.score, int) and not isinstance(r.score, bool)
        # P2
        assert 0 <= r.confidence <= 1000
        # P3
        assert isinstance(r.alert, AlertTier)
        # P4 (only when IMMEDIATE_RED is not set; the random sampler does
        # not set it on the dimensions, so this branch is always exercised)
        if not r.immediate_red:
            assert r.alert is _alert_for(r.score), (
                f"sample {i}: alert {r.alert.value} != _alert_for({r.score})"
            )


# ----------------------------------------------------------------------------
# P5 — IMMEDIATE_RED flag forces RED, regardless of score
# ----------------------------------------------------------------------------

def test_property_immediate_red_forces_red_regardless_of_underlying_score(baseline):
    rng = random.Random(0xBADA55)
    for _ in range(50):
        # Random underlying scores; set IMMEDIATE_RED on SECURITY.
        scores = {dim: rng.randint(0, DIMENSION_MAX_SCORES[dim]) for dim in DimensionId.ordered()}
        dims = {
            dim: _result(dim, scores[dim], immediate_red=(dim is DimensionId.SECURITY))
            for dim in DimensionId.ordered()
        }
        r = compute_composite_score(dims, baseline, computed_at=REF_TIME)
        assert r.immediate_red is True
        assert r.alert is AlertTier.RED, (
            f"IMMEDIATE_RED set but alert={r.alert.value} (score={r.score})"
        )


# ----------------------------------------------------------------------------
# P6 — weighted contributions sum (≈ score, ±5) under random inputs
# ----------------------------------------------------------------------------

def test_property_contributions_sum_within_rounding_of_score(baseline):
    rng = random.Random(0xFEEDFACE)
    for i in range(SAMPLES):
        dims = _random_inputs(rng)
        r = compute_composite_score(dims, baseline, computed_at=REF_TIME)
        if r.delta_clamped:
            # The clamp intentionally breaks the sum identity — out of scope
            # for this property; `previous_score=None` above means we never
            # see the clamp here, but be defensive.
            continue
        contrib_sum = sum(r.weighted_contributions.values())
        assert abs(contrib_sum - r.score) <= 5, (
            f"sample {i}: contributions sum {contrib_sum} disagrees with "
            f"score {r.score} by > 5"
        )


# ----------------------------------------------------------------------------
# P7 — determinism: same inputs → identical output
# ----------------------------------------------------------------------------

def test_property_determinism_same_inputs_byte_identical_output(baseline):
    rng = random.Random(0xDEADBEEF)
    for _ in range(50):
        dims = _random_inputs(rng)
        r1 = compute_composite_score(dims, baseline, computed_at=REF_TIME)
        r2 = compute_composite_score(dims, baseline, computed_at=REF_TIME)
        assert r1.score == r2.score
        assert r1.alert is r2.alert
        assert r1.confidence == r2.confidence
        assert r1.aggregated_flags == r2.aggregated_flags
        assert dict(r1.weighted_contributions) == dict(r2.weighted_contributions)
        assert r1.scoring_schema_fingerprint == r2.scoring_schema_fingerprint


# ----------------------------------------------------------------------------
# P8 — boundary: all-zero inputs land at score 0 → RED
# ----------------------------------------------------------------------------

def test_property_all_zero_lands_at_red(baseline):
    zeros = {dim: _result(dim, 0) for dim in DimensionId.ordered()}
    r = compute_composite_score(zeros, baseline, computed_at=REF_TIME)
    assert r.score == 0
    assert r.alert is AlertTier.RED


# ----------------------------------------------------------------------------
# P9 — monotonicity: raising ONE dimension's score never decreases composite
# ----------------------------------------------------------------------------

@pytest.mark.parametrize("dim", list(DimensionId.ordered()))
def test_property_monotonic_in_each_dimension(dim, baseline):
    """
    For each dimension, hold the others at a random fixed point, sweep the
    target dimension across its legal range in increasing steps, and assert
    the composite never decreases.

    This is the directional invariant a consumer assumes: a detector
    raising its score MUST make the agent look at least as suspicious.
    """
    rng = random.Random(hash(dim.value) & 0xFFFFFFFF)

    # Fix the OTHER dimensions at a random point.
    fixed = {
        other: _result(other, rng.randint(0, DIMENSION_MAX_SCORES[other]))
        for other in DimensionId.ordered() if other is not dim
    }

    max_target = DIMENSION_MAX_SCORES[dim]
    # 25 sample points across the legal range, monotone non-decreasing.
    points = sorted({0, max_target} | {
        rng.randint(0, max_target) for _ in range(23)
    })

    prev = -1
    for v in points:
        dims = dict(fixed)
        dims[dim] = _result(dim, v)
        r = compute_composite_score(dims, baseline, computed_at=REF_TIME)
        assert r.score >= prev, (
            f"monotonicity broken: dim={dim.value}, target={v}, "
            f"score={r.score}, prev={prev}"
        )
        prev = r.score


# ----------------------------------------------------------------------------
# P10 — alert tier boundary correctness (deterministic, not random)
# ----------------------------------------------------------------------------

def test_property_alert_tier_boundaries_exact():
    # _alert_for is pure; pin the boundaries explicitly so any future
    # threshold tweak fails loudly here.
    assert _alert_for(GREEN_THRESHOLD)     is AlertTier.GREEN
    assert _alert_for(GREEN_THRESHOLD - 1) is AlertTier.YELLOW
    assert _alert_for(YELLOW_THRESHOLD)    is AlertTier.YELLOW
    assert _alert_for(YELLOW_THRESHOLD -1) is AlertTier.RED
    assert _alert_for(0)                   is AlertTier.RED
    assert _alert_for(1000)                is AlertTier.GREEN
