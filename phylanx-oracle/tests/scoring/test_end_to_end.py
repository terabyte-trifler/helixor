"""
tests/scoring/test_end_to_end.py — THE DAY-4 DONE-WHEN.

"The scoring pipeline runs end-to-end with stub detectors returning zeros,
producing a valid (meaningless) 0-1000 score. The skeleton is real; only
the detector internals are stubs."

This test wires Day 1 -> Day 2 -> Day 4 stubs together and asserts the
final ScoreResult is valid, exactly zero, and carries the full provenance
chain stamped correctly.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from baseline import compute_baseline
from detection import (
    DimensionId,
    FlagBit,
    default_registry,
    run_detection_engine,
)
from features import ExtractionWindow, Transaction, extract


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


def _make_txs(days: int = 30):
    """A realistic agent transaction history; `days` days x 5 tx/day."""
    txs = []
    for day in range(days):
        for k in range(5):
            idx = day * 5 + k
            txs.append(Transaction(
                signature=f"S{idx:08d}".ljust(64, "x"),
                slot=100_000_000 + idx,
                block_time=REF_END - timedelta(hours=day * 24 + k * 2 + 1.0),
                success=(idx % 20) != 0,
                program_ids=("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",),
                sol_change=1_000_000 if k % 2 == 0 else -400_000,
                fee=5000,
                priority_fee=1000 if k % 3 == 0 else 0,
                compute_units=200_000,
                counterparty=f"cp{idx % 7}",
            ))
    return txs


def test_full_pipeline_day1_to_day4():
    """
    Day 1 (features) -> Day 2 (baseline) -> Day 4 (detection + scoring).
    """
    # Day 2: compute the baseline over the full 30-day window.
    window = ExtractionWindow.ending_at(REF_END, days=30)
    txs = _make_txs()
    baseline = compute_baseline(
        agent_wallet="11111111111111111111111111111112",
        transactions=txs,
        window=window,
        computed_at=REF_END,
    )
    assert baseline.is_compatible_with_current_engine()
    assert len(baseline.stats_hash) == 64

    # Day 1: extract the CURRENT 100-feature vector — one day's behaviour,
    # comparable to the baseline's per-feature daily means.
    one_day = ExtractionWindow.ending_at(REF_END, days=1)
    features = extract(_make_txs(days=1), one_day)
    assert len(features.to_list()) == 100

    # Day 4 contract + Day 5 drift: run the detection engine + composite scorer
    result = run_detection_engine(features, baseline, default_registry(), computed_at=REF_END)

    # ── THE DONE-WHEN — Phase 1 complete (Day 12) ───────────────────────────
    # 1. Valid 0-1000 score
    assert 0 <= result.score <= 1000
    # 2. Day 12: ALL FIVE dimensions are real. A clean agent scores high.
    assert 600 < result.score <= 1000
    # 3. No stub dimensions left → INSUFFICIENT_DATA no longer aggregates.
    assert not result.has_flag(FlagBit.INSUFFICIENT_DATA)
    # 4. No false IMMEDIATE_RED on a clean agent.
    assert not result.immediate_red
    # 5. Every dimension represented
    assert set(result.dimension_results.keys()) == set(DimensionId.ordered())
    # 7. Weighted contributions sum to score (Day-13 invariant)
    assert sum(result.weighted_contributions.values()) == result.score
    # 8. All five dimensions are real contributors — Phase 1 complete.
    for dim in DimensionId.ordered():
        assert result.dimension_results[dim].score > 0
    # 9. Provenance chain is complete
    assert result.baseline_stats_hash == baseline.stats_hash
    assert result.feature_schema_fingerprint  # non-empty
    assert result.scoring_schema_fingerprint  # non-empty


def test_full_pipeline_is_deterministic():
    """Two complete pipeline runs with identical inputs produce identical scores."""
    window = ExtractionWindow.ending_at(REF_END, days=30)
    txs = _make_txs()
    baseline = compute_baseline(
        agent_wallet="11111111111111111111111111111112",
        transactions=txs,
        window=window,
        computed_at=REF_END,
    )
    one_day = ExtractionWindow.ending_at(REF_END, days=1)
    features = extract(_make_txs(days=1), one_day)
    r1 = run_detection_engine(features, baseline, default_registry(), computed_at=REF_END)
    r2 = run_detection_engine(features, baseline, default_registry(), computed_at=REF_END)

    # The whole composite is byte-identical for byte-identical inputs.
    # (Required for the Phase-4 3-node BFT oracle cluster consensus.)
    assert r1.score == r2.score
    assert r1.alert == r2.alert
    assert r1.aggregated_flags == r2.aggregated_flags
    assert r1.weighted_contributions == r2.weighted_contributions
    assert r1.scoring_schema_fingerprint == r2.scoring_schema_fingerprint
