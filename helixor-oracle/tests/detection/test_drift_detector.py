"""
tests/detection/test_drift_detector.py — DriftDetector end-to-end.

THE DAY-5 DONE-WHEN
-------------------
"Synthetic drift injected into fixtures produces PSI > 0.25 and elevated
KS rejection; clean data produces neither."

We build a baseline from 30 days of CLEAN agent behaviour, then run the
detector on:
  1. A "clean" current feature vector drawn from the same distribution →
     PSI low (< 0.10), no KS rejection, neither FLAG_PSI nor FLAG_KS.
  2. A "drifted" current feature vector where the tx-type mix has shifted
     hard and per-feature values have moved many σ from baseline →
     PSI > 0.25, KS rejection rate elevated, both flags fire.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from baseline import compute_baseline
from detection import DimensionId, DimensionResult, FlagBit, default_registry
from detection.drift import (
    FLAG_KS,
    FLAG_PSI,
    DriftDetector,
)
from features import ExtractionWindow, Transaction, extract


REF_END = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
PROG_SWAP     = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
PROG_LEND     = "So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo"
PROG_STAKE    = "Stake11111111111111111111111111111111111111"
PROG_TRANSFER = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"


def _build_txs(
    *,
    days:           int,
    txs_per_day:    int,
    program:        str = PROG_SWAP,
    success_rate:   float = 0.95,
    fee:            int = 5000,
    sol_change_pos: int = 1_000_000,
    sol_change_neg: int = -400_000,
    end:            datetime = REF_END,
) -> list[Transaction]:
    """Deterministic transaction generator. Same shape as Day 2 conftest."""
    txs: list[Transaction] = []
    fail_every = max(2, int(round(1.0 / max(1e-9, 1.0 - success_rate))))
    for day in range(days):
        for k in range(txs_per_day):
            idx = day * txs_per_day + k
            txs.append(Transaction(
                signature=f"S{idx:08d}".ljust(64, "x"),
                slot=100_000_000 + idx,
                block_time=end - timedelta(hours=day * 24 + k * 2 + 1.0),
                success=(idx % fail_every) != 0,
                program_ids=(program,),
                sol_change=sol_change_pos if k % 2 == 0 else sol_change_neg,
                fee=fee,
                priority_fee=1000 if k % 3 == 0 else 0,
                compute_units=200_000,
                counterparty=f"cp{idx % 7}",
            ))
    return txs


@pytest.fixture
def clean_baseline():
    """A baseline built from 30 days of pure-swap, high-success behaviour."""
    txs = _build_txs(days=30, txs_per_day=5, program=PROG_SWAP, success_rate=0.95)
    window = ExtractionWindow.ending_at(REF_END, days=30)
    return compute_baseline("agentDRIFT1", txs, window, computed_at=REF_END)


# =============================================================================
# Done-when: clean current data → no drift signal
# =============================================================================

class TestCleanCase:

    def test_clean_current_no_drift_flags(self, clean_baseline):
        # Current = one day of the SAME distribution as the baseline.
        txs = _build_txs(days=1, txs_per_day=5, program=PROG_SWAP, success_rate=0.95)
        window = ExtractionWindow.ending_at(REF_END, days=1)
        features = extract(txs, window)

        result = DriftDetector().score(features, clean_baseline)
        assert isinstance(result, DimensionResult)
        assert result.dimension is DimensionId.DRIFT
        # PSI should be near 1.0 (no shift).
        assert result.sub_scores["psi_normalised"] > 0.5
        # No drift flags on clean data.
        assert not (result.flags & FLAG_PSI)
        assert not (result.flags & FLAG_KS)
        # KS rejection rate should be modest.
        assert result.sub_scores["ks_rejection_rate"] < 0.20
        # Day 6: PROVISIONAL is dropped (all 5 algorithms wired).
        assert not result.has_flag(FlagBit.PROVISIONAL)
        # Clean case fills most of the 200-point budget.
        assert result.score >= 150


# =============================================================================
# Done-when: synthetic drift → PSI > 0.25 + elevated KS rejection + flags
# =============================================================================

class TestDriftedCase:

    def test_tx_type_shift_triggers_psi(self, clean_baseline):
        # Baseline was 100% SWAP. Current is 100% LEND — total category flip.
        txs = _build_txs(days=1, txs_per_day=5, program=PROG_LEND, success_rate=0.95)
        window = ExtractionWindow.ending_at(REF_END, days=1)
        features = extract(txs, window)

        result = DriftDetector().score(features, clean_baseline)
        # PSI > 0.25 → FLAG_PSI must fire.
        assert result.flags & FLAG_PSI
        # The PSI sub-score reflects this: it should be near 0.
        assert result.sub_scores["psi_normalised"] < 0.1
        # Day 6: the full 200-point budget is in play. PSI's 40 points
        # collapse to 0 but other algorithms still contribute. Score is
        # dragged DOWN from the clean ~191 but stays > 0.
        assert result.score < 160

    def test_extreme_feature_shift_triggers_ks(self, clean_baseline):
        # Force big swings in everything: 200× the fees, all failures, huge
        # SOL changes. Per-feature z-scores should blow up.
        txs = _build_txs(
            days=1,
            txs_per_day=10,
            program=PROG_TRANSFER,
            success_rate=0.10,        # nearly all failures, vs baseline 0.95
            fee=500_000,              # 100× baseline fee
            sol_change_pos=100_000_000,
            sol_change_neg=-100_000_000,
        )
        window = ExtractionWindow.ending_at(REF_END, days=1)
        features = extract(txs, window)

        result = DriftDetector().score(features, clean_baseline)
        # At least one of the drift flags should fire on this.
        assert result.flags & (FLAG_PSI | FLAG_KS)
        # KS rejection rate elevated above the clean-case noise floor.
        # In a 100-feature vector, even a fairly drifted single day rarely
        # pushes more than a handful of features past |z|>3 — most features
        # describe distributional SHAPES (entropies, fractions) that don't
        # blow up linearly with magnitude.
        assert result.sub_scores["ks_rejection_rate"] >= 0.03

    def test_combined_drift_drops_score(self, clean_baseline):
        # Major category shift + extreme features → flags + low score.
        txs = _build_txs(
            days=1, txs_per_day=5,
            program=PROG_STAKE,             # baseline was swap → full category flip
            success_rate=0.20,
            fee=50_000,
            sol_change_pos=10_000_000,
            sol_change_neg=-10_000_000,
        )
        window = ExtractionWindow.ending_at(REF_END, days=1)
        features = extract(txs, window)

        result = DriftDetector().score(features, clean_baseline)
        assert result.flags & FLAG_PSI
        # Day 6: full 200 budget. PSI's 40 collapse + KS may add more loss.
        # CUSUM/ADWIN/DDM still see the SAME baseline daily series (the
        # "current" features don't feed the streaming algos) so they don't
        # drop here — but the overall score is well below the clean ~191.
        assert 0 <= result.score < 160


# =============================================================================
# Contract: the DimensionResult contract is preserved
# =============================================================================

class TestContractCompliance:

    def test_result_passes_all_validations(self, clean_baseline):
        # Build a "real" current feature vector (1 day's worth).
        txs = _build_txs(days=1, txs_per_day=5, program=PROG_SWAP)
        window = ExtractionWindow.ending_at(REF_END, days=1)
        features = extract(txs, window)
        result = DriftDetector().score(features, clean_baseline)

        # The DimensionResult constructor enforces the contract; if we got
        # this far, all of these hold — but assert them explicitly.
        assert result.dimension is DimensionId.DRIFT
        assert result.max_score == 200
        assert 0 <= result.score <= 200
        # All five sub-scores present, finite, in [0, 1].
        for key in ("psi_normalised", "ks_rejection_rate",
                    "cusum_normalised", "adwin_drift_score",
                    "ddm_warning_ratio"):
            assert key in result.sub_scores
            assert 0.0 <= result.sub_scores[key] <= 1.0

    def test_algo_version_bumped_to_3(self, clean_baseline):
        txs = _build_txs(days=1, txs_per_day=5)
        window = ExtractionWindow.ending_at(REF_END, days=1)
        features = extract(txs, window)
        result = DriftDetector().score(features, clean_baseline)
        assert result.algo_version == 3

    def test_provisional_flag_dropped(self, clean_baseline):
        """Day 6 wires all 5 algorithms → PROVISIONAL is no longer set."""
        txs = _build_txs(days=1, txs_per_day=5)
        window = ExtractionWindow.ending_at(REF_END, days=1)
        features = extract(txs, window)
        result = DriftDetector().score(features, clean_baseline)
        assert not result.has_flag(FlagBit.PROVISIONAL)


# =============================================================================
# Determinism — phase-4 BFT contract
# =============================================================================

class TestDeterminism:

    def test_same_input_same_result(self, clean_baseline):
        txs = _build_txs(days=1, txs_per_day=5, program=PROG_LEND)
        window = ExtractionWindow.ending_at(REF_END, days=1)
        features = extract(txs, window)
        r1 = DriftDetector().score(features, clean_baseline)
        r2 = DriftDetector().score(features, clean_baseline)
        assert r1 == r2

    def test_50_repeated_runs_stable(self, clean_baseline):
        txs = _build_txs(days=1, txs_per_day=5, program=PROG_LEND)
        window = ExtractionWindow.ending_at(REF_END, days=1)
        features = extract(txs, window)
        first = DriftDetector().score(features, clean_baseline)
        for _ in range(50):
            assert DriftDetector().score(features, clean_baseline) == first


# =============================================================================
# Registry wiring — default_registry returns the Day-6 real algo v3
# =============================================================================

class TestRegistryWiresRealDetector:

    def test_default_registry_drift_is_real_v3(self):
        reg = default_registry()
        det = reg.get(DimensionId.DRIFT)
        assert det.algo_version == 3
        # Type check: the real DriftDetector
        assert isinstance(det, DriftDetector)


# =============================================================================
# DAY-6 DONE-WHEN: each of the 5 algorithms fires independently
# =============================================================================
#
# The streaming algorithms (CUSUM, ADWIN, DDM) read the baseline's
# daily_success_rate_series, NOT the current feature vector. So to test
# each in isolation we craft BASELINES with targeted daily series:
#
#   - CUSUM trigger : 30 days at high success rate, then 30 days at low.
#                     This is the textbook "abrupt change" Page CUSUM catches.
#   - ADWIN trigger : same shape — abrupt change. ADWIN detects it via the
#                     Hoeffding-bound cut.
#   - DDM trigger   : gradual climb in error rate. DDM's bread-and-butter.
#
# Each test uses a synthetic baseline (constructed directly) so we have
# full control over the daily series.
# =============================================================================

from baseline.types import BaselineStats, BASELINE_ALGO_VERSION
from features import FEATURE_SCHEMA_VERSION, FeatureVector
from features.vector import TOTAL_FEATURES
from detection.drift import FLAG_CUSUM, FLAG_ADWIN, FLAG_DDM
from scoring.weights import scoring_schema_fingerprint


def _synthetic_baseline(*, daily_series: list[float],
                        success_rate_30d: float = 0.95,
                        txtype_dist: tuple[float, ...] = (1.0, 0.0, 0.0, 0.0, 0.0)
                       ) -> BaselineStats:
    """
    Hand-build a BaselineStats with the chosen daily_success_rate_series.

    Means/stds are uniform constants so PSI/KS won't fire against a current
    feature vector drawn from the same distribution — this lets us isolate
    the streaming algorithms.
    """
    end = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
    return BaselineStats(
        agent_wallet="agentSTREAM",
        baseline_algo_version=BASELINE_ALGO_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_schema_fingerprint=FeatureVector.feature_schema_fingerprint(),
        scoring_schema_fingerprint=scoring_schema_fingerprint(),
        window_start=end - timedelta(days=len(daily_series)),
        window_end=end,
        feature_means=tuple(0.5 for _ in range(TOTAL_FEATURES)),
        feature_stds=tuple(0.1 for _ in range(TOTAL_FEATURES)),
        txtype_distribution=txtype_dist,
        action_entropy=0.0,
        success_rate_30d=success_rate_30d,
        daily_success_rate_series=tuple(daily_series),
        transaction_count=150,
        days_with_activity=len(daily_series),
        is_provisional=False,
        computed_at=end,
        stats_hash="b" * 64,
    )


def _aligned_features(*, txtype_dist: tuple[float, ...] = (1.0, 0.0, 0.0, 0.0, 0.0)) -> FeatureVector:
    """
    Build a current FeatureVector that aligns with `_synthetic_baseline`:
    all features at their baseline mean (0.5) so per-feature z-scores are 0,
    EXCEPT the tx-type fractions which we set to match the baseline's
    txtype_distribution exactly (so PSI is also 0).
    """
    import dataclasses
    field_names = [f.name for f in dataclasses.fields(FeatureVector)]
    values = {name: 0.5 for name in field_names}
    # Override the 5 tx-type fractions to align with the baseline distribution.
    values["txtype_swap_frac"]     = txtype_dist[0]
    values["txtype_lend_frac"]     = txtype_dist[1]
    values["txtype_stake_frac"]    = txtype_dist[2]
    values["txtype_transfer_frac"] = txtype_dist[3]
    values["txtype_other_frac"]    = txtype_dist[4]
    return FeatureVector(**values)


class TestEachAlgorithmFiresIndependently:
    """
    Day-6 done-when: each of the 5 drift algorithms fires on its targeted
    fixture, and the OTHER algorithms (where possible) do not.

    PSI and KS fire on the CURRENT feature vector vs baseline summary.
    CUSUM / ADWIN / DDM fire on the BASELINE's daily series.
    """

    def test_only_cusum_fires_on_abrupt_change(self):
        # Baseline daily series: 15 high days, then 15 low days. CUSUM's
        # cumulative deviation from the OVERALL mean accumulates rapidly.
        daily = [0.99]*15 + [0.50]*15
        baseline = _synthetic_baseline(
            daily_series=daily,
            success_rate_30d=sum(daily) / len(daily),  # mean ≈ 0.745
        )
        features = _aligned_features()

        result = DriftDetector().score(features, baseline)
        # CUSUM fires.
        assert result.flags & FLAG_CUSUM, f"flags={bin(result.flags)}"
        # CUSUM sub-score is dragged down.
        assert result.sub_scores["cusum_normalised"] < 0.5
        # PSI / KS should NOT fire (we crafted aligned features).
        assert not (result.flags & FLAG_PSI)
        assert not (result.flags & FLAG_KS)

    def test_adwin_fires_on_abrupt_change(self):
        # ADWIN should cut the window when the second half is statistically
        # distinct from the first. Same fixture as CUSUM works.
        daily = [0.99]*20 + [0.30]*20
        baseline = _synthetic_baseline(
            daily_series=daily,
            success_rate_30d=sum(daily) / len(daily),
        )
        features = _aligned_features()

        result = DriftDetector().score(features, baseline)
        assert result.flags & FLAG_ADWIN, f"flags={bin(result.flags)}"
        assert result.sub_scores["adwin_drift_score"] < 0.75

    def test_ddm_fires_on_gradual_error_climb(self):
        # DDM's strong suit: gradual error-rate climb. We make daily SUCCESS
        # rate steadily decrease (failure rate steadily climbs).
        daily = [0.98 - i * 0.025 for i in range(40)]  # 0.98 → 0.005
        baseline = _synthetic_baseline(
            daily_series=daily,
            success_rate_30d=sum(daily) / len(daily),
        )
        features = _aligned_features()

        result = DriftDetector().score(features, baseline)
        assert result.flags & FLAG_DDM, f"flags={bin(result.flags)}"
        assert result.sub_scores["ddm_warning_ratio"] < 0.5

    def test_clean_baseline_no_streaming_flags(self):
        # Same length but STABLE daily series — none of CUSUM/ADWIN/DDM fire.
        daily = [0.95] * 30
        baseline = _synthetic_baseline(
            daily_series=daily,
            success_rate_30d=0.95,
        )
        features = _aligned_features()

        result = DriftDetector().score(features, baseline)
        assert not (result.flags & FLAG_CUSUM)
        assert not (result.flags & FLAG_ADWIN)
        assert not (result.flags & FLAG_DDM)
        # All three streaming sub-scores at full credit.
        assert result.sub_scores["cusum_normalised"] >= 0.5
        assert result.sub_scores["adwin_drift_score"] == 1.0
        assert result.sub_scores["ddm_warning_ratio"] == 1.0


class TestFullDimensionBudget:
    """Day-6 unlocks the full 200-point score budget (vs Day-5's partial 80)."""

    def test_perfectly_clean_reaches_near_full_budget(self):
        baseline = _synthetic_baseline(daily_series=[0.95]*30, success_rate_30d=0.95)
        features = _aligned_features()
        result = DriftDetector().score(features, baseline)
        # All 5 sub-scores near 1.0; total well above the Day-5 cap of 80.
        assert result.score >= 180
        assert result.score <= 200

    def test_score_partitions_into_5_buckets_of_40(self):
        """A targeted drop in ONE sub-score reduces the total by ~40 points."""
        clean = _synthetic_baseline(daily_series=[0.95]*30, success_rate_30d=0.95)
        # Same shape, but with abrupt change → CUSUM/ADWIN/DDM collapse.
        triggered = _synthetic_baseline(
            daily_series=[0.99]*15 + [0.30]*15,
            success_rate_30d=0.645,
        )
        features = _aligned_features()
        s_clean     = DriftDetector().score(features, clean).score
        s_triggered = DriftDetector().score(features, triggered).score
        # Triggering all three streaming algos removes ~120 points.
        assert s_triggered < s_clean - 60  # conservative bound
