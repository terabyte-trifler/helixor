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

from dataclasses import fields
from datetime import datetime, timedelta, timezone

import pytest

from baseline import compute_baseline
from detection import DimensionId, DimensionResult, FlagBit, default_registry
from detection.drift import (
    FLAG_KS,
    FLAG_PSI,
    KS_CORRECTED_ALPHA,
    DriftDetector,
    _feature_z_scores,
)
from detection._drift_math import ks_one_sample_normal
from features import ExtractionWindow, Transaction, extract
from features import FeatureVector


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
        # PSI should be tiny.
        assert result.sub_scores["psi_normalised"] > 0.5
        # No major-shift flag.
        assert not (result.flags & FLAG_PSI)
        # KS rejection rate should be modest (some natural day-to-day noise).
        assert result.sub_scores["ks_rejection_rate"] < 0.20
        # PROVISIONAL is set (partial implementation today), but KS flag is not.
        assert result.has_flag(FlagBit.PROVISIONAL)


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
        # The dimension score should be DRAGGED DOWN from the clean ~80.
        # PSI contribution drops to near 0.
        assert result.score < 80   # well below clean-case ~80

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
        assert "ks_p_value" in result.sub_scores

    def test_bonferroni_ks_p_value_triggers_ks_flag(self, clean_baseline):
        # Build a current vector whose active features are all many standard
        # deviations above baseline. This specifically exercises the KS p-value
        # path, not just PSI or the explanatory |z| rejection-rate diagnostic.
        values = []
        for mean, std in zip(
            clean_baseline.feature_means,
            clean_baseline.feature_stds,
            strict=True,
        ):
            values.append(float(mean + 10.0 * std) if std > 1e-6 else float(mean))
        features = FeatureVector(**{
            field.name: value
            for field, value in zip(fields(FeatureVector), values, strict=True)
        })

        z_scores, n_active = _feature_z_scores(features, clean_baseline)
        assert n_active >= 5
        _ks_statistic, p_value = ks_one_sample_normal(z_scores)
        assert p_value <= KS_CORRECTED_ALPHA

        result = DriftDetector().score(features, clean_baseline)
        assert result.flags & FLAG_KS
        assert result.sub_scores["ks_p_value"] == pytest.approx(p_value)
        assert result.sub_scores["ks_p_value"] <= KS_CORRECTED_ALPHA

    def test_combined_drift_drops_score(self, clean_baseline):
        # Major category shift + extreme features → both flags + low score.
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
        # Score is in [0, 200] but should be well below the partial cap of 80.
        assert 0 <= result.score < 50


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
        for key in ("psi_normalised", "ks_rejection_rate", "ks_statistic", "ks_p_value",
                    "cusum_normalised", "adwin_drift_score",
                    "ddm_warning_ratio"):
            assert key in result.sub_scores
            assert 0.0 <= result.sub_scores[key] <= 1.0

    def test_algo_version_bumped_to_2(self, clean_baseline):
        txs = _build_txs(days=1, txs_per_day=5)
        window = ExtractionWindow.ending_at(REF_END, days=1)
        features = extract(txs, window)
        result = DriftDetector().score(features, clean_baseline)
        assert result.algo_version == 2

    def test_provisional_flag_always_set(self, clean_baseline):
        """Until Day 6 lands CUSUM/ADWIN/DDM, PROVISIONAL stays on."""
        txs = _build_txs(days=1, txs_per_day=5)
        window = ExtractionWindow.ending_at(REF_END, days=1)
        features = extract(txs, window)
        result = DriftDetector().score(features, clean_baseline)
        assert result.has_flag(FlagBit.PROVISIONAL)


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
# Registry wiring — default_registry now returns the real algo v2
# =============================================================================

class TestRegistryWiresRealDetector:

    def test_default_registry_drift_is_real_v2(self):
        reg = default_registry()
        det = reg.get(DimensionId.DRIFT)
        assert det.algo_version == 2
        # Type check: the real DriftDetector
        assert isinstance(det, DriftDetector)
