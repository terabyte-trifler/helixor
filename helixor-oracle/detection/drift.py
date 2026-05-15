"""
detection/drift.py — Dimension 1: statistical drift from baseline.

STATUS: Day 5 — PSI + KS landed. CUSUM/ADWIN/DDM follow on Day 6.

ALGORITHMS WIRED TODAY (Day 5)
------------------------------
PSI (Population Stability Index):
    Compares the agent's CURRENT tx-type distribution (5 categories: swap,
    lend, stake, transfer, other) against the baseline's tx-type distribution.
    ε-smoothed, formula `Σ (cur - base) * ln(cur/base)`. Industry bands:
      PSI < 0.10  stable
      0.10–0.25   moderate shift
      > 0.25      major shift  → FLAG_PSI fires

KS test (one-sample, against N(0, 1)):
    Each of the 100 features is z-scored against the baseline:
        z_i = (current_i - baseline_mean_i) / max(baseline_std_i, ε)
    If the agent is behaving in line with its 30-day baseline, the 100
    z-scores look like draws from N(0, 1). KS rejects H0 when they don't.
    Bonferroni-corrected at α = 0.05 / 100 = 5e-4 (per-feature). The
    DIMENSION-level KS rejection rate is the fraction of features whose
    individual z-score has |z| > 3 (a robust per-feature outlier signal
    complementing the global KS test).

SCORE LAYOUT (today: partial implementation)
--------------------------------------------
Drift dimension MAX_SCORE = 200. PSI + KS together carry up to 80 of those:
   - PSI sub-score    0..40
   - KS sub-score     0..40
   - CUSUM            (Day 6)   reserves 40
   - ADWIN            (Day 6)   reserves 40
   - DDM              (Day 6)   reserves 40
                                 ─────
                                  200

When the dimension is partial (PROVISIONAL bit set today), the composite
scorer still produces a meaningful drift contribution from PSI+KS; Day 6
fills in the remaining 120.

FLAGS SET BY THIS DETECTOR
--------------------------
    FLAG_PSI            PSI > 0.25 (major shift)
    FLAG_KS             KS test rejected H0 at corrected α
    FlagBit.PROVISIONAL   always set today (algorithms partial)
    FlagBit.DEGRADED_BASELINE  if baseline.is_provisional
"""

from __future__ import annotations

from collections.abc import Mapping

from baseline import BaselineStats
from detection._drift_math import (
    bonferroni_alpha,
    ks_one_sample_normal,
    population_stability_index,
    psi_normalised_score,
)
from detection.base import (
    Detector,
    DetectorContractError,
    assert_baseline_compatible,
)
from detection.types import DimensionId, DimensionResult, FlagBit
from features import FeatureVector


# Dimension-specific flag bits. Order matches the Day-4 stub — do not renumber.
FLAG_PSI    = 1 << 8
FLAG_KS     = 1 << 9
FLAG_CUSUM  = 1 << 10    # Day 6
FLAG_ADWIN  = 1 << 11    # Day 6
FLAG_DDM    = 1 << 12    # Day 6


SUB_SCORE_KEYS: tuple[str, ...] = (
    "psi_normalised",        # in [0, 1]; 1.0 = no shift
    "ks_rejection_rate",     # in [0, 1]; fraction of per-feature outliers
    "ks_statistic",          # in [0, 1]; one-sample KS D statistic
    "ks_p_value",            # in [0, 1]; Bonferroni-tested p-value
    "cusum_normalised",      # Day 6
    "adwin_drift_score",     # Day 6
    "ddm_warning_ratio",     # Day 6
)


# ── Tunables ─────────────────────────────────────────────────────────────────
PSI_MAX_POINTS = 40
KS_MAX_POINTS  = 40

# Per-feature outlier threshold. A feature with |z| > KS_FEATURE_Z_FLOOR is
# counted as a per-feature rejection.
KS_FEATURE_Z_FLOOR = 3.0
KS_ALPHA           = 0.05
KS_N_TESTS         = 100
KS_CORRECTED_ALPHA = bonferroni_alpha(KS_ALPHA, KS_N_TESTS)

STD_EPSILON = 1e-6


# =============================================================================
# DriftDetector — real implementation
# =============================================================================

class DriftDetector:
    """
    Day 5: PSI + KS. CUSUM/ADWIN/DDM still stubbed; PROVISIONAL flag stays
    set until Day 6 lands.

    Pure, deterministic. Stdlib-only math means three Phase-4 oracle nodes
    given the same (features, baseline) produce byte-identical DimensionResults.
    """

    @property
    def dimension(self) -> DimensionId:
        return DimensionId.DRIFT

    @property
    def algo_version(self) -> int:
        # Day-4 stub was algo v1. Real PSI+KS is v2.
        return 2

    def score(
        self,
        features: FeatureVector,
        baseline: BaselineStats,
    ) -> DimensionResult:
        # 1. Refuse if the baseline isn't comparable.
        assert_baseline_compatible(baseline)

        flags = int(FlagBit.PROVISIONAL)
        if baseline.is_provisional:
            flags |= int(FlagBit.DEGRADED_BASELINE)

        # 2. PSI on the 5-category tx-type distribution.
        current_txtype  = _current_txtype_distribution(features)
        baseline_txtype = tuple(baseline.txtype_distribution)
        psi = population_stability_index(current_txtype, baseline_txtype)
        psi_sub = psi_normalised_score(psi)
        if psi > 0.25:
            flags |= FLAG_PSI

        # 3. KS test on per-feature z-scores.
        #
        #    The KS p-value is the canonical flag path: reject H0 when
        #    p <= bonferroni_alpha(0.05, 100) = 5e-4. The per-feature
        #    |z| > 3 rejection rate is retained as a diagnostic sub-score
        #    because it is easier to explain to operators.
        #
        #    Zero-variance baseline features are excluded from the sample
        #    (they carry no drift signal).
        z_scores, n_active = _feature_z_scores(features, baseline)
        if n_active >= 5:
            feature_rejections = sum(1 for z in z_scores if abs(z) > KS_FEATURE_Z_FLOOR)
            ks_rejection_rate = feature_rejections / n_active
            ks_statistic, ks_p_value = ks_one_sample_normal(z_scores)
        else:
            # Too few features have baseline variance to evaluate drift meaningfully.
            ks_rejection_rate = 0.0
            ks_statistic = 0.0
            ks_p_value = 1.0
            flags |= int(FlagBit.DEGRADED_BASELINE)
        if ks_p_value <= KS_CORRECTED_ALPHA:
            flags |= FLAG_KS

        # 4. Combine into a partial 0..200 score.
        # psi_sub is "good": 1.0 = stable, 0.0 = shifted.
        # ks_rejection_rate is "bad": invert to "good".
        ks_sub_good = max(0.0, 1.0 - ks_rejection_rate)
        score_partial = int(round(
            psi_sub * PSI_MAX_POINTS + ks_sub_good * KS_MAX_POINTS
        ))
        score_partial = max(0, min(score_partial, 200))

        sub_scores: Mapping[str, float] = {
            "psi_normalised":    psi_sub,
            "ks_rejection_rate": ks_rejection_rate,
            "ks_statistic":      ks_statistic,
            "ks_p_value":        ks_p_value,
            "cusum_normalised":  0.0,
            "adwin_drift_score": 0.0,
            "ddm_warning_ratio": 0.0,
        }

        return DimensionResult(
            dimension=DimensionId.DRIFT,
            score=score_partial,
            max_score=200,
            flags=flags,
            sub_scores=sub_scores,
            algo_version=self.algo_version,
        )


# =============================================================================
# Helpers
# =============================================================================

def _current_txtype_distribution(features: FeatureVector) -> tuple[float, ...]:
    """5-category tx-type distribution from the current FeatureVector,
    in canonical ActionType order: swap, lend, stake, transfer, other."""
    return (
        features.txtype_swap_frac,
        features.txtype_lend_frac,
        features.txtype_stake_frac,
        features.txtype_transfer_frac,
        features.txtype_other_frac,
    )


def _feature_z_scores(
    features: FeatureVector,
    baseline: BaselineStats,
) -> tuple[list[float], int]:
    """
    z = (current - baseline_mean) / baseline_std, per feature.
    Returns (z_scores_for_active_features, n_active_features).

    A feature with baseline σ ≈ 0 has no variance in the historical
    distribution — it cannot meaningfully drift, so it is EXCLUDED from
    the KS sample. Including it would feed a permanent 0 to the empirical
    CDF and bias the global KS test toward rejection on clean data.
    The per-feature outlier rate (|z|>3 fraction) is computed against the
    active count, not the full 100.
    """
    current = features.to_list()
    means   = baseline.feature_means
    stds    = baseline.feature_stds
    if len(current) != len(means) or len(current) != len(stds):
        raise DetectorContractError(
            f"feature/baseline length mismatch: features={len(current)} "
            f"means={len(means)} stds={len(stds)}"
        )

    zs: list[float] = []
    for x, mu, sigma in zip(current, means, stds, strict=True):
        if sigma > STD_EPSILON:
            zs.append((x - mu) / sigma)
    return zs, len(zs)


# Static check: the real detector still conforms to the Protocol.
_: Detector = DriftDetector()
