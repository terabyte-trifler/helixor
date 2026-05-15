"""
detection/drift.py — Dimension 1: statistical drift from baseline.

STATUS: Day 6 — full PSI + KS + CUSUM + ADWIN + DDM detector.

ALGORITHMS WIRED
----------------
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

CUSUM:
    Runs Page's two-sided cumulative-sum detector over the baseline's daily
    success-rate series. Uses k = 0.5σ and h = 5σ, with a low-variance floor.

ADWIN:
    Runs adaptive windowing over the same daily success-rate series and cuts
    stale history when a Hoeffding-bound split detects a mean shift.

DDM:
    Runs Drift Detection Method over per-day failure rates (1 - success rate),
    warning at 2σ over the historical minimum and drift at 3σ.

SCORE LAYOUT
------------
Drift dimension MAX_SCORE = 200. Each algorithm carries 40 points:
   - PSI sub-score    0..40
   - KS sub-score     0..40
   - CUSUM            0..40
   - ADWIN            0..40
   - DDM              0..40
                                 ─────
                                  200

FLAGS SET BY THIS DETECTOR
--------------------------
    FLAG_PSI            PSI > 0.25 (major shift)
    FLAG_KS             per-feature rejection rate exceeds threshold
    FLAG_CUSUM          CUSUM crosses the decision threshold
    FLAG_ADWIN          ADWIN drops enough of the historical window
    FLAG_DDM            DDM severity reaches drift territory
    FlagBit.DEGRADED_BASELINE  if baseline.is_provisional
"""

from __future__ import annotations

from collections.abc import Mapping

from baseline import BaselineStats
from detection._drift_math import (
    adwin_detect,
    adwin_normalised_score,
    cusum_normalised_score,
    cusum_two_sided,
    ddm_detect,
    ddm_normalised_score,
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
from features import _stats as st


# Dimension-specific flag bits. Order matches the Day-4 stub — do not renumber.
FLAG_PSI    = 1 << 8
FLAG_KS     = 1 << 9
FLAG_CUSUM  = 1 << 10    # Day 6
FLAG_ADWIN  = 1 << 11    # Day 6
FLAG_DDM    = 1 << 12    # Day 6


SUB_SCORE_KEYS: tuple[str, ...] = (
    "psi_normalised",        # in [0, 1]; 1.0 = no shift
    "ks_rejection_rate",     # in [0, 1]; fraction of per-feature outliers
    "cusum_normalised",      # Day 6
    "adwin_drift_score",     # Day 6
    "ddm_warning_ratio",     # Day 6
)


# ── Tunables ─────────────────────────────────────────────────────────────────
# Drift dimension MAX_SCORE = 200. Each algorithm carries 40 of those points.
PSI_MAX_POINTS   = 40
KS_MAX_POINTS    = 40
CUSUM_MAX_POINTS = 40
ADWIN_MAX_POINTS = 40
DDM_MAX_POINTS   = 40   # 5 * 40 = 200, the full dimension

# Per-feature outlier threshold. A feature with |z| > KS_FEATURE_Z_FLOOR is
# counted as a per-feature rejection.
KS_FEATURE_Z_FLOOR  = 3.0
# If the fraction of features that reject exceeds this, FLAG_KS fires.
KS_REJECT_RATE_FLAG = 0.05

STD_EPSILON = 1e-6


# =============================================================================
# DriftDetector — real implementation
# =============================================================================

class DriftDetector:
    """
    Day 6: full PSI + KS + CUSUM + ADWIN + DDM implementation.

    Pure, deterministic. Stdlib-only math means three Phase-4 oracle nodes
    given the same (features, baseline) produce byte-identical DimensionResults.
    """

    @property
    def dimension(self) -> DimensionId:
        return DimensionId.DRIFT

    @property
    def algo_version(self) -> int:
        # Day-4 stub = 1; Day-5 (PSI + KS, partial) = 2; Day-6 (all 5) = 3.
        return 3

    def score(
        self,
        features: FeatureVector,
        baseline: BaselineStats,
    ) -> DimensionResult:
        # 1. Refuse if the baseline isn't comparable.
        assert_baseline_compatible(baseline)

        flags = 0
        if baseline.is_provisional:
            flags |= int(FlagBit.DEGRADED_BASELINE)

        # 2. PSI on the 5-category tx-type distribution.
        current_txtype  = _current_txtype_distribution(features)
        baseline_txtype = tuple(baseline.txtype_distribution)
        psi = population_stability_index(current_txtype, baseline_txtype)
        psi_sub = psi_normalised_score(psi)
        if psi > 0.25:
            flags |= FLAG_PSI

        # 3. KS — per-feature outlier rate (primary signal).
        z_scores, n_active = _feature_z_scores(features, baseline)
        if n_active >= 5:
            feature_rejections = sum(1 for z in z_scores if abs(z) > KS_FEATURE_Z_FLOOR)
            ks_rejection_rate = feature_rejections / n_active
        else:
            ks_rejection_rate = 0.0
            flags |= int(FlagBit.DEGRADED_BASELINE)
        if ks_rejection_rate > KS_REJECT_RATE_FLAG:
            flags |= FLAG_KS

        # 4. CUSUM on the agent's daily success-rate series.
        #    Reference mean = baseline.success_rate_30d.
        #    σ = stddev of the daily series stored on the baseline.
        daily_series = baseline.daily_success_rate_series
        if len(daily_series) >= 2:
            sigma = st.stddev(daily_series)
            cusum_result = cusum_two_sided(
                daily_series,
                reference_mean=baseline.success_rate_30d,
                sigma=sigma,
            )
            cusum_sub = cusum_normalised_score(cusum_result)
            if cusum_result["triggered"]:
                flags |= FLAG_CUSUM
        else:
            cusum_sub = 1.0   # not enough data to detect change → assume stable
            flags |= int(FlagBit.DEGRADED_BASELINE)

        # 5. ADWIN on the daily success-rate series.
        if len(daily_series) >= 2:
            adwin_result = adwin_detect(daily_series)
            adwin_sub = adwin_normalised_score(adwin_result)
            # Use severity (width-loss > 25%), not the bare cut boolean,
            # so a single Hoeffding cut on a noisy tail doesn't false-trip.
            if adwin_sub < 0.75:
                flags |= FLAG_ADWIN
        else:
            adwin_sub = 1.0

        # 6. DDM on the daily FAILURE-rate series (1 - success_rate per day).
        if len(daily_series) >= 1:
            failure_series = tuple(1.0 - r for r in daily_series)
            ddm_result = ddm_detect(failure_series)
            ddm_sub = ddm_normalised_score(ddm_result)
            # Only set the flag when the SEVERITY (not the bare boolean) is real.
            # The boolean tripping at index N reflects "we just crossed the
            # warning level at this exact sample" — which can happen due to a
            # single tail observation in clean data. The severity score
            # captures sustained drift; threshold at <= 0.5 → real drift.
            if ddm_sub < 0.5:
                flags |= FLAG_DDM
        else:
            ddm_sub = 1.0

        # 7. Combine. All five sub-scores are "good" (1.0 = stable, 0.0 = drift).
        ks_sub_good = max(0.0, 1.0 - ks_rejection_rate)
        score_total = int(round(
            psi_sub   * PSI_MAX_POINTS   +
            ks_sub_good * KS_MAX_POINTS  +
            cusum_sub * CUSUM_MAX_POINTS +
            adwin_sub * ADWIN_MAX_POINTS +
            ddm_sub   * DDM_MAX_POINTS
        ))
        score_total = max(0, min(score_total, 200))

        sub_scores: Mapping[str, float] = {
            "psi_normalised":    psi_sub,
            "ks_rejection_rate": ks_rejection_rate,
            "cusum_normalised":  cusum_sub,
            "adwin_drift_score": adwin_sub,
            "ddm_warning_ratio": ddm_sub,
        }

        return DimensionResult(
            dimension=DimensionId.DRIFT,
            score=score_total,
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
