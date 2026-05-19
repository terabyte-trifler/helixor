"""
detection/consistency.py — Dimension 4: behavioural consistency.

STATUS: Day 12 — COMPLETE. The last Phase-1 dimension.

FOUR COMPONENTS
---------------
1. Tool-stability — how far the agent's current program-invocation mix has
   moved from its baseline program-mix. An agent whose tool usage is stable
   over time is consistent; one that abruptly re-shapes its tool mix is not.

2. Activity-rhythm regularity — how far the agent's current activity-rhythm
   features (time-of-day entropy, inter-tx timing, burst pattern) have
   moved from its own baseline rhythm. Direction-agnostic: a regular agent
   turning erratic AND an erratic agent turning clockwork are both breaks.

3. Counterparty-outcome consistency — a conjunction: outcome volatility
   only counts against consistency to the extent the agent is dealing with
   REPEAT counterparties (it should have a stable track record with them).

4. Domain classifier — does the agent's observed transaction-type mix match
   the expected profile of its DECLARED domain? A "lending agent" suddenly
   doing NFT mints is inconsistent with its declaration. This is the
   done-when's core.

SCORE LAYOUT — 200-point dimension
----------------------------------
   Domain conformance   0..70    the done-when core
   Tool stability       0..50
   Rhythm regularity    0..45
   Counterparty outcome 0..35
                        -----
                         200

A STATEFUL DETECTOR
-------------------
Like Days 10-11, this detector needs context beyond (features, baseline):
the agent's declared domain. Constructed with a `ConsistencyContext`;
`default_registry()` builds it empty (domain classifier abstains).
"""

from __future__ import annotations

import dataclasses as _dc
from collections.abc import Mapping

from baseline import BaselineStats
from detection._consistency_math import (
    counterparty_outcome_consistency,
    divergence_to_health,
    jensen_shannon_divergence,
    rhythm_divergence,
)
from detection.base import Detector, assert_baseline_compatible
from detection.consistency_context import (
    EMPTY_CONSISTENCY_CONTEXT,
    ConsistencyContext,
)
from detection.domain_profiles import domain_profile
from detection.types import DimensionId, DimensionResult, FlagBit
from features import FeatureVector
from features.vector import group_of


# ── Dimension-specific flag bits — Consistency owns bits 22-23, 30-31 ────────
# (Drift: 8-12, Performance: 13-15, Anomaly: 16-21, Security: 24-29.)
FLAG_TOOL_INSTABILITY  = 1 << 22    # program-mix shifted sharply from baseline
FLAG_RHYTHM_BROKEN     = 1 << 23    # activity rhythm broke vs baseline
FLAG_COUNTERPARTY_FLIP = 1 << 30    # repeat-counterparty outcomes turned erratic
FLAG_DOMAIN_DRIFT      = 1 << 31    # observed behaviour outside the declared domain


SUB_SCORE_KEYS: tuple[str, ...] = (
    "tool_stability",            # [0,1]; 1.0 = program-mix unchanged
    "rhythm_regularity",         # [0,1]; 1.0 = rhythm unchanged
    "counterparty_consistency",  # [0,1]; 1.0 = stable repeat-CP outcomes
    "domain_alignment",          # [0,1]; 1.0 = behaviour matches declared domain
)


# ── Point budget — 70 + 50 + 45 + 35 = 200 ───────────────────────────────────
DOMAIN_MAX_POINTS        = 70
TOOL_MAX_POINTS          = 50
RHYTHM_MAX_POINTS        = 45
COUNTERPARTY_MAX_POINTS  = 35

# Saturation magnitudes — the divergence at which a component hits 0 health.
#   Tool-mix JSD is in [0, 1] already; a JSD of 0.6 is a near-total re-shape.
TOOL_JSD_SATURATION   = 0.60
#   Domain JSD likewise; 0.6 = observed mix nothing like the declared domain.
DOMAIN_JSD_SATURATION = 0.60
#   Rhythm divergence is a mean abs-z; ~5σ mean shift is a maximal break.
RHYTHM_SATURATION     = 5.0

# A component health below this sets its FLAG_*.
COMPONENT_FLAG_FLOOR = 0.5

# Feature indices, resolved once from the canonical field order.
_FIELD_NAMES = [f.name for f in _dc.fields(FeatureVector)]
_IDX = {name: i for i, name in enumerate(_FIELD_NAMES)}

# The five txtype features, in the canonical (swap, lend, stake, transfer,
# other) order — must match domain_profiles.TXTYPE_ORDER.
_TXTYPE_FEATURES = (
    "txtype_swap_frac", "txtype_lend_frac", "txtype_stake_frac",
    "txtype_transfer_frac", "txtype_other_frac",
)
# Indices of the `programs` and `rhythm` feature groups.
_PROGRAM_INDICES = tuple(
    i for i, n in enumerate(_FIELD_NAMES) if group_of(n) == "programs"
)
_RHYTHM_INDICES = tuple(
    i for i, n in enumerate(_FIELD_NAMES) if group_of(n) == "rhythm"
)


# =============================================================================
# ConsistencyDetector — Day 12
# =============================================================================

class ConsistencyDetector:
    """
    Dimension 4. A stateful detector: constructed with a
    `ConsistencyContext` carrying the agent's declared domain.

    Pure + deterministic given (features, baseline, context).
    """

    def __init__(
        self,
        context: ConsistencyContext = EMPTY_CONSISTENCY_CONTEXT,
    ) -> None:
        self._ctx = context

    @property
    def dimension(self) -> DimensionId:
        return DimensionId.CONSISTENCY

    @property
    def algo_version(self) -> int:
        # Day-4 stub = 1. Day-12 real implementation = 2.
        return 2

    @property
    def context(self) -> ConsistencyContext:
        return self._ctx

    def score(
        self,
        features: FeatureVector,
        baseline: BaselineStats,
    ) -> DimensionResult:
        assert_baseline_compatible(baseline)

        flags = 0
        if baseline.is_provisional:
            flags |= int(FlagBit.DEGRADED_BASELINE)

        feature_values = features.to_list()

        # ── 1. Tool-stability — current program-mix vs baseline ─────────────
        current_programs  = [feature_values[i] for i in _PROGRAM_INDICES]
        baseline_programs = [baseline.feature_means[i] for i in _PROGRAM_INDICES]
        tool_jsd = jensen_shannon_divergence(current_programs, baseline_programs)
        tool_health = divergence_to_health(tool_jsd, saturation=TOOL_JSD_SATURATION)
        if tool_health < COMPONENT_FLAG_FLOOR:
            flags |= FLAG_TOOL_INSTABILITY

        # ── 2. Rhythm regularity — current rhythm vs baseline rhythm ────────
        current_rhythm  = [feature_values[i] for i in _RHYTHM_INDICES]
        baseline_rmeans = [baseline.feature_means[i] for i in _RHYTHM_INDICES]
        baseline_rstds  = [baseline.feature_stds[i] for i in _RHYTHM_INDICES]
        rhythm_div = rhythm_divergence(current_rhythm, baseline_rmeans, baseline_rstds)
        rhythm_health = divergence_to_health(rhythm_div, saturation=RHYTHM_SATURATION)
        if rhythm_health < COMPONENT_FLAG_FLOOR:
            flags |= FLAG_RHYTHM_BROKEN

        # ── 3. Counterparty-outcome consistency (a conjunction) ─────────────
        cp_health = counterparty_outcome_consistency(
            repeat_ratio=feature_values[_IDX["cp_repeat_ratio"]],
            success_volatility=feature_values[_IDX["success_volatility"]],
        )
        if cp_health < COMPONENT_FLAG_FLOOR:
            flags |= FLAG_COUNTERPARTY_FLIP

        # ── 4. Domain classifier — observed txtype-mix vs declared domain ───
        profile = domain_profile(self._ctx.declared_domain)
        if profile is None:
            # No declared domain (or one Helixor has no profile for):
            # the classifier ABSTAINS — full marks, no penalty.
            domain_health = 1.0
            domain_jsd = 0.0
        else:
            observed_mix = [feature_values[_IDX[f]] for f in _TXTYPE_FEATURES]
            domain_jsd = jensen_shannon_divergence(observed_mix, list(profile))
            domain_health = divergence_to_health(
                domain_jsd, saturation=DOMAIN_JSD_SATURATION,
            )
            if domain_health < COMPONENT_FLAG_FLOOR:
                flags |= FLAG_DOMAIN_DRIFT

        # ── 5. Aggregate into the 0..200 score ──────────────────────────────
        score_total = int(round(
            domain_health * DOMAIN_MAX_POINTS       +
            tool_health   * TOOL_MAX_POINTS         +
            rhythm_health * RHYTHM_MAX_POINTS       +
            cp_health     * COUNTERPARTY_MAX_POINTS
        ))
        score_total = max(0, min(score_total, 200))

        sub_scores: Mapping[str, float] = {
            "tool_stability":           tool_health,
            "rhythm_regularity":        rhythm_health,
            "counterparty_consistency": cp_health,
            "domain_alignment":         domain_health,
        }

        return DimensionResult(
            dimension=DimensionId.CONSISTENCY,
            score=score_total,
            max_score=200,
            flags=flags,
            sub_scores=sub_scores,
            algo_version=self.algo_version,
        )


# Static check: the real detector conforms to the Detector Protocol.
_: Detector = ConsistencyDetector()
