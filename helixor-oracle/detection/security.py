"""
detection/security.py — Dimension 5: the security layer.

STATUS: Day 10 — COMPLETE. Day 9 built the attack-pattern library + scan();
Day 10 wires it into the 0-150 DimensionResult and adds the integrity,
directed-behaviour, and Sybil-cluster signals.

FOUR SECURITY COMPONENTS
------------------------
1. Attack-pattern scan (Day 9) — the 31-pattern library run over the
   agent's transactions + declared metadata. Produces SecuritySignals;
   the worst severity drives this component's score.

2. Integrity check — declared `code_hash` vs the hash recorded at baseline
   time, plus a hidden-swap check (fixed hash + sharply diverged behaviour).

3. Directed behavioural anomaly — security-specific, distinct from dim2.
   Dim2 asks "is this statistically unusual?"; this asks "is the deviation
   pointed in a known-malicious DIRECTION?" — a conjunction of value
   outflow with new-code / churn / authority activity.

4. Sybil-cluster signal — graph analysis over the cohort: shared funding
   sources and counterparties. Inherently multi-agent; supplied via the
   SecurityContext's SybilGraph.

SCORE LAYOUT — 150-point dimension
----------------------------------
   Attack patterns   0..60
   Integrity         0..40
   Directed anomaly  0..25
   Sybil cluster     0..25
                     -----
                      150

IMMEDIATE_RED FAST-PATH
-----------------------
Security is one of the two dimensions allowed to short-circuit the
composite straight to RED. It sets FlagBit.IMMEDIATE_RED on:
  * any CRITICAL attack-pattern signal,
  * a code_hash integrity violation,
  * confirmed membership in a Sybil cluster.
"""

from __future__ import annotations

from collections.abc import Mapping

from baseline import BaselineStats
from detection._security_integrity import check_integrity, directed_threat_score
from detection.base import Detector, assert_baseline_compatible
from detection.security_context import EMPTY_SECURITY_CONTEXT, SecurityContext
from detection.security_scan import scan
from detection.security_types import SecuritySignal, Severity
from detection.types import DimensionId, DimensionResult, FlagBit
from features import FeatureVector


# ── Dimension-specific flag bits — Security owns bits 24-29 ──────────────────
# (Drift: 8-12, Anomaly: 16-21 — see detection/types.py.)
FLAG_ATTACK_PATTERN = 1 << 24    # at least one attack-pattern signal fired
FLAG_INTEGRITY      = 1 << 25    # integrity check failed
FLAG_DIRECTED_ANOM  = 1 << 26    # directed behavioural-threat shape detected
FLAG_SYBIL          = 1 << 27    # agent is in a Sybil cluster
FLAG_CRITICAL_HIT   = 1 << 28    # a CRITICAL-severity attack signal fired


SUB_SCORE_KEYS: tuple[str, ...] = (
    "attack_pattern_score",    # [0,1]; 1.0 = no attack signals
    "integrity_score",         # [0,1]; 1.0 = integrity intact
    "directed_anomaly_score",  # [0,1]; 1.0 = no directed threat shape
    "sybil_cluster_score",     # [0,1]; 1.0 = not in a Sybil cluster
)


# ── Point budget — 60 + 40 + 25 + 25 = 150 ───────────────────────────────────
ATTACK_MAX_POINTS    = 60
INTEGRITY_MAX_POINTS = 40
DIRECTED_MAX_POINTS  = 25
SYBIL_MAX_POINTS     = 25

# A component health below this sets its FLAG_*.
COMPONENT_FLAG_FLOOR = 0.5

# Feature indices we need for the directed-behaviour check. Resolved once
# from the canonical field order.
import dataclasses as _dc
_FIELD_NAMES = [f.name for f in _dc.fields(FeatureVector)]
_IDX = {name: i for i, name in enumerate(_FIELD_NAMES)}


# =============================================================================
# Attack-pattern scoring — worst severity drives the component
# =============================================================================

def _attack_pattern_health(signals: list[SecuritySignal]) -> tuple[float, bool]:
    """
    Map a list of attack-pattern signals to a [0, 1] health score and a
    'has a CRITICAL hit' flag.

    The score is driven by the WORST signal (severity × confidence), not a
    sum — one CRITICAL exfiltration finding should dominate a dozen LOW
    informational ones. Health falls as the worst weighted-severity rises.
    """
    if not signals:
        return 1.0, False
    worst = max(s.weighted_severity for s in signals)   # in [0, 5]
    has_critical = any(s.severity is Severity.CRITICAL for s in signals)
    # weighted_severity 5 (a confident CRITICAL) → health 0.0;
    # weighted_severity 1 (a weak LOW)           → health 0.8.
    health = max(0.0, 1.0 - worst / 5.0)
    return health, has_critical


# =============================================================================
# SecurityDetector — Day 10
# =============================================================================

class SecurityDetector:
    """
    Dimension 5. A STATEFUL detector: constructed with a SecurityContext
    (cohort Sybil graph + registration hashes + tx window), then scores
    agents against it.

    `default_registry()` builds one with EMPTY_SECURITY_CONTEXT — the
    single-agent checks still run; the Sybil signal is simply absent.

    Pure + deterministic given (features, baseline, context).
    """

    def __init__(self, context: SecurityContext = EMPTY_SECURITY_CONTEXT) -> None:
        self._ctx = context

    @property
    def dimension(self) -> DimensionId:
        return DimensionId.SECURITY

    @property
    def algo_version(self) -> int:
        # Day-4 stub = 1. Day 9-10 full security layer = 2.
        return 2

    @property
    def context(self) -> SecurityContext:
        return self._ctx

    def score(
        self,
        features: FeatureVector,
        baseline: BaselineStats,
    ) -> DimensionResult:
        assert_baseline_compatible(baseline)
        ctx = self._ctx

        flags = 0
        if baseline.is_provisional:
            flags |= int(FlagBit.DEGRADED_BASELINE)

        # ── 1. Attack-pattern scan (Day-9 library) ──────────────────────────
        signals = scan(
            ctx.transactions,
            ctx.scan_metadata,
            denylisted_programs=ctx.denylisted_programs,
        )
        attack_health, has_critical = _attack_pattern_health(signals)
        if attack_health < COMPONENT_FLAG_FLOOR:
            flags |= FLAG_ATTACK_PATTERN
        if has_critical:
            flags |= FLAG_CRITICAL_HIT
            flags |= int(FlagBit.IMMEDIATE_RED)

        # ── 2. Integrity check ──────────────────────────────────────────────
        integrity = check_integrity(
            declared_code_hash=ctx.declared_code_hash,
            baseline_recorded_hash=ctx.baseline_recorded_hash,
            current_values=features.to_list(),
            baseline_means=baseline.feature_means,
            baseline_stds=baseline.feature_stds,
        )
        integrity_health = integrity.health
        if integrity.violated:
            flags |= FLAG_INTEGRITY
            if integrity.hash_mismatch:
                # An explicit code_hash mismatch is unambiguous → fast-path.
                flags |= int(FlagBit.IMMEDIATE_RED)

        # ── 3. Directed behavioural anomaly (security-specific) ─────────────
        directed = directed_threat_score(
            new_program_rate     = features.to_list()[_IDX["prog_new_rate_7d"]],
            counterparty_churn   = features.to_list()[_IDX["cp_new_rate_7d"]],
            net_outflow_fraction = _net_outflow_fraction(features),
            authority_op_fraction= _authority_op_fraction(ctx),
        )
        directed_health = 1.0 - directed
        if directed_health < COMPONENT_FLAG_FLOOR:
            flags |= FLAG_DIRECTED_ANOM

        # ── 4. Sybil-cluster signal ─────────────────────────────────────────
        sybil = ctx.sybil_graph.assess(baseline.agent_wallet)
        sybil_health = 1.0 - sybil.sybil_signal
        if sybil.in_cluster:
            flags |= FLAG_SYBIL
            # A confirmed Sybil cluster is a fast-path finding.
            flags |= int(FlagBit.IMMEDIATE_RED)

        # ── 5. Aggregate into the 0..150 score ──────────────────────────────
        score_total = int(round(
            attack_health    * ATTACK_MAX_POINTS    +
            integrity_health * INTEGRITY_MAX_POINTS +
            directed_health  * DIRECTED_MAX_POINTS  +
            sybil_health     * SYBIL_MAX_POINTS
        ))
        score_total = max(0, min(score_total, 150))

        sub_scores: Mapping[str, float] = {
            "attack_pattern_score":   attack_health,
            "integrity_score":        integrity_health,
            "directed_anomaly_score": directed_health,
            "sybil_cluster_score":    sybil_health,
        }

        return DimensionResult(
            dimension=DimensionId.SECURITY,
            score=score_total,
            max_score=150,
            flags=flags,
            sub_scores=sub_scores,
            algo_version=self.algo_version,
        )


# =============================================================================
# Helpers
# =============================================================================

def _net_outflow_fraction(features: FeatureVector) -> float:
    """
    Fraction of value movement that is OUTFLOW, in [0, 1].

    Uses the solflow features: out / (in + out). 0.5 = balanced; → 1.0 as
    the agent becomes a pure value sink (the drain shape).
    """
    vals = features.to_list()
    total_in  = vals[_IDX["solflow_total_in"]]
    total_out = vals[_IDX["solflow_total_out"]]
    denom = total_in + total_out
    if denom <= 1e-12:
        return 0.0
    return max(0.0, min(1.0, total_out / denom))


def _authority_op_fraction(ctx: SecurityContext) -> float:
    """
    Fraction of context transactions that performed authority-sensitive ops.

    This signal lives in SecurityContext.transaction metadata rather than the
    frozen 100-feature vector. That keeps existing baselines compatible while
    making the Day-10 directed-threat hook active as soon as the parser/indexer
    can mark privileged operations.
    """
    if not ctx.transactions:
        return 0.0
    authority_ops = sum(1 for tx in ctx.transactions if tx.authority_operation)
    return authority_ops / len(ctx.transactions)


# Static check: the real detector conforms to the Detector Protocol.
_: Detector = SecurityDetector()
