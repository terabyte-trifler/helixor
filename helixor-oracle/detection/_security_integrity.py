"""
detection/_security_integrity.py — integrity + behavioural-fingerprint checks.

Two security-specific checks that Day-9's pattern scanner does not cover:

INTEGRITY CHECK
---------------
At registration an agent commits a `code_hash` — an opaque identity token
for "the code/model this agent runs". Helixor cannot hash the agent's code
itself (it only sees on-chain transactions), so the integrity check is NOT
`hash(code) == declared`. Instead:

  * The agent's declared `code_hash` is recorded alongside the behavioural
    baseline when the baseline is committed.
  * A mismatch between the CURRENTLY declared `code_hash` and the one
    recorded at baseline time means the agent changed its declared identity
    WITHOUT re-baselining — a silent swap. That is an integrity violation.
  * The subtler attack: the `code_hash` stays fixed but the agent's
    behaviour diverges sharply — a silent code swap hidden behind a stale
    hash. We catch this by computing a BEHAVIOURAL FINGERPRINT from the
    feature vector and measuring its divergence from the baseline
    fingerprint. A fixed hash + diverged behaviour = integrity violation.

BEHAVIOURAL-BASELINE ANOMALY (security-specific)
------------------------------------------------
Dimension 2 already measures statistical deviation ("is this unusual for
this agent?"). This check is different: it asks "is the deviation pointed
in a KNOWN-MALICIOUS DIRECTION?" — privilege-seeking, value-concentration,
counterparty-hijacking. It is directed, not omnidirectional. A burst of
new programs is statistically anomalous (dim2) AND a security concern
(here) only if it co-occurs with value outflow or authority change.

All pure stdlib, deterministic.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Sequence


# =============================================================================
# Behavioural fingerprint
# =============================================================================

def behavioural_fingerprint(feature_values: Sequence[float]) -> str:
    """
    A stable 64-hex-char fingerprint of a feature vector.

    Features are quantised to 3 decimal places before hashing so that
    floating-point noise below the third decimal does not change the
    fingerprint — two byte-identical-behaviour observations fingerprint
    identically across machines (Phase-4 BFT).
    """
    quantised = ";".join(f"{v:.3f}" for v in feature_values)
    return hashlib.sha256(quantised.encode("utf-8")).hexdigest()


def fingerprint_divergence(
    current_values:  Sequence[float],
    baseline_means:  Sequence[float],
    baseline_stds:   Sequence[float],
) -> float:
    """
    A [0, 1] divergence between current behaviour and the baseline.

    This is NOT the omnidirectional z-distance of dim2 — it is a coarse,
    bounded "has the behavioural identity shifted" measure, used only to
    decide whether a fixed code_hash is hiding a behaviour change.

    Computed as the fraction of features that moved more than 3σ from
    baseline. 0.0 = identical behavioural identity; 1.0 = every feature
    has shifted out of its baseline envelope.
    """
    n = len(current_values)
    if n == 0 or n != len(baseline_means) or n != len(baseline_stds):
        return 0.0
    shifted = 0
    for x, mu, sigma in zip(current_values, baseline_means, baseline_stds):
        if sigma <= 1e-9:
            continue                       # zero-variance feature: no signal
        if abs(x - mu) > 3.0 * sigma:
            shifted += 1
    return shifted / n


# =============================================================================
# Integrity check
# =============================================================================

class IntegrityVerdict:
    """Result of the integrity check. Lightweight, not a frozen dataclass —
    constructed once per score() and immediately consumed."""

    __slots__ = ("hash_mismatch", "behaviour_diverged", "divergence", "detail")

    def __init__(
        self,
        *,
        hash_mismatch: bool,
        behaviour_diverged: bool,
        divergence: float,
        detail: str,
    ) -> None:
        self.hash_mismatch = hash_mismatch
        self.behaviour_diverged = behaviour_diverged
        self.divergence = divergence
        self.detail = detail

    @property
    def violated(self) -> bool:
        """True if EITHER an explicit hash mismatch OR a hidden behaviour swap."""
        return self.hash_mismatch or self.behaviour_diverged

    @property
    def health(self) -> float:
        """
        Integrity health in [0, 1], 1.0 = intact.
          hash mismatch         → 0.0   (unambiguous)
          behaviour diverged    → scales with divergence
          neither               → 1.0
        """
        if self.hash_mismatch:
            return 0.0
        if self.behaviour_diverged:
            return max(0.0, 1.0 - self.divergence)
        return 1.0


# Divergence above this, under an UNCHANGED code_hash, is treated as a
# hidden code swap. Set high — a fixed hash should mean fixed behaviour, so
# even a moderate divergence is suspicious, but day-to-day noise must not trip it.
BEHAVIOUR_SWAP_DIVERGENCE = 0.35


def check_integrity(
    *,
    declared_code_hash:        str,
    baseline_recorded_hash:    str,
    current_values:            Sequence[float],
    baseline_means:            Sequence[float],
    baseline_stds:             Sequence[float],
) -> IntegrityVerdict:
    """
    Run the integrity check.

      declared_code_hash      — the code_hash the agent currently declares
      baseline_recorded_hash  — the code_hash recorded when the baseline
                                was committed ("" if none was recorded)

    If no hashes are available at all, the check is a no-op (intact) — an
    agent that never committed a code_hash cannot violate hash integrity;
    the behavioural-swap arm still runs.
    """
    hash_mismatch = False
    detail_parts: list[str] = []

    if declared_code_hash and baseline_recorded_hash:
        if declared_code_hash != baseline_recorded_hash:
            hash_mismatch = True
            detail_parts.append("declared code_hash differs from baseline-recorded hash")

    divergence = fingerprint_divergence(current_values, baseline_means, baseline_stds)

    # Hidden-swap arm: a FIXED (matching, or simply present) hash combined
    # with sharply diverged behaviour.
    hash_is_stable = (
        not hash_mismatch
        and bool(declared_code_hash)
        and declared_code_hash == baseline_recorded_hash
    )
    behaviour_diverged = hash_is_stable and divergence >= BEHAVIOUR_SWAP_DIVERGENCE
    if behaviour_diverged:
        detail_parts.append(
            f"behaviour diverged {divergence:.0%} under an unchanged code_hash"
        )

    return IntegrityVerdict(
        hash_mismatch=hash_mismatch,
        behaviour_diverged=behaviour_diverged,
        divergence=divergence,
        detail="; ".join(detail_parts) or "integrity intact",
    )


# =============================================================================
# Behavioural-baseline anomaly (security-specific, directed)
# =============================================================================

def directed_threat_score(
    *,
    new_program_rate:        float,   # feature: prog_new_rate_7d, in [0,1]-ish
    counterparty_churn:      float,   # feature: counterparty turnover, in [0,1]-ish
    net_outflow_fraction:    float,   # fraction of value flowing OUT, [0,1]
    authority_op_fraction:   float,   # fraction of txs that are authority ops, [0,1]
) -> float:
    """
    A directed "deviation toward a malicious shape" score in [0, 1].

    Unlike dim2's omnidirectional anomaly, this is a CONJUNCTION: each input
    is individually innocuous, but their CO-OCCURRENCE is the threat shape.

      * new programs alone        → benign (capability rollout)
      * value outflow alone       → benign (normal trading)
      * new programs + outflow    → the confused-deputy / drain shape
      * authority ops + outflow   → the privilege-then-drain shape

    Returns 0.0 when the signals do not co-occur; rises as they do.
    """
    # Clamp every input to [0, 1] defensively.
    npr = _clamp01(new_program_rate)
    cc  = _clamp01(counterparty_churn)
    nof = _clamp01(net_outflow_fraction)
    aof = _clamp01(authority_op_fraction)

    # Two threat conjunctions; the score is the stronger of the two.
    drain_shape     = nof * max(npr, cc)          # outflow co-occurring with churn/new code
    privilege_shape = nof * aof                   # outflow co-occurring with authority ops
    return _clamp01(max(drain_shape, privilege_shape))


def _clamp01(x: float) -> float:
    if not math.isfinite(x):
        return 0.0
    return max(0.0, min(1.0, x))
