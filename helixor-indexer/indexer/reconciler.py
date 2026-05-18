"""
indexer/reconciler.py — Geyser-vs-webhook stream reconciliation.

The indexer runs two ingestion paths: Geyser (primary) and the Helius
webhook fallback. Both observe the same on-chain truth. The reconciler
compares the two observations and ALERTS on divergence — because divergence
means one path is dropping transactions.

WHAT DIVERGENCE MEANS
---------------------
For a given agent + time window, let G be the set of transaction
signatures Geyser delivered and W the set the webhook path delivered.
On-chain truth T is what actually happened.

  - signatures in W but not G  → Geyser MISSED transactions. The primary
    path is lossy — the most serious alert (Geyser is supposed to be the
    complete one).
  - signatures in G but not W  → the webhook path missed them. Expected to
    some degree (webhooks are lossy by design) — a low-severity alert
    unless the rate is high.
  - G == W                     → the paths agree. No alert.

The reconciler does not assume either path equals T — it can only compare
the two paths to each other. Persistent one-sided divergence is the signal.
"""

from __future__ import annotations

import enum
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field

from indexer.types import IngestionSource

logger = logging.getLogger("helixor.indexer.reconciler")


# =============================================================================
# Alert severity
# =============================================================================

class DivergenceSeverity(enum.IntEnum):
    """How serious a stream divergence is."""
    NONE     = 0     # the streams agree
    LOW      = 1     # webhook missed some — webhooks are lossy by design
    MEDIUM   = 2     # Geyser missed a few — the primary path should not
    HIGH     = 3     # Geyser missed many — the primary path is degraded


# A Geyser miss-rate above this fraction escalates LOW/MEDIUM to HIGH.
GEYSER_MISS_RATE_HIGH = 0.05


# =============================================================================
# ReconciliationResult
# =============================================================================

@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    """The outcome of reconciling one agent's two streams over a window."""
    agent_wallet:        str
    geyser_count:        int
    webhook_count:       int
    agreed_count:        int                       # signatures in both
    geyser_only:         tuple[str, ...]           # Geyser saw, webhook didn't
    webhook_only:        tuple[str, ...]           # webhook saw, Geyser didn't
    severity:            DivergenceSeverity

    @property
    def diverged(self) -> bool:
        return self.severity is not DivergenceSeverity.NONE

    @property
    def geyser_miss_rate(self) -> float:
        """
        Fraction of webhook-observed transactions Geyser missed. The key
        health metric — Geyser is the path that is supposed to be complete.
        """
        total = self.agreed_count + len(self.webhook_only)
        return len(self.webhook_only) / total if total else 0.0


# =============================================================================
# The reconciler
# =============================================================================

def reconcile_agent(
    agent_wallet:       str,
    geyser_signatures:  Iterable[str],
    webhook_signatures: Iterable[str],
) -> ReconciliationResult:
    """
    Reconcile one agent's Geyser and webhook observations.

    Inputs are the transaction-signature sets each path delivered for the
    agent over the same window. Pure + deterministic.
    """
    geyser = set(geyser_signatures)
    webhook = set(webhook_signatures)

    agreed = geyser & webhook
    geyser_only = sorted(geyser - webhook)
    webhook_only = sorted(webhook - geyser)        # Geyser MISSED these

    severity = _classify(
        geyser_only_count=len(geyser_only),
        webhook_only_count=len(webhook_only),
        agreed_count=len(agreed),
    )

    result = ReconciliationResult(
        agent_wallet=agent_wallet,
        geyser_count=len(geyser),
        webhook_count=len(webhook),
        agreed_count=len(agreed),
        geyser_only=tuple(geyser_only),
        webhook_only=tuple(webhook_only),
        severity=severity,
    )

    if result.diverged:
        logger.warning(
            "stream divergence for %s: severity=%s, Geyser missed %d, "
            "webhook missed %d (Geyser miss-rate %.1f%%)",
            agent_wallet, severity.name, len(webhook_only),
            len(geyser_only), result.geyser_miss_rate * 100,
        )

    return result


def _classify(
    *,
    geyser_only_count:  int,
    webhook_only_count: int,
    agreed_count:       int,
) -> DivergenceSeverity:
    """
    Classify divergence severity.

      - Geyser missed transactions (webhook_only > 0) is the serious case:
        MEDIUM, escalating to HIGH if the miss-rate is high.
      - The webhook missing transactions (geyser_only > 0) is expected —
        webhooks are lossy — so it is only LOW.
      - Both clean → NONE.
    """
    if webhook_only_count > 0:
        total = agreed_count + webhook_only_count
        miss_rate = webhook_only_count / total if total else 1.0
        return (DivergenceSeverity.HIGH
                if miss_rate > GEYSER_MISS_RATE_HIGH
                else DivergenceSeverity.MEDIUM)
    if geyser_only_count > 0:
        return DivergenceSeverity.LOW
    return DivergenceSeverity.NONE


# =============================================================================
# Batch reconciliation
# =============================================================================

@dataclass(frozen=True, slots=True)
class ReconciliationReport:
    """Reconciliation across many agents."""
    results: tuple[ReconciliationResult, ...]

    @property
    def diverged_agents(self) -> tuple[ReconciliationResult, ...]:
        return tuple(r for r in self.results if r.diverged)

    @property
    def max_severity(self) -> DivergenceSeverity:
        if not self.results:
            return DivergenceSeverity.NONE
        return max(r.severity for r in self.results)

    @property
    def any_geyser_loss(self) -> bool:
        """True if Geyser missed transactions for ANY agent — the alert."""
        return any(r.webhook_only for r in self.results)


def reconcile_all(
    per_agent_streams: dict[str, tuple[Iterable[str], Iterable[str]]],
) -> ReconciliationReport:
    """
    Reconcile many agents at once.

    `per_agent_streams` maps agent_wallet -> (geyser_sigs, webhook_sigs).
    Returns a `ReconciliationReport`. Deterministic — agents processed in
    sorted order.
    """
    results = [
        reconcile_agent(wallet, geyser, webhook)
        for wallet, (geyser, webhook) in sorted(per_agent_streams.items())
    ]
    return ReconciliationReport(results=tuple(results))
