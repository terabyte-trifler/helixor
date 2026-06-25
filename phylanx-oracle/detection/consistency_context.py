"""
detection/consistency_context.py — per-scoring-run consistency context.

The domain classifier needs the agent's DECLARED domain — which is
registration context, not part of (features, baseline). Like the Day-10
SecurityContext and the Day-11 MarketContext, the ConsistencyDetector is a
stateful detector constructed with a `ConsistencyContext`.

`default_registry()` builds the detector with an empty context (no
declared domain → the domain classifier abstains, no penalty).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ConsistencyContext:
    """
    Context for a consistency scoring run.

    declared_domain — the behavioural domain the agent declared at
                      registration ("lending", "defi-trading", ...). Empty
                      string → the domain classifier abstains.
    """
    declared_domain: str = ""


# The default — no declared domain. The domain classifier abstains.
EMPTY_CONSISTENCY_CONTEXT = ConsistencyContext()
