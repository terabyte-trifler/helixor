"""
detection/security_context.py — the per-scoring-run security context.

`Detector.score(features, baseline)` is a fixed two-argument Protocol
(Day 4). Security needs MORE than that — it needs cohort context (the
Sybil graph) and registration context (the code_hash recorded at baseline
time). Rather than break the Protocol, the SecurityDetector is a STATEFUL
detector: it is constructed with a `SecurityContext` and scores against it.

A scoring run builds one `SecurityContext` (cohort snapshot + denylist),
constructs a `SecurityDetector(context)`, and scores every agent. The
`default_registry()` builds a SecurityDetector with an empty context.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from detection._sybil_graph import EMPTY_SYBIL_GRAPH, SybilGraph
from detection.security_types import ScanMetadata
from features.types import Transaction


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """
    Everything the SecurityDetector needs beyond (features, baseline).

    All fields optional — an empty context yields a detector that still
    runs the single-agent checks (attack scan, integrity, directed
    behaviour) and simply produces no Sybil signal.
    """
    # The agent's transaction window — scanned by the Day-9 pattern library.
    transactions:           tuple[Transaction, ...] = ()
    # Agent registration / declared metadata (Day-9 ScanMetadata).
    scan_metadata:          ScanMetadata = field(default_factory=ScanMetadata)
    # The cohort Sybil graph. EMPTY by default.
    sybil_graph:            SybilGraph = EMPTY_SYBIL_GRAPH
    # Curated known-malicious program denylist (Day-9 HLX-SEC-021).
    denylisted_programs:    frozenset[str] = field(default_factory=frozenset)
    # The code_hash the agent CURRENTLY declares (registration record).
    declared_code_hash:     str = ""
    # The code_hash recorded WHEN THE BASELINE was committed.
    baseline_recorded_hash: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.transactions, tuple):
            object.__setattr__(self, "transactions", tuple(self.transactions))
        if not isinstance(self.denylisted_programs, frozenset):
            object.__setattr__(
                self, "denylisted_programs", frozenset(self.denylisted_programs),
            )


# The default context — empty cohort, no registration hashes.
EMPTY_SECURITY_CONTEXT = SecurityContext()
