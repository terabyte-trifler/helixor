"""
slashing/divergence.py — TA-1: Byzantine-node divergence detection.

THE TRUST ASSUMPTION (audit)
-----------------------------
    "Oracle nodes are honest (or ≤2 are Byzantine) — the entire system
    breaks at 3+ faulty nodes."

The threshold-signing layer (advance_epoch on-chain) only accepts cluster-
signed scores when ≥ floor(n/2)+1 nodes agree, so a lone malicious node
cannot land a forged cert. But the cluster has NO economic penalty for the
divergent node itself: it can submit garbage every epoch and pay nothing.

This file resolves that gap. Given the per-node score submissions for one
epoch, `DivergenceDetector.detect()` computes:

    consensus       — the median score across the cluster (deterministic,
                      Byzantine-robust: requires ⌈n/2⌉ nodes to move the
                      median by more than `tolerance`)
    divergent_nodes — every node whose score deviates from the consensus
                      by more than `tolerance`, OR whose `immediate_red`
                      bit disagrees with the cluster majority

A divergence report is the evidence packet for a `challenge_oracle`
instruction on slash-authority. The challenge handler is the on-chain
authority; this module is the pure off-chain detector that produces the
evidence hash.

DETERMINISTIC
-------------
Pure integer/boolean logic. Two cluster members observing the same verdict
set MUST compute byte-identical reports — the report's evidence_hash is the
canonical commitment.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

from slashing.consensus import NodeVerdict


# Default tolerance: 50 points on a 0..1000 scale = 5%. The composite
# scorer's 200-point delta guard rail (composite.py) gives honest nodes
# substantial room; 50 is a tight floor relative to that, so divergence
# beyond it is structurally meaningful, not floating-point noise.
DEFAULT_SCORE_TOLERANCE = 50


# =============================================================================
# DivergenceReport — the off-chain evidence packet
# =============================================================================

@dataclass(frozen=True, slots=True)
class DivergenceReport:
    """
    One epoch's divergence report, suitable for hashing into a
    `challenge_oracle` evidence packet.

    `evidence_hash` is the SHA-256 of the canonical-bytes serialisation:

        agent || epoch || consensus_score (u16 LE) ||
        consensus_immediate_red (u8) ||
        sorted(divergent_nodes joined by 0x00)

    Every honest cluster member computing this report on the same verdict
    set produces the IDENTICAL evidence_hash. That is the on-chain anchor.
    """
    agent:                   str
    epoch:                   int
    consensus_score:         int
    consensus_immediate_red: bool
    tolerance:               int
    divergent_nodes:         tuple[str, ...]
    evidence_hash:           bytes

    def __post_init__(self) -> None:
        if not self.agent:
            raise ValueError("DivergenceReport.agent must be non-empty")
        if self.epoch < 0:
            raise ValueError(f"epoch must be >= 0, got {self.epoch}")
        if not (0 <= self.consensus_score <= 1000):
            raise ValueError(
                f"consensus_score {self.consensus_score} out of range [0, 1000]"
            )
        if self.tolerance < 0:
            raise ValueError(f"tolerance must be >= 0, got {self.tolerance}")
        if len(self.evidence_hash) != 32:
            raise ValueError(
                f"evidence_hash must be 32 bytes, got {len(self.evidence_hash)}"
            )
        # Sorted, deduplicated, non-empty IDs in divergent_nodes.
        if sorted(set(self.divergent_nodes)) != list(self.divergent_nodes):
            raise ValueError(
                "divergent_nodes must be sorted, deduplicated, non-empty IDs"
            )
        for nid in self.divergent_nodes:
            if not nid:
                raise ValueError("divergent_nodes IDs must be non-empty")

    @property
    def has_divergence(self) -> bool:
        """True iff at least one node diverged from the cluster."""
        return len(self.divergent_nodes) > 0


# =============================================================================
# DivergenceDetector
# =============================================================================

class DivergenceDetector:
    """
    The pure off-chain detector. Given an epoch's per-node verdicts, returns
    a `DivergenceReport` whose `evidence_hash` is the canonical commitment.

    The consensus score is the MEDIAN of the verdicts — this is the
    Byzantine-robust statistic. To move the median by more than `tolerance`,
    an attacker must control ⌈n/2⌉ nodes, which by hypothesis breaks the
    audit's "≤2 Byzantine" floor.

    The consensus `immediate_red` is the MAJORITY (≥ ⌈n/2⌉) vote on the
    immediate-red bit.

    A node is DIVERGENT if either:
        |node.score - consensus_score| > tolerance
        OR
        node.immediate_red != consensus_immediate_red
    """

    __slots__ = ("_tolerance",)

    def __init__(self, *, tolerance: int = DEFAULT_SCORE_TOLERANCE) -> None:
        if tolerance < 0:
            raise ValueError(f"tolerance must be >= 0, got {tolerance}")
        self._tolerance = int(tolerance)

    @property
    def tolerance(self) -> int:
        return self._tolerance

    def detect(
        self,
        *,
        agent: str,
        epoch: int,
        verdicts: Sequence[NodeVerdict],
    ) -> DivergenceReport:
        if not agent:
            raise ValueError("agent must be non-empty")
        if epoch < 0:
            raise ValueError(f"epoch must be >= 0, got {epoch}")
        if len(verdicts) == 0:
            raise ValueError("detect() requires at least one verdict")

        # Duplicate IDs are a structural fault — the caller is wrong, not
        # divergence.
        seen: set[str] = set()
        for v in verdicts:
            if v.node_id in seen:
                raise ValueError(f"duplicate verdict from node {v.node_id}")
            seen.add(v.node_id)

        # Byzantine-robust consensus: median of the scores.
        scores = sorted(v.score for v in verdicts)
        n = len(scores)
        if n % 2 == 1:
            consensus_score = scores[n // 2]
        else:
            # Even-n median is the floor of the two-element average to keep
            # the result an integer; the choice between floor and ceil is a
            # convention pinned in tests.
            consensus_score = (scores[n // 2 - 1] + scores[n // 2]) // 2

        # Immediate-red consensus: strict majority. Ties default to False
        # (red is the loud signal; we do not promote it on a tied vote).
        red_votes = sum(1 for v in verdicts if v.immediate_red)
        consensus_immediate_red = red_votes > (n // 2)

        # Per-node divergence.
        divergent: list[str] = []
        for v in verdicts:
            if abs(v.score - consensus_score) > self._tolerance:
                divergent.append(v.node_id)
                continue
            if v.immediate_red != consensus_immediate_red:
                divergent.append(v.node_id)

        divergent_sorted = tuple(sorted(set(divergent)))

        evidence_hash = _evidence_hash(
            agent=agent,
            epoch=epoch,
            consensus_score=consensus_score,
            consensus_immediate_red=consensus_immediate_red,
            divergent_nodes=divergent_sorted,
        )

        return DivergenceReport(
            agent=agent,
            epoch=epoch,
            consensus_score=consensus_score,
            consensus_immediate_red=consensus_immediate_red,
            tolerance=self._tolerance,
            divergent_nodes=divergent_sorted,
            evidence_hash=evidence_hash,
        )


def _evidence_hash(
    *,
    agent: str,
    epoch: int,
    consensus_score: int,
    consensus_immediate_red: bool,
    divergent_nodes: tuple[str, ...],
) -> bytes:
    """
    Canonical-bytes commitment over the report's identifying fields. Two
    cluster members observing the same verdict set MUST produce identical
    bytes here — this is the on-chain anchor.
    """
    h = hashlib.sha256()
    h.update(agent.encode("utf-8"))
    h.update(b"\x00")
    h.update(epoch.to_bytes(8, "little", signed=False))
    h.update(consensus_score.to_bytes(2, "little", signed=False))
    h.update(b"\x01" if consensus_immediate_red else b"\x00")
    for nid in divergent_nodes:  # already sorted
        h.update(b"\x00")
        h.update(nid.encode("utf-8"))
    return h.digest()


__all__ = [
    "DEFAULT_SCORE_TOLERANCE",
    "DivergenceDetector",
    "DivergenceReport",
]
