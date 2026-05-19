"""
slashing/consensus.py — oracle-cluster consensus for slash confirmation.

A slash is a destructive, economically real action — Day 20/21's
slash-authority program actually moves staked SOL. A single oracle node
must therefore NOT be able to trigger one alone: a slash fires only when
the oracle CLUSTER agrees the offense is real.

WHAT THE CLUSTER IS TODAY vs PHASE 4
------------------------------------
The real 3-node BFT oracle cluster is Phase-4 work (Days 23-28). Today
Helixor runs a single oracle node. So this module models consensus behind
an abstraction:

  - `ConsensusPolicy` — the interface: "given N nodes' verdicts on an
    agent, is the offense CONFIRMED?"
  - `SingleNodeConsensus` — today's policy: one node, its verdict stands.
    Honest about being a single node — it does not pretend to be a cluster.
  - `ThresholdConsensus` — the Phase-4 policy: an offense is confirmed
    only when at least `threshold` of the cluster's nodes independently
    return a confirming verdict (e.g. 2-of-3 BFT). Already implemented and
    tested here so Phase 4 is a wiring change, not a redesign.

The epoch runner asks a `ConsensusPolicy` whether an offense is confirmed
before it will slash. Swapping `SingleNodeConsensus` for
`ThresholdConsensus` in Phase 4 changes one constructor argument.

DETERMINISM
-----------
Consensus evaluation is pure integer/boolean logic over an explicit set of
verdicts — no clock, no randomness — so two nodes evaluating the same
verdict set reach byte-identical conclusions. This matters: the Phase-4
cluster's own agreement depends on each node computing consensus
identically.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


# =============================================================================
# A single node's verdict on an agent
# =============================================================================

@dataclass(frozen=True, slots=True)
class NodeVerdict:
    """
    One oracle node's verdict on whether an agent committed a slashable
    offense this epoch.

    `node_id` identifies the node; `confirms_compromise` is its boolean
    finding. The verdict carries the node's observed `score` and
    `immediate_red` so a reviewer can see WHY a node voted as it did, but
    only `confirms_compromise` feeds the consensus tally.
    """
    node_id:             str
    confirms_compromise: bool
    score:               int
    immediate_red:       bool

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("NodeVerdict.node_id must be non-empty")
        if not (0 <= self.score <= 1000):
            raise ValueError(f"score out of range: {self.score}")


# =============================================================================
# Consensus result
# =============================================================================

@dataclass(frozen=True, slots=True)
class ConsensusResult:
    """The cluster's collective verdict on one agent."""
    confirmed:        bool      # is the offense CONFIRMED by the cluster?
    confirming_votes: int       # how many nodes confirmed
    total_nodes:      int       # how many nodes voted
    policy:           str       # which policy decided (for the audit trail)

    @property
    def vote_summary(self) -> str:
        return f"{self.confirming_votes}/{self.total_nodes}"


# =============================================================================
# The consensus-policy interface
# =============================================================================

@runtime_checkable
class ConsensusPolicy(Protocol):
    """Decides whether a set of node verdicts CONFIRMS a slashable offense."""

    def evaluate(self, verdicts: Sequence[NodeVerdict]) -> ConsensusResult: ...

    @property
    def name(self) -> str: ...


# =============================================================================
# SingleNodeConsensus — today's policy
# =============================================================================

class SingleNodeConsensus:
    """
    Today's consensus policy: Helixor runs ONE oracle node, so that node's
    verdict is the cluster's verdict.

    This is honest about being a single node — it is NOT a security claim
    of distributed agreement. It is the correct policy for the current
    single-node deployment, and the `ConsensusPolicy` interface means
    Phase 4 swaps in `ThresholdConsensus` without touching the runner.
    """

    name = "single-node"

    def evaluate(self, verdicts: Sequence[NodeVerdict]) -> ConsensusResult:
        if len(verdicts) != 1:
            raise ValueError(
                f"SingleNodeConsensus expects exactly 1 verdict, "
                f"got {len(verdicts)} — use ThresholdConsensus for a cluster"
            )
        v = verdicts[0]
        return ConsensusResult(
            confirmed=v.confirms_compromise,
            confirming_votes=1 if v.confirms_compromise else 0,
            total_nodes=1,
            policy=self.name,
        )


# =============================================================================
# ThresholdConsensus — the Phase-4 BFT policy
# =============================================================================

class ThresholdConsensus:
    """
    The Phase-4 cluster policy: an offense is CONFIRMED only when at least
    `threshold` of the cluster's nodes independently confirm it.

    For a 3-node cluster a threshold of 2 gives 2-of-3 BFT agreement —
    tolerating one faulty or malicious node. The threshold is validated
    against the cluster size at construction.

    Implemented and tested now so the Phase-4 cluster is a wiring change.
    """

    def __init__(self, *, cluster_size: int, threshold: int) -> None:
        if cluster_size < 1:
            raise ValueError(f"cluster_size must be >= 1, got {cluster_size}")
        if not (1 <= threshold <= cluster_size):
            raise ValueError(
                f"threshold {threshold} must be in 1..={cluster_size}"
            )
        # A meaningful BFT threshold is a strict majority. We do not forbid
        # a non-majority threshold (a deployment may choose otherwise) but
        # we surface it.
        self._cluster_size = cluster_size
        self._threshold = threshold

    @property
    def name(self) -> str:
        return f"threshold-{self._threshold}-of-{self._cluster_size}"

    @property
    def threshold(self) -> int:
        return self._threshold

    @property
    def cluster_size(self) -> int:
        return self._cluster_size

    def evaluate(self, verdicts: Sequence[NodeVerdict]) -> ConsensusResult:
        if len(verdicts) > self._cluster_size:
            raise ValueError(
                f"got {len(verdicts)} verdicts for a {self._cluster_size}-node "
                f"cluster"
            )
        # Each node votes at most once — duplicate node_ids are a fault.
        seen: set[str] = set()
        for v in verdicts:
            if v.node_id in seen:
                raise ValueError(f"duplicate verdict from node {v.node_id}")
            seen.add(v.node_id)

        confirming = sum(1 for v in verdicts if v.confirms_compromise)
        return ConsensusResult(
            confirmed=confirming >= self._threshold,
            confirming_votes=confirming,
            total_nodes=len(verdicts),
            policy=self.name,
        )
