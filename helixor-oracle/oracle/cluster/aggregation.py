"""
oracle/cluster/aggregation.py — Byzantine-fault-tolerant score aggregation.

The oracle cluster's whole reason to exist: no single node decides an
agent's score. Each node scores independently; the cluster AGGREGATES the
per-node scores into one cluster score — and the aggregator is the
**median**.

WHY THE MEDIAN
--------------
The median is the robust aggregator. With an odd cluster (3 or 5 nodes)
the median is the middle value, and a single outlier — whether a faulty
node returning garbage, a malicious node lying, or a crashed node that
simply did not vote — CANNOT move it:

  3 nodes, scores [851, 851, 12]  -> median 851   (the liar is ignored)
  3 nodes, one offline [851, 851] -> median 851   (2 honest nodes agree)
  5 nodes, two faulty [851,851,851,0,1000] -> median 851

The mean would be corruptible — one node returning 0 or 1000 drags the
average. The median is not. This is the BFT property the spec asks for:
"1 of 3 can be faulty/offline and the cluster still produces a correct
score."

QUORUM
------
The median is only meaningful with enough honest nodes present. The
aggregator requires a QUORUM — a strict majority of the cluster
(floor(n/2)+1): 2 of 3, 3 of 5. Below quorum it refuses to produce a
score rather than emit one a single faulty node could have authored.

DETERMINISM
-----------
Median aggregation is pure integer / ordering logic — no clock, no
randomness, no I/O. Every node computing the cluster median over the same
submission set reaches the byte-identical result. This is essential: the
cluster's agreement depends on each node aggregating identically.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from oracle.cluster.messages import AgentScore


# =============================================================================
# A single node's submission for one agent
# =============================================================================

@dataclass(frozen=True, slots=True)
class NodeScore:
    """
    One node's score for one agent — the unit the aggregator consumes.

    `node_id` identifies the author; `score` is its AgentScore payload.
    A node that is offline simply contributes NO NodeScore — absence is
    how a missing node is represented, not a sentinel value.
    """
    node_id: str
    score:   AgentScore

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("NodeScore.node_id must be non-empty")
        if self.node_id != self.score.agent_wallet and not self.score.agent_wallet:
            raise ValueError("NodeScore.score has no agent_wallet")


# =============================================================================
# The aggregated cluster result for one agent
# =============================================================================

@dataclass(frozen=True, slots=True)
class AggregatedScore:
    """
    The cluster's agreed score for one agent — the median of the nodes'
    submissions.

    Carries the median values AND the audit trail: which nodes
    contributed, how many, and the spread, so a reviewer can see the
    cluster agreed (or how far apart it was).
    """
    agent_wallet:        str
    # The median values — what the cluster submits on-chain.
    score:               int
    alert_tier:          int
    flags:               int
    immediate_red:       bool
    confidence:          int
    # Audit trail.
    contributing_nodes:  tuple[str, ...]
    node_count:          int
    quorum:              int
    # The spread of the raw `score` values — 0 means perfect agreement.
    score_spread:        int

    @property
    def unanimous(self) -> bool:
        """True if every contributing node produced the identical score."""
        return self.score_spread == 0


class QuorumNotMet(Exception):
    """
    Raised when fewer than `quorum` nodes contributed a score. The cluster
    refuses to aggregate below quorum rather than emit a score a single
    faulty node could have authored.
    """

    def __init__(self, agent_wallet: str, got: int, needed: int) -> None:
        super().__init__(
            f"quorum not met for {agent_wallet}: {got} node(s) contributed, "
            f"need {needed}"
        )
        self.agent_wallet = agent_wallet
        self.got = got
        self.needed = needed


# =============================================================================
# The quorum rule
# =============================================================================

def quorum_for(cluster_size: int) -> int:
    """
    The quorum for a cluster of `cluster_size` nodes — a strict majority,
    `floor(n/2) + 1`. Matches OracleConfig::consensus_threshold on-chain.
      1 -> 1   3 -> 2   5 -> 3
    """
    if cluster_size < 1:
        raise ValueError(f"cluster_size must be >= 1, got {cluster_size}")
    return cluster_size // 2 + 1


# =============================================================================
# Median helpers — pure, deterministic
# =============================================================================

def _median_int(values: Sequence[int]) -> int:
    """
    The median of a non-empty sequence of ints, as an int.

    For an ODD count the median is the middle element — the BFT-robust
    case the cluster is sized for (3 or 5 nodes). For an EVEN count (e.g.
    a 3-node cluster with one node offline -> 2 values) we take the LOWER
    of the two middle values, deterministically — never an average, which
    would invent a value no node submitted and could be a non-integer.
    Taking the lower-middle is the conservative choice: it cannot be
    inflated by a single high outlier.
    """
    if not values:
        raise ValueError("median of an empty sequence")
    ordered = sorted(values)
    n = len(ordered)
    # Lower-middle index: for odd n this is the true middle; for even n it
    # is the lower of the two central values.
    return ordered[(n - 1) // 2]


def _median_bool(values: Sequence[bool]) -> bool:
    """
    The majority value of a sequence of bools. With an odd cluster this is
    an unambiguous majority; on an even tie it returns False — the
    conservative default (do not assert `immediate_red` on a tie).
    """
    if not values:
        raise ValueError("majority of an empty sequence")
    trues = sum(1 for v in values if v)
    return trues > len(values) / 2


# =============================================================================
# The aggregator
# =============================================================================

def aggregate_scores(
    agent_wallet: str,
    node_scores:  Sequence[NodeScore],
    *,
    cluster_size: int,
) -> AggregatedScore:
    """
    Aggregate the per-node scores for one agent into the cluster's median
    score.

    `node_scores` are the submissions actually received — a node that is
    offline contributes nothing, so `len(node_scores)` may be less than
    `cluster_size`. The QUORUM is checked against `cluster_size`: if fewer
    than a strict majority contributed, `QuorumNotMet` is raised.

    Each numeric field is aggregated by median; `immediate_red` by
    majority. The `agent_wallet` of every NodeScore must match.

    Pure and deterministic.
    """
    if not node_scores:
        raise QuorumNotMet(agent_wallet, 0, quorum_for(cluster_size))

    # Every submission must be for THIS agent.
    for ns in node_scores:
        if ns.score.agent_wallet != agent_wallet:
            raise ValueError(
                f"NodeScore from {ns.node_id} is for "
                f"{ns.score.agent_wallet}, expected {agent_wallet}"
            )

    # A node may submit at most once — duplicate node_ids are a fault.
    seen: set[str] = set()
    for ns in node_scores:
        if ns.node_id in seen:
            raise ValueError(
                f"duplicate submission from node {ns.node_id} for {agent_wallet}"
            )
        seen.add(ns.node_id)

    # ── Quorum check ────────────────────────────────────────────────────────
    quorum = quorum_for(cluster_size)
    if len(node_scores) < quorum:
        raise QuorumNotMet(agent_wallet, len(node_scores), quorum)

    # ── Median across the contributing nodes ────────────────────────────────
    scores_sorted = sorted(node_scores, key=lambda ns: ns.node_id)
    raw_scores = [ns.score.score for ns in scores_sorted]

    median_score      = _median_int(raw_scores)
    median_alert      = _median_int([ns.score.alert_tier for ns in scores_sorted])
    median_confidence = _median_int([ns.score.confidence for ns in scores_sorted])
    majority_ir       = _median_bool([ns.score.immediate_red for ns in scores_sorted])
    # Flags are a bitmask, not an ordinal quantity — aggregate by taking the
    # bits a MAJORITY of nodes set. A single faulty node cannot add or
    # clear a flag.
    median_flags      = _majority_flags([ns.score.flags for ns in scores_sorted])

    return AggregatedScore(
        agent_wallet=agent_wallet,
        score=median_score,
        alert_tier=median_alert,
        flags=median_flags,
        immediate_red=majority_ir,
        confidence=median_confidence,
        contributing_nodes=tuple(ns.node_id for ns in scores_sorted),
        node_count=len(node_scores),
        quorum=quorum,
        score_spread=max(raw_scores) - min(raw_scores),
    )


def _majority_flags(flag_values: Sequence[int]) -> int:
    """
    Aggregate a set of u32 flag bitmasks bit-by-bit: a bit is set in the
    result iff a strict majority of nodes set it. So a single faulty node
    can neither inject a spurious flag nor suppress a real one.
    """
    n = len(flag_values)
    result = 0
    for bit in range(32):
        mask = 1 << bit
        set_count = sum(1 for f in flag_values if f & mask)
        if set_count > n / 2:
            result |= mask
    return result
