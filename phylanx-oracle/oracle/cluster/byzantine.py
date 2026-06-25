"""
oracle/cluster/byzantine.py — Byzantine fault detection for the cluster.

Day 24 made the cluster median-robust: one outlier cannot move the result.
Day 25 made it copy-proof: a node cannot free-ride on a peer's score. Day
26 makes the cluster ACCUSE: it identifies *which* node is faulty, and
feeds repeated offenders to on-chain slashing.

TWO MECHANISMS
--------------
1. DEVIATION DETECTION (per epoch). After every node reveals, compute how
   far each node's score is from the cluster median. A node deviating by
   more than `BYZANTINE_DEVIATION_THRESHOLD` (30%) is flagged Byzantine
   for that epoch. The median is the honest reference because — by
   construction (Day 24) — a single faulty node cannot move it.

2. OM(1) BYZANTINE AGREEMENT. The Lamport-Shostak-Pease "Oral Messages"
   algorithm, OM(m) with m = 1: the classic Byzantine-generals solution
   for reaching agreement when up to one node lies inconsistently to
   different peers. See `om1_agreement` below for the algorithm and its
   honest scope (OM(1) needs n >= 4).

Deviation detection alone catches a node that lies the SAME wrong value to
everyone. OM(1) additionally catches a node that lies DIFFERENTLY to
different peers — the harder Byzantine case — by forcing agreement on what
each node actually said.

DETERMINISM
-----------
All of this is pure integer / ordering logic over an explicit set of
revealed scores — no clock, no randomness, no I/O. Every honest node runs
the identical analysis and reaches the identical verdict, which is what
lets the cluster agree on who is Byzantine.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field


# A node whose score deviates from the cluster median by more than this
# fraction is flagged Byzantine for the epoch. 30% — far wider than any
# honest disagreement between correct detectors on the same inputs (which
# is zero, the engine being deterministic), but not so tight that a
# boundary-rounding difference trips it.
BYZANTINE_DEVIATION_THRESHOLD = 0.30


# =============================================================================
# Per-node deviation
# =============================================================================

@dataclass(frozen=True, slots=True)
class NodeDeviation:
    """How far one node's score sits from the cluster median for one agent."""
    node_id:        str
    score:          int
    median:         int
    # Absolute deviation as a fraction of the median (or of 1 if median is
    # 0, to avoid divide-by-zero — see _deviation_fraction).
    deviation:      float
    is_byzantine:   bool

    @property
    def deviation_pct(self) -> float:
        return self.deviation * 100.0


@dataclass(frozen=True, slots=True)
class DeviationReport:
    """The deviation analysis for one agent across all revealing nodes."""
    agent_wallet:    str
    median:          int
    deviations:      tuple[NodeDeviation, ...]

    @property
    def byzantine_nodes(self) -> tuple[str, ...]:
        """Node ids flagged Byzantine for this agent."""
        return tuple(d.node_id for d in self.deviations if d.is_byzantine)

    @property
    def honest_nodes(self) -> tuple[str, ...]:
        return tuple(d.node_id for d in self.deviations if not d.is_byzantine)


# =============================================================================
# Deviation analysis
# =============================================================================

def _deviation_fraction(score: int, median: int) -> float:
    """
    |score - median| as a fraction of the median. When the median is 0 we
    divide by 1 instead — any non-zero score against a 0 median is a large
    absolute deviation, and dividing by zero is undefined; using 1 makes
    the fraction equal the raw score, which crosses the 30% threshold for
    any score >= 1, correctly flagging it.
    """
    denom = median if median > 0 else 1
    return abs(score - median) / denom


def analyse_deviation(
    agent_wallet: str,
    node_scores:  Mapping[str, int],
    *,
    threshold:    float = BYZANTINE_DEVIATION_THRESHOLD,
) -> DeviationReport:
    """
    Compute each node's deviation from the cluster median for one agent,
    and flag the Byzantine ones.

    `node_scores` maps node_id -> that node's score for this agent. The
    median is computed here (lower-middle on an even count, matching the
    Day-24 aggregator). A node whose score deviates by more than
    `threshold` is flagged Byzantine.

    Pure + deterministic.
    """
    if not node_scores:
        raise ValueError("analyse_deviation needs at least one node score")

    ordered = sorted(node_scores.values())
    median = ordered[(len(ordered) - 1) // 2]      # lower-middle, as Day 24

    deviations: list[NodeDeviation] = []
    for node_id in sorted(node_scores):
        score = node_scores[node_id]
        frac = _deviation_fraction(score, median)
        deviations.append(NodeDeviation(
            node_id=node_id,
            score=score,
            median=median,
            deviation=frac,
            is_byzantine=frac > threshold,
        ))

    return DeviationReport(
        agent_wallet=agent_wallet,
        median=median,
        deviations=tuple(deviations),
    )


# =============================================================================
# OM(1) — recursive Oral Messages Byzantine agreement
# =============================================================================
#
# OM(m) is the Lamport-Shostak-Pease algorithm for Byzantine agreement. It
# lets honest nodes agree on a value even when up to `m` nodes are traitors
# that may send DIFFERENT values to different peers. It is recursive:
#
#   OM(0): the commander sends its value to every lieutenant; each uses it.
#   OM(m): the commander sends its value to every lieutenant; then each
#          lieutenant acts as the commander of an OM(m-1) among the others;
#          each node decides by MAJORITY over the values thus gathered.
#
# OM(m) tolerates m traitors iff there are at least 3m + 1 nodes. So OM(1)
# — m = 1 — requires n >= 4. Phylanx's cluster is 3-5 nodes; OM(1) is
# therefore meaningful for the 4- and 5-node cluster. For a 3-node cluster
# (n = 3 < 4) OM(1)'s precondition does not hold, and the honest mechanism
# is the median + deviation detection (the median of 3 is itself robust to
# one outlier). `om1_agreement` enforces the n >= 4 precondition rather
# than silently returning an unsound result on 3 nodes.

@dataclass(frozen=True, slots=True)
class OMResult:
    """The outcome of an OM(1) agreement on one (commander, value) input."""
    agreed_value:   int
    # Each lieutenant's decided value — they should all match `agreed_value`
    # when the honest majority holds.
    decisions:      dict[str, int]
    honest_majority: bool


def om1_agreement(
    commander:        str,
    commander_value:  int,
    lieutenants:      Sequence[str],
    *,
    messages:         Mapping[tuple[str, str], int] | None = None,
) -> OMResult:
    """
    Run OM(1) — Oral Messages with m = 1 — to agree on the commander's
    value among `lieutenants`.

    `messages` optionally overrides what a node relays to another:
    messages[(sender, receiver)] = the value `sender` told `receiver`. A
    BYZANTINE node can be modelled by giving it inconsistent entries — that
    is exactly the case OM(1) is designed to survive. When `messages` is
    omitted every node relays `commander_value` faithfully (the all-honest
    case).

    PRECONDITION: total nodes (commander + lieutenants) must be >= 4 —
    OM(1) needs n >= 3m+1 with m = 1. A smaller cluster raises ValueError;
    use deviation detection there instead.

    Returns the agreed value (the majority decision) and each lieutenant's
    individual decision.
    """
    n = 1 + len(lieutenants)
    if n < 4:
        raise ValueError(
            f"OM(1) needs n >= 4 nodes (got {n}); for a smaller cluster use "
            f"deviation detection — the median of an odd cluster is itself "
            f"robust to one Byzantine node"
        )
    lts = list(lieutenants)

    def relayed(sender: str, receiver: str, default: int) -> int:
        if messages is not None and (sender, receiver) in messages:
            return messages[(sender, receiver)]
        return default

    # ── OM(1), step 1: the commander sends its value to every lieutenant ────
    # received[L] = the value lieutenant L got DIRECTLY from the commander.
    received_from_commander = {
        lt: relayed(commander, lt, commander_value) for lt in lts
    }

    # ── OM(1), step 2: each lieutenant L acts as the commander of an
    #    OM(0) among the OTHER lieutenants — i.e. L tells every other
    #    lieutenant the value it got from the commander. ──
    # gathered[L] = the multiset of values L now holds: its own direct
    # value, plus what every other lieutenant relayed to it.
    decisions: dict[str, int] = {}
    for lt in lts:
        gathered = [received_from_commander[lt]]
        for other in lts:
            if other == lt:
                continue
            # `other` relays to `lt` the value `other` got from the
            # commander. A Byzantine `other` may relay something else.
            gathered.append(
                relayed(other, lt, received_from_commander[other])
            )
        decisions[lt] = _majority_value(gathered)

    agreed = _majority_value(list(decisions.values()))
    honest_majority = sum(
        1 for v in decisions.values() if v == agreed
    ) > len(decisions) / 2

    return OMResult(
        agreed_value=agreed,
        decisions=decisions,
        honest_majority=honest_majority,
    )


def _majority_value(values: Sequence[int]) -> int:
    """
    The majority value of a sequence. With no strict majority, returns the
    MEDIAN (lower-middle) — the default OM uses when lieutenants disagree,
    and itself robust to a single outlier.
    """
    if not values:
        raise ValueError("majority of an empty sequence")
    counts: dict[int, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    best_value, best_count = max(counts.items(), key=lambda kv: (kv[1], -kv[0]))
    if best_count > len(values) / 2:
        return best_value
    ordered = sorted(values)
    return ordered[(len(ordered) - 1) // 2]
