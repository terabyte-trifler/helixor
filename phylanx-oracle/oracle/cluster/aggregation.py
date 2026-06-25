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

    Day 37 — label consensus fields:
      * `label_bitmask` (u64) — the per-bit majority of every contributing
        node's `failure_mode_bitmask`. A bit is set iff a strict majority
        of CONTRIBUTING nodes set it; a single faulty node can neither
        inject nor suppress a label.
      * `diagnosis_payload_hash` (32 bytes or empty) — the exact-match hash
        a strict honest majority of contributing nodes agreed on. Empty
        when no majority hash exists (the cluster could not agree on
        diagnosis payload bytes) OR every node ran in score-only mode.
      * `payload_hash_signers` — the node ids whose payload hash matched
        the consensus. The cert signing set comes from this when label
        consensus is in play.
      * `payload_hash_dissenters` — the node ids whose payload hash did
        NOT match the consensus. Hard label-deviation evidence; the
        watchdog strikes these immediately (no flap window).
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
    # Day 37 — label consensus. Defaults make pre-v2 callers behave as
    # before (no label_bitmask, no payload-hash consensus, no dissenters).
    label_bitmask:               int = 0
    diagnosis_payload_hash:      bytes = b""
    payload_hash_signers:        tuple[str, ...] = ()
    payload_hash_dissenters:     tuple[str, ...] = ()

    @property
    def unanimous(self) -> bool:
        """True if every contributing node produced the identical score."""
        return self.score_spread == 0

    @property
    def has_payload_hash_consensus(self) -> bool:
        """
        True iff a strict honest majority of contributing nodes agreed on
        a non-empty `diagnosis_payload_hash`. When False the cluster
        emits no payload-hash field downstream — the cert is score-only
        (or the labels did not converge).
        """
        return bool(self.diagnosis_payload_hash)


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

    # Day 37 — label consensus. Per-bit u64 majority over the diagnosis
    # bitmask; exact-match majority over the payload-hash bytes.
    label_bitmask = _majority_label_bits(
        [ns.score.failure_mode_bitmask for ns in scores_sorted]
    )
    consensus_hash, signers, dissenters = _payload_hash_consensus(
        scores_sorted
    )

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
        label_bitmask=label_bitmask,
        diagnosis_payload_hash=consensus_hash,
        payload_hash_signers=signers,
        payload_hash_dissenters=dissenters,
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


def _majority_label_bits(values: Sequence[int]) -> int:
    """
    Day 37 — per-bit majority over the u64 diagnosis label bitmask. A bit
    is set in the aggregate iff a strict majority of contributing nodes
    set it.

    The Day-37 spec phrases it as "bit set iff >= ceil((n_honest+1)/2)
    honest nodes set it" — over the SIGNING set this is exactly a strict
    majority of the contributors, which is what we apply here. Below
    quorum the function isn't called (aggregate_scores guards on that).
    """
    n = len(values)
    if n == 0:
        return 0
    result = 0
    for bit in range(64):
        mask = 1 << bit
        set_count = sum(1 for v in values if v & mask)
        if set_count > n / 2:
            result |= mask
    return result


def _payload_hash_consensus(
    scores_sorted: Sequence["NodeScore"],
) -> tuple[bytes, tuple[str, ...], tuple[str, ...]]:
    """
    Day 37 — exact-match honest-majority consensus over the per-agent
    `diagnosis_payload_hash`. Returns (consensus_hash, signers,
    dissenters):

      * consensus_hash — the byte string a strict majority of contributing
        nodes agreed on. b"" when no non-empty hash holds a strict
        majority (either the cluster is in score-only mode, or no
        majority emerged — the diagnosis labels did not converge).
      * signers — node ids whose hash equals the consensus, in input
        order. Empty when there is no consensus. The cert signing set
        used downstream by Day 38 attestation.
      * dissenters — node ids whose hash differs from the consensus.
        Hard label-deviation evidence; the watchdog strikes these
        immediately (no flap window). Pre-v2 nodes that reveal an empty
        hash are NOT dissenters when there is no consensus — empty
        agrees with empty.
    """
    n = len(scores_sorted)
    if n == 0:
        return b"", (), ()
    counts: dict[bytes, int] = {}
    for ns in scores_sorted:
        h = bytes(ns.score.diagnosis_payload_hash)
        if not h:
            continue                # empty hashes do not "vote" for anything
        counts[h] = counts.get(h, 0) + 1
    if not counts:
        # Score-only mode — no node ran the kernel. Empty consensus is the
        # right answer; nobody is a dissenter.
        return b"", (), ()
    best_hash, best_count = max(counts.items(), key=lambda kv: kv[1])
    if best_count <= n / 2:
        # No strict majority — labels diverged. Surface NO consensus hash
        # but flag every non-empty-hash node as a dissenter so the
        # watchdog can attribute the divergence. (Empty-hash nodes are
        # not dissenters — they simply didn't run the kernel.)
        dissenters = tuple(
            ns.node_id for ns in scores_sorted
            if ns.score.diagnosis_payload_hash
        )
        return b"", (), dissenters
    signers = tuple(
        ns.node_id for ns in scores_sorted
        if bytes(ns.score.diagnosis_payload_hash) == best_hash
    )
    dissenters = tuple(
        ns.node_id for ns in scores_sorted
        if bytes(ns.score.diagnosis_payload_hash) != best_hash
        and ns.score.diagnosis_payload_hash                # skip empty / pre-v2
    )
    return best_hash, signers, dissenters
