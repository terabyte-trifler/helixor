"""
detection/_sybil_graph.py — Sybil-cluster detection via cohort graph analysis.

A Sybil cluster is a set of agents controlled by one operator. Single-agent
scanning (Day 9) cannot see it — the signal is inherently RELATIONAL. Two
agents look individually clean but, viewed together, share funding sources
and counterparties in a way independent agents almost never do.

This module builds a graph over a COHORT of agents and finds clusters.

WHAT MAKES TWO AGENTS "LINKED"
------------------------------
  1. Shared funding source — both agents were initially funded from the
     same wallet. Strong signal: independent agents rarely share a funder.
  2. Shared counterparties — both agents transact with a heavily
     overlapping set of counterparties. Jaccard overlap above a threshold.
  3. Direct value flow — the agents transact with EACH OTHER.

CLUSTERING
----------
We build an undirected graph: nodes = agents, an edge connects two agents
whose link strength clears a threshold. Connected components of size >= 2
are candidate Sybil clusters. An agent's "Sybil signal" is a function of
its component size and its mean link strength to component-mates.

Everything here is pure stdlib and deterministic — connected components
via iterative union-find, Jaccard over sets. No randomness, no ML; the
Phase-4 BFT rule holds.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field


# =============================================================================
# Tunables
# =============================================================================

# Counterparty-set Jaccard above this contributes a counterparty link.
COUNTERPARTY_JACCARD_LINK   = 0.60
# Minimum shared counterparties before the Jaccard link counts at all —
# two agents each with one counterparty would otherwise score Jaccard 1.0.
MIN_SHARED_COUNTERPARTIES   = 3
# Overall link strength above which an edge is drawn.
EDGE_THRESHOLD              = 0.50
# A component of at least this size is a candidate Sybil cluster.
MIN_CLUSTER_SIZE            = 3


# =============================================================================
# Per-agent cohort record
# =============================================================================

@dataclass(frozen=True, slots=True)
class AgentCohortRecord:
    """
    The relational fingerprint of one agent, as seen by the cohort graph.

    Deliberately minimal — only the fields Sybil detection needs, so the
    cohort view can be assembled cheaply for every agent in a scoring batch.
    """
    agent_wallet:     str
    funding_source:   str = ""                       # initial-funder wallet, "" if unknown
    counterparties:   frozenset[str] = field(default_factory=frozenset)
    # Agents this agent directly transacted with (subset of all wallets).
    direct_links:     frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.agent_wallet:
            raise ValueError("AgentCohortRecord.agent_wallet must be non-empty")
        if not isinstance(self.counterparties, frozenset):
            object.__setattr__(self, "counterparties", frozenset(self.counterparties))
        if not isinstance(self.direct_links, frozenset):
            object.__setattr__(self, "direct_links", frozenset(self.direct_links))


# =============================================================================
# Link strength
# =============================================================================

def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def link_strength(a: AgentCohortRecord, b: AgentCohortRecord) -> float:
    """
    Link strength in [0, 1] between two agents. The maximum of three signals:

      shared funding   — 0.9 if both agents share a (non-empty) funder
      counterparty sim — counterparty-set Jaccard, but only when at least
                         MIN_SHARED_COUNTERPARTIES are shared
      direct flow      — 0.8 if either agent directly transacted with the other

    Pure, symmetric: link_strength(a, b) == link_strength(b, a).
    """
    if a.agent_wallet == b.agent_wallet:
        return 0.0

    strengths: list[float] = []

    # 1. Shared funding source — the strongest cheap signal.
    if a.funding_source and a.funding_source == b.funding_source:
        strengths.append(0.9)

    # 2. Counterparty-set overlap.
    shared = a.counterparties & b.counterparties
    if len(shared) >= MIN_SHARED_COUNTERPARTIES:
        jac = _jaccard(a.counterparties, b.counterparties)
        if jac >= COUNTERPARTY_JACCARD_LINK:
            strengths.append(jac)

    # 3. Direct value flow between the two agents.
    if b.agent_wallet in a.direct_links or a.agent_wallet in b.direct_links:
        strengths.append(0.8)

    return max(strengths) if strengths else 0.0


# =============================================================================
# Union-Find (iterative — no recursion, deterministic)
# =============================================================================

class _UnionFind:
    def __init__(self, items: Iterable[str]) -> None:
        self._parent: dict[str, str] = {x: x for x in items}

    def find(self, x: str) -> str:
        # Iterative path-halving.
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # Deterministic merge: smaller wallet string becomes the root.
            lo, hi = (ra, rb) if ra < rb else (rb, ra)
            self._parent[hi] = lo

    def components(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for x in self._parent:
            out.setdefault(self.find(x), []).append(x)
        for members in out.values():
            members.sort()
        return out


# =============================================================================
# SybilGraph — the cohort graph
# =============================================================================

@dataclass(frozen=True, slots=True)
class SybilAssessment:
    """The Sybil verdict for a single agent."""
    agent_wallet:     str
    in_cluster:       bool
    cluster_size:     int
    mean_link_strength: float          # mean edge strength to cluster-mates, [0,1]
    cluster_members:  tuple[str, ...]  # sorted, includes the agent itself

    @property
    def sybil_signal(self) -> float:
        """
        A [0, 1] Sybil-risk signal. 0 = no cluster; rises with cluster size
        and link strength. Saturates: a 3-agent cluster with strong links
        is already a near-maximal signal.
        """
        if not self.in_cluster:
            return 0.0
        # Size term saturates at ~6 agents.
        size_term = min(1.0, (self.cluster_size - 1) / 5.0)
        # Combine multiplicatively with link strength so a large-but-weak
        # component and a small-but-strong one both produce moderate signal.
        return max(0.0, min(1.0, 0.5 * size_term + 0.5 * self.mean_link_strength))


class SybilGraph:
    """
    A cohort graph over agents. Construct it with the cohort's
    `AgentCohortRecord`s; query per-agent `assess()`.

    The graph is built once at construction and is immutable thereafter —
    a scoring run gets a consistent cohort snapshot.
    """

    __slots__ = ("_records", "_components", "_edges")

    def __init__(self, records: Iterable[AgentCohortRecord]) -> None:
        recs = {r.agent_wallet: r for r in records}
        self._records: Mapping[str, AgentCohortRecord] = recs

        # Build edges: every pair whose link strength clears EDGE_THRESHOLD.
        wallets = sorted(recs)
        edges: dict[tuple[str, str], float] = {}
        uf = _UnionFind(wallets)
        for i, wa in enumerate(wallets):
            for wb in wallets[i + 1:]:
                s = link_strength(recs[wa], recs[wb])
                if s >= EDGE_THRESHOLD:
                    edges[(wa, wb)] = s
                    uf.union(wa, wb)
        self._edges = edges
        self._components = uf.components()

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def _component_of(self, wallet: str) -> list[str]:
        for members in self._components.values():
            if wallet in members:
                return members
        return [wallet]

    def assess(self, agent_wallet: str) -> SybilAssessment:
        """
        Assess one agent's Sybil-cluster membership.

        An agent not in the cohort at all → a clean, no-cluster assessment.
        """
        if agent_wallet not in self._records:
            return SybilAssessment(
                agent_wallet=agent_wallet, in_cluster=False,
                cluster_size=1, mean_link_strength=0.0,
                cluster_members=(agent_wallet,),
            )

        members = self._component_of(agent_wallet)
        cluster_size = len(members)
        in_cluster = cluster_size >= MIN_CLUSTER_SIZE

        # Mean strength of this agent's edges to cluster-mates.
        my_edges = [
            s for (wa, wb), s in self._edges.items()
            if agent_wallet in (wa, wb)
            and (wa in members and wb in members)
        ]
        mean_strength = sum(my_edges) / len(my_edges) if my_edges else 0.0

        return SybilAssessment(
            agent_wallet=agent_wallet,
            in_cluster=in_cluster,
            cluster_size=cluster_size,
            mean_link_strength=mean_strength,
            cluster_members=tuple(members),
        )

    def clusters(self) -> list[tuple[str, ...]]:
        """All detected Sybil clusters (components of size >= MIN_CLUSTER_SIZE)."""
        return sorted(
            (tuple(m) for m in self._components.values()
             if len(m) >= MIN_CLUSTER_SIZE),
            key=lambda c: (-len(c), c),
        )


# An empty graph — the default cohort context when none is supplied.
EMPTY_SYBIL_GRAPH = SybilGraph([])
