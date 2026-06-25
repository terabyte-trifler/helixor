"""
tests/detection/test_sybil_graph.py — Sybil-cluster graph analysis.

THE DAY-10 DONE-WHEN (Sybil half): a simulated Sybil cluster is detected.
"""

from __future__ import annotations

import pytest

from detection._sybil_graph import (
    AgentCohortRecord,
    SybilGraph,
    link_strength,
)


def _cp(*names: str) -> frozenset[str]:
    return frozenset(names)


# =============================================================================
# AgentCohortRecord
# =============================================================================

class TestCohortRecord:

    def test_rejects_empty_wallet(self):
        with pytest.raises(ValueError, match="agent_wallet"):
            AgentCohortRecord(agent_wallet="")

    def test_coerces_sets(self):
        r = AgentCohortRecord(agent_wallet="a", counterparties={"x", "y"})
        assert isinstance(r.counterparties, frozenset)


# =============================================================================
# link_strength
# =============================================================================

class TestLinkStrength:

    def test_self_link_is_zero(self):
        r = AgentCohortRecord(agent_wallet="a", funding_source="f")
        assert link_strength(r, r) == 0.0

    def test_shared_funding_source_strong_link(self):
        a = AgentCohortRecord(agent_wallet="a", funding_source="OPERATOR")
        b = AgentCohortRecord(agent_wallet="b", funding_source="OPERATOR")
        assert link_strength(a, b) >= 0.85

    def test_different_funding_no_funding_link(self):
        a = AgentCohortRecord(agent_wallet="a", funding_source="ex1")
        b = AgentCohortRecord(agent_wallet="b", funding_source="ex2")
        assert link_strength(a, b) == 0.0

    def test_shared_counterparties_link(self):
        # Heavily overlapping counterparty sets.
        shared = _cp("c1", "c2", "c3", "c4", "c5")
        a = AgentCohortRecord(agent_wallet="a", counterparties=shared)
        b = AgentCohortRecord(agent_wallet="b", counterparties=shared)
        assert link_strength(a, b) >= 0.6

    def test_few_shared_counterparties_no_link(self):
        # Below MIN_SHARED_COUNTERPARTIES — must NOT link even at Jaccard 1.0.
        a = AgentCohortRecord(agent_wallet="a", counterparties=_cp("c1"))
        b = AgentCohortRecord(agent_wallet="b", counterparties=_cp("c1"))
        assert link_strength(a, b) == 0.0

    def test_direct_flow_link(self):
        a = AgentCohortRecord(agent_wallet="a", direct_links=_cp("b"))
        b = AgentCohortRecord(agent_wallet="b")
        assert link_strength(a, b) >= 0.75

    def test_symmetric(self):
        a = AgentCohortRecord(agent_wallet="a", funding_source="f",
                              counterparties=_cp("c1", "c2", "c3", "c4"))
        b = AgentCohortRecord(agent_wallet="b", funding_source="f",
                              counterparties=_cp("c1", "c2", "c3", "c4"))
        assert link_strength(a, b) == link_strength(b, a)


# =============================================================================
# SybilGraph — cluster detection (THE DONE-WHEN)
# =============================================================================

class TestSybilClusterDetection:

    def _sybil_cohort(self, n: int = 4) -> list[AgentCohortRecord]:
        """n agents all funded from one operator wallet — a Sybil cluster."""
        return [
            AgentCohortRecord(
                agent_wallet=f"sybil{i}",
                funding_source="OPERATOR_WALLET",
                counterparties=_cp("shared_a", "shared_b", "shared_c", "shared_d"),
            )
            for i in range(n)
        ]

    def _honest_cohort(self) -> list[AgentCohortRecord]:
        """Independent agents — distinct funders, distinct counterparties."""
        return [
            AgentCohortRecord(agent_wallet="honest1", funding_source="exchange_A",
                              counterparties=_cp("a1", "a2", "a3", "a4", "a5")),
            AgentCohortRecord(agent_wallet="honest2", funding_source="exchange_B",
                              counterparties=_cp("b1", "b2", "b3")),
            AgentCohortRecord(agent_wallet="honest3", funding_source="exchange_C",
                              counterparties=_cp("c1", "c2", "c3", "c4")),
        ]

    def test_simulated_sybil_cluster_is_detected(self):
        """THE DONE-WHEN: a simulated Sybil cluster is detected."""
        graph = SybilGraph(self._sybil_cohort(4))
        clusters = graph.clusters()
        assert len(clusters) == 1
        assert len(clusters[0]) == 4
        # Every member assesses as in-cluster.
        for i in range(4):
            a = graph.assess(f"sybil{i}")
            assert a.in_cluster
            assert a.cluster_size == 4
            assert a.sybil_signal > 0.0

    def test_independent_agents_form_no_cluster(self):
        graph = SybilGraph(self._honest_cohort())
        assert graph.clusters() == []
        for w in ("honest1", "honest2", "honest3"):
            a = graph.assess(w)
            assert not a.in_cluster
            assert a.sybil_signal == 0.0

    def test_mixed_cohort_isolates_the_cluster(self):
        # Sybil cluster + honest agents in one cohort.
        graph = SybilGraph(self._sybil_cohort(3) + self._honest_cohort())
        clusters = graph.clusters()
        assert len(clusters) == 1
        # The honest agents are NOT swept into the cluster.
        for w in ("honest1", "honest2", "honest3"):
            assert not graph.assess(w).in_cluster

    def test_two_agents_below_min_cluster_size(self):
        # Only 2 shared-funder agents — below MIN_CLUSTER_SIZE (3).
        pair = [
            AgentCohortRecord(agent_wallet="p1", funding_source="OP"),
            AgentCohortRecord(agent_wallet="p2", funding_source="OP"),
        ]
        graph = SybilGraph(pair)
        assert graph.clusters() == []
        assert not graph.assess("p1").in_cluster

    def test_unknown_agent_clean_assessment(self):
        graph = SybilGraph(self._sybil_cohort(4))
        a = graph.assess("not_in_cohort")
        assert not a.in_cluster
        assert a.sybil_signal == 0.0

    def test_larger_cluster_higher_signal(self):
        small = SybilGraph(self._sybil_cohort(3)).assess("sybil0")
        large = SybilGraph(self._sybil_cohort(6)).assess("sybil0")
        assert large.sybil_signal >= small.sybil_signal

    def test_deterministic(self):
        cohort = self._sybil_cohort(4) + self._honest_cohort()
        g1 = SybilGraph(cohort)
        g2 = SybilGraph(cohort)
        assert g1.clusters() == g2.clusters()
        assert g1.assess("sybil0") == g2.assess("sybil0")

    def test_empty_graph(self):
        graph = SybilGraph([])
        assert graph.clusters() == []
        assert graph.edge_count == 0
