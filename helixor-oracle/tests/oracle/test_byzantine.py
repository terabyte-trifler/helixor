"""
tests/oracle/test_byzantine.py — Byzantine detection primitives.

Pins deviation analysis, the OM(1) recursive agreement, and the
cross-epoch strike watchdog.
"""

from __future__ import annotations

import pytest

from oracle.cluster.byzantine import (
    BYZANTINE_DEVIATION_THRESHOLD,
    analyse_deviation,
    om1_agreement,
)
from oracle.cluster.byzantine_watchdog import (
    STRIKE_THRESHOLD,
    ByzantineWatchdog,
    EpochByzantineFlag,
    PROOF_CONFLICTING_SCORES,
)


# =============================================================================
# Deviation analysis
# =============================================================================

class TestDeviationAnalysis:

    def test_threshold_is_thirty_percent(self):
        assert BYZANTINE_DEVIATION_THRESHOLD == 0.30

    def test_honest_cluster_flags_nobody(self):
        report = analyse_deviation("agentA", {"n0": 851, "n1": 851, "n2": 851})
        assert report.byzantine_nodes == ()
        assert set(report.honest_nodes) == {"n0", "n1", "n2"}

    def test_wildly_wrong_score_is_flagged(self):
        # n2 at 40 vs a median of 851 — a ~95% deviation.
        report = analyse_deviation("agentA", {"n0": 851, "n1": 851, "n2": 40})
        assert report.byzantine_nodes == ("n2",)
        assert report.median == 851

    def test_high_outlier_is_flagged(self):
        # n2 inflating to 1000 vs a median of 400 — 150% deviation.
        report = analyse_deviation("agentA", {"n0": 400, "n1": 400, "n2": 1000})
        assert report.byzantine_nodes == ("n2",)

    def test_small_disagreement_is_not_flagged(self):
        # 700 vs median 720 — under 30%, honest noise, not flagged.
        report = analyse_deviation("agentA", {"n0": 720, "n1": 720, "n2": 700})
        assert report.byzantine_nodes == ()

    def test_just_over_threshold_is_flagged(self):
        # median 100, n2 at 131 -> 31% deviation -> flagged.
        report = analyse_deviation("agentA", {"n0": 100, "n1": 100, "n2": 131})
        assert "n2" in report.byzantine_nodes

    def test_just_under_threshold_is_not_flagged(self):
        # median 100, n2 at 129 -> 29% -> not flagged.
        report = analyse_deviation("agentA", {"n0": 100, "n1": 100, "n2": 129})
        assert "n2" not in report.byzantine_nodes

    def test_zero_median_handled(self):
        # median 0, a node at 500 — must not divide by zero, and 500 is a
        # large deviation -> flagged.
        report = analyse_deviation("agentA", {"n0": 0, "n1": 0, "n2": 500})
        assert "n2" in report.byzantine_nodes

    def test_deviation_pct_reported(self):
        report = analyse_deviation("agentA", {"n0": 100, "n1": 100, "n2": 200})
        n2 = next(d for d in report.deviations if d.node_id == "n2")
        assert n2.deviation_pct == pytest.approx(100.0)

    def test_empty_rejected(self):
        with pytest.raises(ValueError):
            analyse_deviation("agentA", {})

    def test_deterministic(self):
        scores = {"n0": 851, "n1": 840, "n2": 12}
        first = analyse_deviation("agentA", scores)
        for _ in range(20):
            r = analyse_deviation("agentA", scores)
            assert r.byzantine_nodes == first.byzantine_nodes
            assert r.median == first.median


# =============================================================================
# OM(1) — recursive Oral Messages agreement
# =============================================================================

class TestOM1:

    def test_all_honest_agrees_on_the_value(self):
        # 4 nodes, everyone relays faithfully -> the commander's value wins.
        result = om1_agreement("commander", 700, ["L1", "L2", "L3"])
        assert result.agreed_value == 700
        assert result.honest_majority is True
        assert all(v == 700 for v in result.decisions.values())

    def test_tolerates_one_inconsistent_traitor(self):
        # L2 is Byzantine — it relays DIFFERENT values to different peers.
        # OM(1) still reaches agreement among the honest majority.
        messages = {("L2", "L1"): 999, ("L2", "L3"): 0}
        result = om1_agreement(
            "commander", 700, ["L1", "L2", "L3"], messages=messages,
        )
        assert result.agreed_value == 700
        assert result.honest_majority is True

    def test_tolerates_a_traitor_commander(self):
        # The commander itself lies — sends different values to lieutenants.
        # OM(1) guarantees the honest lieutenants still AGREE (on some
        # value), even if it is not "correct" — agreement is the property.
        messages = {
            ("commander", "L1"): 100,
            ("commander", "L2"): 100,
            ("commander", "L3"): 900,
        }
        result = om1_agreement(
            "commander", 100, ["L1", "L2", "L3"], messages=messages,
        )
        # All honest lieutenants decide the same value.
        assert len(set(result.decisions.values())) == 1

    def test_requires_at_least_four_nodes(self):
        # OM(1) needs n >= 3m+1 = 4. A 3-node cluster cannot run it.
        with pytest.raises(ValueError, match="n >= 4"):
            om1_agreement("commander", 700, ["L1", "L2"])

    def test_five_node_om1(self):
        result = om1_agreement("commander", 500, ["L1", "L2", "L3", "L4"])
        assert result.agreed_value == 500

    def test_deterministic(self):
        messages = {("L2", "L1"): 999}
        first = om1_agreement(
            "commander", 700, ["L1", "L2", "L3"], messages=messages,
        )
        for _ in range(20):
            r = om1_agreement(
                "commander", 700, ["L1", "L2", "L3"], messages=messages,
            )
            assert r.agreed_value == first.agreed_value
            assert r.decisions == first.decisions


# =============================================================================
# The watchdog — cross-epoch strikes
# =============================================================================

class TestByzantineWatchdog:

    def _flag(self, node_id: str, epoch: int) -> EpochByzantineFlag:
        return EpochByzantineFlag(
            node_id=node_id, epoch=epoch, subject_agent="agentA",
            accused_score=40, cluster_median=851,
        )

    def test_strike_threshold_is_three(self):
        assert STRIKE_THRESHOLD == 3

    def test_one_strike_does_not_challenge(self):
        wd = ByzantineWatchdog()
        filed = wd.record_epoch(1, [self._flag("n2", 1)])
        assert filed == []
        assert wd.strikes_for("n2") == 1
        assert wd.is_challenged("n2") is False

    def test_three_strikes_files_a_challenge(self):
        wd = ByzantineWatchdog()
        wd.record_epoch(1, [self._flag("n2", 1)])
        wd.record_epoch(2, [self._flag("n2", 2)])
        filed = wd.record_epoch(3, [self._flag("n2", 3)])
        assert len(filed) == 1
        assert filed[0].accused_node == "n2"
        assert filed[0].strikes == 3
        assert wd.is_challenged("n2") is True

    def test_challenge_uses_conflicting_scores_proof(self):
        wd = ByzantineWatchdog()
        for e in (1, 2, 3):
            filed = wd.record_epoch(e, [self._flag("n2", e)])
        assert filed[0].proof_type == PROOF_CONFLICTING_SCORES

    def test_a_node_is_challenged_only_once(self):
        wd = ByzantineWatchdog()
        for e in (1, 2, 3, 4, 5):
            filed = wd.record_epoch(e, [self._flag("n2", e)])
        # The challenge fires at epoch 3; epochs 4-5 do not re-file.
        assert wd.strikes_for("n2") == 5
        # Only epoch 3 returned a challenge.
        assert filed == []  # epoch 5 filed nothing

    def test_challenge_fn_is_invoked(self):
        wd = ByzantineWatchdog()
        received = []
        for e in (1, 2, 3):
            wd.record_epoch(e, [self._flag("n2", e)],
                            challenge_fn=received.append)
        assert len(received) == 1
        assert received[0].accused_node == "n2"

    def test_one_strike_per_epoch_even_with_many_agents(self):
        # A node flagged for 3 agents in one epoch earns ONE strike.
        wd = ByzantineWatchdog()
        flags = [
            EpochByzantineFlag("n2", 1, f"agent{i}", 40, 851)
            for i in range(3)
        ]
        wd.record_epoch(1, flags)
        assert wd.strikes_for("n2") == 1

    def test_honest_node_never_challenged(self):
        wd = ByzantineWatchdog()
        for e in (1, 2, 3):
            wd.record_epoch(e, [self._flag("n2", e)])
        assert wd.strikes_for("n0") == 0
        assert wd.is_challenged("n0") is False

    def test_flag_epoch_mismatch_rejected(self):
        wd = ByzantineWatchdog()
        with pytest.raises(ValueError):
            wd.record_epoch(1, [self._flag("n2", 2)])

    def test_challenge_cites_worst_deviation(self):
        # When a node is flagged for several agents, the cited evidence is
        # the worst (largest) deviation.
        wd = ByzantineWatchdog()
        for e in (1, 2):
            wd.record_epoch(e, [self._flag("n2", e)])
        flags = [
            EpochByzantineFlag("n2", 3, "agentA", 800, 851),  # small
            EpochByzantineFlag("n2", 3, "agentB", 10, 851),   # huge
        ]
        filed = wd.record_epoch(3, flags)
        assert filed[0].accused_score == 10        # the worst one
