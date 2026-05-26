"""
tests/slashing/test_ta1_divergence.py — TA-1 divergence-detection tests.

Pins the Byzantine-robust median + tolerance logic that turns the on-chain
threshold-signing layer's TRUST assumption ("≤2 Byzantine nodes") into an
ECONOMIC reality: divergent nodes get a deterministic, hashable evidence
packet that any honest cluster member can land via `challenge_oracle`.
"""

from __future__ import annotations

import pytest

from slashing.consensus import NodeVerdict
from slashing.divergence import (
    DEFAULT_SCORE_TOLERANCE,
    DivergenceDetector,
    DivergenceReport,
)


# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------

def test_default_score_tolerance_is_fifty():
    # 5% of the 0..1000 scale — tighter than the 200-pt delta guard rail in
    # composite.py, so anything beyond is structural disagreement, not noise.
    assert DEFAULT_SCORE_TOLERANCE == 50


def test_negative_tolerance_rejected():
    with pytest.raises(ValueError, match="tolerance"):
        DivergenceDetector(tolerance=-1)


# ----------------------------------------------------------------------------
# Median consensus — Byzantine-robust
# ----------------------------------------------------------------------------

def _v(node_id: str, score: int, *, red: bool = False) -> NodeVerdict:
    return NodeVerdict(
        node_id=node_id,
        confirms_compromise=red,  # unused by divergence; pin to red
        score=score,
        immediate_red=red,
    )


def test_three_node_unanimous_no_divergence():
    detector = DivergenceDetector()
    report = detector.detect(
        agent="agentA", epoch=42,
        verdicts=[_v("n1", 700), _v("n2", 700), _v("n3", 700)],
    )
    assert report.consensus_score == 700
    assert report.divergent_nodes == ()
    assert not report.has_divergence


def test_three_node_one_outlier_flagged():
    # Median(700, 705, 100) = 700. tolerance=50. n3 is 600 below → divergent.
    detector = DivergenceDetector()
    report = detector.detect(
        agent="agentA", epoch=1,
        verdicts=[_v("n1", 700), _v("n2", 705), _v("n3", 100)],
    )
    assert report.consensus_score == 700
    assert report.divergent_nodes == ("n3",)


def test_outlier_within_tolerance_not_flagged():
    # tolerance=50, deltas are 30, 40, 50 — all within bounds.
    detector = DivergenceDetector(tolerance=50)
    report = detector.detect(
        agent="agentA", epoch=1,
        verdicts=[_v("n1", 700), _v("n2", 670), _v("n3", 750)],
    )
    assert report.divergent_nodes == ()


def test_outlier_just_outside_tolerance_flagged():
    # tolerance=50. Median = 700. n3=751 → delta=51 → divergent.
    detector = DivergenceDetector(tolerance=50)
    report = detector.detect(
        agent="agentA", epoch=1,
        verdicts=[_v("n1", 700), _v("n2", 700), _v("n3", 751)],
    )
    assert report.divergent_nodes == ("n3",)


def test_five_node_two_byzantine_cannot_move_median():
    # With 5 nodes, the median is the 3rd-ranked score. Two Byzantine
    # nodes voting 0 cannot move the median below 700 (the honest votes).
    detector = DivergenceDetector()
    report = detector.detect(
        agent="agentA", epoch=7,
        verdicts=[
            _v("honest1", 700), _v("honest2", 700), _v("honest3", 700),
            _v("byzantine1", 0), _v("byzantine2", 0),
        ],
    )
    assert report.consensus_score == 700
    assert set(report.divergent_nodes) == {"byzantine1", "byzantine2"}


# ----------------------------------------------------------------------------
# immediate_red consensus
# ----------------------------------------------------------------------------

def test_immediate_red_strict_majority():
    detector = DivergenceDetector()
    # 2 of 3 vote red → consensus is red.
    report = detector.detect(
        agent="agentA", epoch=1,
        verdicts=[
            _v("n1", 700, red=True),
            _v("n2", 700, red=True),
            _v("n3", 700, red=False),
        ],
    )
    assert report.consensus_immediate_red is True
    assert report.divergent_nodes == ("n3",)


def test_immediate_red_tie_defaults_false():
    # Two of four vote red — exactly half. Strict majority requires > n/2,
    # so a tie defaults to False (red is loud; we don't promote on a tie).
    detector = DivergenceDetector()
    report = detector.detect(
        agent="agentA", epoch=1,
        verdicts=[
            _v("n1", 700, red=True),  _v("n2", 700, red=True),
            _v("n3", 700, red=False), _v("n4", 700, red=False),
        ],
    )
    assert report.consensus_immediate_red is False
    # Scores agree, only red-bit disagrees → red-voters are divergent.
    assert set(report.divergent_nodes) == {"n1", "n2"}


# ----------------------------------------------------------------------------
# Even-n median convention
# ----------------------------------------------------------------------------

def test_even_n_median_floors_two_element_average():
    # 4 nodes: scores [700, 720, 740, 760]. Median = (720+740)//2 = 730.
    detector = DivergenceDetector(tolerance=0)
    report = detector.detect(
        agent="a", epoch=1,
        verdicts=[_v("n1", 700), _v("n2", 720), _v("n3", 740), _v("n4", 760)],
    )
    assert report.consensus_score == 730


# ----------------------------------------------------------------------------
# Determinism of evidence_hash — TWO honest cluster members must agree
# ----------------------------------------------------------------------------

def test_evidence_hash_deterministic_across_callers():
    detector_a = DivergenceDetector(tolerance=50)
    detector_b = DivergenceDetector(tolerance=50)
    verdicts = [_v("n1", 700), _v("n2", 800), _v("n3", 100)]
    r1 = detector_a.detect(agent="agentX", epoch=99, verdicts=verdicts)
    r2 = detector_b.detect(agent="agentX", epoch=99, verdicts=verdicts)
    assert r1.evidence_hash == r2.evidence_hash
    assert len(r1.evidence_hash) == 32


def test_evidence_hash_changes_with_epoch():
    detector = DivergenceDetector()
    v = [_v("n1", 700), _v("n2", 100)]
    r1 = detector.detect(agent="a", epoch=1, verdicts=v)
    r2 = detector.detect(agent="a", epoch=2, verdicts=v)
    assert r1.evidence_hash != r2.evidence_hash


def test_evidence_hash_invariant_under_verdict_reordering():
    detector = DivergenceDetector()
    forward = [_v("n1", 700), _v("n2", 705), _v("n3", 100)]
    reverse = [_v("n3", 100), _v("n2", 705), _v("n1", 700)]
    h1 = detector.detect(agent="a", epoch=1, verdicts=forward).evidence_hash
    h2 = detector.detect(agent="a", epoch=1, verdicts=reverse).evidence_hash
    assert h1 == h2


# ----------------------------------------------------------------------------
# Input validation
# ----------------------------------------------------------------------------

def test_empty_verdicts_rejected():
    detector = DivergenceDetector()
    with pytest.raises(ValueError, match="at least one"):
        detector.detect(agent="a", epoch=1, verdicts=[])


def test_duplicate_node_ids_rejected():
    detector = DivergenceDetector()
    with pytest.raises(ValueError, match="duplicate"):
        detector.detect(
            agent="a", epoch=1,
            verdicts=[_v("n1", 700), _v("n1", 800)],
        )


def test_empty_agent_rejected():
    detector = DivergenceDetector()
    with pytest.raises(ValueError, match="agent"):
        detector.detect(agent="", epoch=1, verdicts=[_v("n1", 700)])


def test_negative_epoch_rejected():
    detector = DivergenceDetector()
    with pytest.raises(ValueError, match="epoch"):
        detector.detect(agent="a", epoch=-1, verdicts=[_v("n1", 700)])


# ----------------------------------------------------------------------------
# DivergenceReport invariants
# ----------------------------------------------------------------------------

def test_report_rejects_unsorted_divergent_nodes():
    with pytest.raises(ValueError, match="sorted"):
        DivergenceReport(
            agent="a", epoch=0, consensus_score=0, consensus_immediate_red=False,
            tolerance=0, divergent_nodes=("z", "a"), evidence_hash=b"\x00" * 32,
        )


def test_report_rejects_short_evidence_hash():
    with pytest.raises(ValueError, match="32 bytes"):
        DivergenceReport(
            agent="a", epoch=0, consensus_score=0, consensus_immediate_red=False,
            tolerance=0, divergent_nodes=(), evidence_hash=b"\x00" * 16,
        )
