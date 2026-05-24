"""
tests/test_repos.py — direct tests of the in-memory repo implementations.

The app tests cover the HTTP surface; these cover the repo invariants
independently. A future TimescaleDB adapter must satisfy the same
properties — these tests are the contract.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from api.byzantine_repo import (
    ByzantineFlagRecord,
    ChallengeRecord,
    InMemoryByzantineRepo,
    NodeRevealRecord,
    StrikeSummary,
)
from api.cluster_health import (
    EpochSummary,
    InMemoryClusterHealthRepo,
    NodeHeartbeat,
)
from api.score_repo import InMemoryScoreRepo, ScoreRecord


REF_TS = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# ScoreRecord validation
# =============================================================================

class TestScoreRecordValidation:

    @pytest.mark.parametrize("bad_score", [-1, 1001, 5000])
    def test_score_must_be_in_range(self, bad_score):
        with pytest.raises(ValueError, match="score"):
            ScoreRecord("a", 1, bad_score, 0, 0, False, 3, REF_TS)

    @pytest.mark.parametrize("bad_tier", [-1, 3, 99])
    def test_alert_tier_must_be_known(self, bad_tier):
        with pytest.raises(ValueError, match="alert_tier"):
            ScoreRecord("a", 1, 500, bad_tier, 0, False, 3, REF_TS)

    def test_epoch_must_be_positive(self):
        with pytest.raises(ValueError, match="epoch"):
            ScoreRecord("a", 0, 500, 0, 0, False, 3, REF_TS)

    def test_signer_count_must_be_positive(self):
        with pytest.raises(ValueError, match="signer_count"):
            ScoreRecord("a", 1, 500, 0, 0, False, 0, REF_TS)


# =============================================================================
# InMemoryScoreRepo
# =============================================================================

class TestInMemoryScoreRepo:

    def test_latest_score_picks_newest_epoch(self):
        repo = InMemoryScoreRepo()
        repo.add(ScoreRecord("a", 10, 500, 1, 0, False, 3, REF_TS))
        repo.add(ScoreRecord("a", 5,  900, 0, 0, False, 3, REF_TS))
        repo.add(ScoreRecord("a", 20, 200, 2, 0, True,  3, REF_TS))
        latest = repo.latest_score("a")
        assert latest.epoch == 20

    def test_latest_score_unknown_agent_is_none(self):
        repo = InMemoryScoreRepo()
        assert repo.latest_score("nobody") is None

    def test_replace_semantics_on_same_epoch(self):
        # The on-chain HealthCertificate is write-once per (agent, epoch).
        # A re-add for the same (agent, epoch) replaces — last-write-wins.
        repo = InMemoryScoreRepo()
        repo.add(ScoreRecord("a", 1, 500, 1, 0, False, 3, REF_TS))
        repo.add(ScoreRecord("a", 1, 750, 1, 0, False, 4, REF_TS))
        latest = repo.latest_score("a")
        assert latest.score == 750
        assert latest.signer_count == 4

    def test_score_history_newest_first(self):
        repo = InMemoryScoreRepo()
        for e in (5, 10, 15, 20):
            repo.add(ScoreRecord("a", e, 500, 1, 0, False, 3, REF_TS))
        history = repo.score_history("a")
        assert [r.epoch for r in history] == [20, 15, 10, 5]

    def test_score_history_filters(self):
        repo = InMemoryScoreRepo()
        for e in range(1, 11):
            repo.add(ScoreRecord("a", e, 500, 1, 0, False, 3, REF_TS))
        out = repo.score_history("a", from_epoch=4, to_epoch=7)
        assert [r.epoch for r in out] == [7, 6, 5, 4]

    def test_score_history_limit(self):
        repo = InMemoryScoreRepo()
        for e in range(1, 11):
            repo.add(ScoreRecord("a", e, 500, 1, 0, False, 3, REF_TS))
        out = repo.score_history("a", limit=3)
        assert [r.epoch for r in out] == [10, 9, 8]

    @pytest.mark.parametrize("bad_limit", [0, -1, 1001])
    def test_score_history_limit_out_of_bounds(self, bad_limit):
        repo = InMemoryScoreRepo()
        with pytest.raises(ValueError):
            repo.score_history("a", limit=bad_limit)

    def test_known_agents_sorted(self):
        repo = InMemoryScoreRepo()
        repo.add(ScoreRecord("zeta",  1, 500, 1, 0, False, 3, REF_TS))
        repo.add(ScoreRecord("alpha", 1, 500, 1, 0, False, 3, REF_TS))
        repo.add(ScoreRecord("beta",  1, 500, 1, 0, False, 3, REF_TS))
        assert repo.known_agents() == ["alpha", "beta", "zeta"]


# =============================================================================
# InMemoryByzantineRepo
# =============================================================================

class TestInMemoryByzantineRepo:

    def test_recent_flags_newest_first(self):
        repo = InMemoryByzantineRepo()
        for e in (10, 20, 30, 15):
            repo.add_flag(ByzantineFlagRecord(
                node_id="n", epoch=e, subject_agent="a",
                accused_score=0, cluster_median=500, deviation=1.0,
            ))
        epochs = [f.epoch for f in repo.recent_flags()]
        assert epochs == [30, 20, 15, 10]

    def test_since_epoch_filter(self):
        repo = InMemoryByzantineRepo()
        for e in (10, 20, 30):
            repo.add_flag(ByzantineFlagRecord(
                node_id="n", epoch=e, subject_agent="a",
                accused_score=0, cluster_median=500, deviation=1.0,
            ))
        epochs = [f.epoch for f in repo.recent_flags(since_epoch=20)]
        assert epochs == [30, 20]

    @pytest.mark.parametrize("bad", [0, -1, 1001])
    def test_limit_out_of_bounds(self, bad):
        repo = InMemoryByzantineRepo()
        with pytest.raises(ValueError):
            repo.recent_flags(limit=bad)

    def test_per_node_reveals_sorted_by_node(self):
        repo = InMemoryByzantineRepo()
        for nid in ("oracle-node-2", "oracle-node-0", "oracle-node-1"):
            repo.add_reveal(NodeRevealRecord(nid, 1, "a", 100))
        nodes = [r.node_id for r in repo.per_node_reveals(epoch=1, agent_wallet="a")]
        assert nodes == ["oracle-node-0", "oracle-node-1", "oracle-node-2"]

    def test_challenges_filter_by_node(self):
        repo = InMemoryByzantineRepo()
        for i, accused in enumerate(["node-a", "node-b", "node-a"]):
            repo.add_challenge(ChallengeRecord(
                challenge_index=i, accused_node=accused,
                proof_type=0, subject_epoch=1, subject_agent="x",
                accused_score=0, cluster_median=500,
                evidence_hash="0"*64, status="pending", filed_at=0,
            ))
        for_a = repo.challenges_for("node-a")
        assert [c.challenge_index for c in for_a] == [2, 0]   # newest first


# =============================================================================
# ByzantineFlagRecord validation
# =============================================================================

class TestByzantineFlagValidation:

    def test_negative_deviation_rejected(self):
        with pytest.raises(ValueError):
            ByzantineFlagRecord(
                node_id="n", epoch=1, subject_agent="a",
                accused_score=0, cluster_median=500, deviation=-0.1,
            )


# =============================================================================
# InMemoryClusterHealthRepo
# =============================================================================

class TestInMemoryClusterHealthRepo:

    def test_heartbeats_sorted_by_node(self):
        repo = InMemoryClusterHealthRepo()
        for nid in ("c", "a", "b"):
            repo.add_heartbeat(NodeHeartbeat(node_id=nid, last_seen_unix=0, epoch=1))
        assert [h.node_id for h in repo.heartbeats()] == ["a", "b", "c"]

    def test_heartbeat_last_writer_wins(self):
        repo = InMemoryClusterHealthRepo()
        repo.add_heartbeat(NodeHeartbeat("a", 100, 1))
        repo.add_heartbeat(NodeHeartbeat("a", 200, 2))
        assert len(repo.heartbeats()) == 1
        assert repo.heartbeats()[0].last_seen_unix == 200

    def test_epoch_summaries_newest_first(self):
        repo = InMemoryClusterHealthRepo()
        for e in (5, 10, 15):
            repo.add_epoch(EpochSummary(
                epoch=e, submitted_count=1, agent_count=1,
                verified_nodes=(), byzantine_nodes=(), unreachable_nodes=(),
                elapsed_seconds=1.0, computed_at=REF_TS,
            ))
        epochs = [e.epoch for e in repo.recent_epochs()]
        assert epochs == [15, 10, 5]

    def test_epoch_replace_semantics(self):
        repo = InMemoryClusterHealthRepo()
        repo.add_epoch(EpochSummary(
            epoch=1, submitted_count=1, agent_count=1,
            verified_nodes=(), byzantine_nodes=(), unreachable_nodes=(),
            elapsed_seconds=1.0, computed_at=REF_TS,
        ))
        repo.add_epoch(EpochSummary(
            epoch=1, submitted_count=2, agent_count=2,
            verified_nodes=(), byzantine_nodes=(), unreachable_nodes=(),
            elapsed_seconds=2.0, computed_at=REF_TS,
        ))
        out = repo.recent_epochs()
        assert len(out) == 1
        assert out[0].submitted_count == 2

    def test_submitted_all_helper(self):
        s = EpochSummary(
            epoch=1, submitted_count=5, agent_count=5,
            verified_nodes=(), byzantine_nodes=(), unreachable_nodes=(),
            elapsed_seconds=1.0, computed_at=REF_TS,
        )
        assert s.submitted_all is True
        s = EpochSummary(
            epoch=1, submitted_count=4, agent_count=5,
            verified_nodes=(), byzantine_nodes=(), unreachable_nodes=(),
            elapsed_seconds=1.0, computed_at=REF_TS,
        )
        assert s.submitted_all is False
