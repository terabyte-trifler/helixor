"""Shared fixtures for the helixor-api test suite."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
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
# Per-test repo fixtures — populated with a small, predictable dataset
# =============================================================================

@pytest.fixture
def score_repo() -> InMemoryScoreRepo:
    repo = InMemoryScoreRepo()
    # Agent A: a YELLOW past, a GREEN now.
    repo.add(ScoreRecord("agentA", 27, 700, 1, 0x02, False, 3, REF_TS))
    repo.add(ScoreRecord("agentA", 28, 851, 1, 0x42, False, 3, REF_TS))
    repo.add(ScoreRecord("agentA", 29, 920, 0, 0x00, False, 4, REF_TS))
    # Agent B: one cert, RED with immediate_red set.
    repo.add(ScoreRecord("agentB", 29, 220, 2, 0xff, True,  5, REF_TS))
    return repo


@pytest.fixture
def byzantine_repo() -> InMemoryByzantineRepo:
    repo = InMemoryByzantineRepo()
    repo.add_flag(ByzantineFlagRecord(
        node_id="oracle-node-2", epoch=28,
        subject_agent="agentA", accused_score=40,
        cluster_median=851, deviation=0.95,
    ))
    repo.add_flag(ByzantineFlagRecord(
        node_id="oracle-node-2", epoch=29,
        subject_agent="agentB", accused_score=900,
        cluster_median=220, deviation=3.09,
    ))
    repo.set_strikes(StrikeSummary(
        node_id="oracle-node-2", strikes=2,
        flagged_epochs=(28, 29), challenged=False,
    ))
    repo.add_reveal(NodeRevealRecord("oracle-node-0", 28, "agentA", 851))
    repo.add_reveal(NodeRevealRecord("oracle-node-1", 28, "agentA", 850))
    repo.add_reveal(NodeRevealRecord("oracle-node-2", 28, "agentA",  40))
    repo.add_reveal(NodeRevealRecord("oracle-node-3", 28, "agentA", 853))
    repo.add_reveal(NodeRevealRecord("oracle-node-4", 28, "agentA", 851))
    repo.add_challenge(ChallengeRecord(
        challenge_index=0,
        accused_node="oracle-node-2",
        proof_type=0,
        subject_epoch=28,
        subject_agent="agentA",
        accused_score=40,
        cluster_median=851,
        evidence_hash="b" * 64,
        status="pending",
        filed_at=1_750_000_000,
    ))
    return repo


@pytest.fixture
def cluster_repo() -> InMemoryClusterHealthRepo:
    repo = InMemoryClusterHealthRepo()
    for i in range(5):
        repo.add_heartbeat(NodeHeartbeat(
            node_id=f"oracle-node-{i}",
            last_seen_unix=1_750_000_000,
            epoch=29,
        ))
    repo.add_epoch(EpochSummary(
        epoch=28, submitted_count=2, agent_count=2,
        verified_nodes=("oracle-node-0", "oracle-node-1", "oracle-node-2",
                        "oracle-node-3", "oracle-node-4"),
        byzantine_nodes=("oracle-node-2",),
        unreachable_nodes=(),
        elapsed_seconds=6.3,
        computed_at=REF_TS,
    ))
    repo.add_epoch(EpochSummary(
        epoch=29, submitted_count=2, agent_count=2,
        verified_nodes=("oracle-node-0", "oracle-node-1", "oracle-node-3",
                        "oracle-node-4"),
        byzantine_nodes=(),
        unreachable_nodes=("oracle-node-2",),
        elapsed_seconds=5.8,
        computed_at=REF_TS,
    ))
    return repo


@pytest.fixture
def app(score_repo, byzantine_repo, cluster_repo):
    return create_app(
        score_repo=score_repo,
        byzantine_repo=byzantine_repo,
        cluster_repo=cluster_repo,
        network="localnet",
        is_production=False,
        scoring_algo_version="v2.7",
        scoring_weights_version="w1",
    )


@pytest.fixture
def client(app) -> TestClient:
    return TestClient(app)
