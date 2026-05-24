"""Timescale/Postgres-backed read repository tests.

These tests prove the production API path reads real database rows
instead of falling back to empty in-memory repositories.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import psycopg2
from fastapi.testclient import TestClient

from api._timescale import ensure_read_schema, open_repos
from api.app import create_app


DB_URL = os.environ.get(
    "HELIXOR_TEST_DATABASE_URL",
    f"postgresql://{os.environ.get('USER', 'postgres')}@127.0.0.1:5432/helixor_pytest",
)


def _reset_tables(db_url: str) -> None:
    ensure_read_schema(db_url)
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                TRUNCATE
                    agent_score_history,
                    byzantine_flags,
                    oracle_node_reveals,
                    oracle_challenges,
                    oracle_heartbeats,
                    epoch_submission_log
                RESTART IDENTITY
                """
            )


def _seed(db_url: str) -> None:
    now = datetime(2026, 5, 21, 12, 0, 0, tzinfo=timezone.utc)
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO registered_agents (
                    agent_wallet, owner_wallet, name, registration_pda,
                    registered_at, active, onchain_signature
                ) VALUES
                    ('agentA', 'ownerA', 'Agent A', 'pdaA', %s, TRUE, 'sigA'),
                    ('agentB', 'ownerB', 'Agent B', 'pdaB', %s, TRUE, 'sigB')
                ON CONFLICT (agent_wallet) DO UPDATE
                SET active = EXCLUDED.active,
                    synced_at = NOW()
                """,
                (now, now),
            )
            cur.execute(
                """
                INSERT INTO agent_score_history (
                    agent_wallet, epoch, score, alert, alert_tier,
                    success_rate_score, consistency_score, stability_score,
                    raw_score, guard_rail_applied, window_success_rate,
                    window_tx_count, window_sol_volatility, baseline_hash,
                    baseline_algo_version, anomaly_flag,
                    scoring_algo_version, weights_version, flags,
                    immediate_red, signer_count, computed_at
                ) VALUES
                    ('agentA', 30, 851, 'YELLOW', 1,
                     0, 0, 0, 851, FALSE, 0.0, 0, 0.0, '',
                     2, FALSE, 27, 1, 66, FALSE, 3, %s),
                    ('agentA', 31, 927, 'GREEN', 0,
                     0, 0, 0, 927, FALSE, 0.0, 0, 0.0, '',
                     2, FALSE, 27, 1, 0, FALSE, 4, %s),
                    ('agentB', 31, 220, 'RED', 2,
                     0, 0, 0, 220, TRUE, 0.0, 0, 0.0, '',
                     2, TRUE, 27, 1, 255, TRUE, 5, %s)
                """,
                (now, now, now),
            )
            cur.execute(
                """
                INSERT INTO byzantine_flags (
                    node_id, epoch, subject_agent, accused_score,
                    cluster_median, deviation, computed_at
                ) VALUES
                    ('oracle-node-2', 31, 'agentA', 40, 927, 0.956, %s)
                """,
                (now,),
            )
            cur.execute(
                """
                INSERT INTO oracle_node_reveals (
                    node_id, epoch, agent_wallet, score, computed_at
                ) VALUES
                    ('oracle-node-0', 31, 'agentA', 927, %s),
                    ('oracle-node-1', 31, 'agentA', 926, %s),
                    ('oracle-node-2', 31, 'agentA', 40, %s)
                """,
                (now, now, now),
            )
            cur.execute(
                """
                INSERT INTO oracle_challenges (
                    challenge_index, accused_node, proof_type, subject_epoch,
                    subject_agent, accused_score, cluster_median,
                    evidence_hash, status, filed_at
                ) VALUES
                    (0, 'oracle-node-2', 0, 31, 'agentA', 40, 927,
                     repeat('c', 64), 'pending', 1779364800)
                """
            )
            cur.execute(
                """
                INSERT INTO oracle_heartbeats (node_id, last_seen_unix, epoch)
                VALUES
                    ('oracle-node-0', 1779364800, 31),
                    ('oracle-node-1', 1779364800, 31),
                    ('oracle-node-2', 1779364700, 31)
                """
            )
            cur.execute(
                """
                INSERT INTO epoch_submission_log (
                    epoch, submitted_count, agent_count, verified_nodes,
                    byzantine_nodes, unreachable_nodes, elapsed_seconds,
                    computed_at
                ) VALUES
                    (31, 2, 2,
                     ARRAY['oracle-node-0','oracle-node-1'],
                     ARRAY['oracle-node-2'],
                     ARRAY[]::TEXT[], 0.49, %s)
                """,
                (now,),
            )


def _client(db_url: str) -> TestClient:
    score_repo, byzantine_repo, cluster_repo = open_repos(db_url)
    app = create_app(
        score_repo=score_repo,
        byzantine_repo=byzantine_repo,
        cluster_repo=cluster_repo,
        network="devnet",
        is_production=False,
        scoring_algo_version="v2.7",
        scoring_weights_version="w1",
    )
    return TestClient(app)


def test_timescale_score_repo_reads_latest_specific_and_history():
    _reset_tables(DB_URL)
    _seed(DB_URL)
    score_repo, _, _ = open_repos(DB_URL)

    latest = score_repo.latest_score("agentA")
    assert latest is not None
    assert latest.epoch == 31
    assert latest.score == 927
    assert latest.alert_tier == 0
    assert latest.signer_count == 4

    epoch_30 = score_repo.score_at_epoch("agentA", 30)
    assert epoch_30 is not None
    assert epoch_30.score == 851

    assert [r.epoch for r in score_repo.score_history("agentA")] == [31, 30]
    assert score_repo.known_agents() == ["agentA", "agentB"]


def test_timescale_byzantine_and_cluster_repos_read_real_tables():
    _reset_tables(DB_URL)
    _seed(DB_URL)
    _, byz_repo, cluster_repo = open_repos(DB_URL)

    flags = byz_repo.recent_flags()
    assert len(flags) == 1
    assert flags[0].node_id == "oracle-node-2"
    assert flags[0].cluster_median == 927

    strikes = byz_repo.strike_summary()
    assert strikes[0].node_id == "oracle-node-2"
    assert strikes[0].strikes == 1
    assert strikes[0].challenged is True

    reveals = byz_repo.per_node_reveals(epoch=31, agent_wallet="agentA")
    assert [r.node_id for r in reveals] == [
        "oracle-node-0",
        "oracle-node-1",
        "oracle-node-2",
    ]

    challenges = byz_repo.challenges_for("oracle-node-2")
    assert challenges[0].accused_score == 40
    assert challenges[0].status == "pending"

    assert [h.node_id for h in cluster_repo.heartbeats()] == [
        "oracle-node-0",
        "oracle-node-1",
        "oracle-node-2",
    ]
    epoch = cluster_repo.recent_epochs()[0]
    assert epoch.epoch == 31
    assert epoch.byzantine_nodes == ("oracle-node-2",)


def test_api_routes_are_database_backed_end_to_end():
    _reset_tables(DB_URL)
    _seed(DB_URL)
    client = _client(DB_URL)

    health = client.get("/agents/agentA/health")
    assert health.status_code == 200
    assert health.json()["score"] == 927

    history = client.get("/agents/agentA/history").json()
    assert [entry["epoch"] for entry in history["entries"]] == [31, 30]

    byzantine = client.get("/byzantine/recent").json()
    assert byzantine["flags"][0]["node"] == "oracle-node-2"

    cluster = client.get("/health/cluster").json()
    assert cluster["recent_epochs"][0]["byzantine_nodes"] == ["oracle-node-2"]
