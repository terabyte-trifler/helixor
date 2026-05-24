"""
api/_timescale.py — production read repositories.

This is the Day-31 gap closer that turns the read API from a Swagger
surface into a real database-backed service. The route layer depends on
small repository protocols; this module implements those protocols over
Postgres/TimescaleDB.

The adapter is intentionally Postgres-first and Timescale-compatible:
it works against plain Postgres in local CI, and opportunistically creates
hypertables when TimescaleDB is installed. That keeps the local audit gate
honest without making every developer run the Timescale extension.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any

import psycopg2
import psycopg2.extras

from api.byzantine_repo import (
    ByzantineFlagRecord,
    ChallengeRecord,
    NodeRevealRecord,
    StrikeSummary,
)
from api.cluster_health import EpochSummary, NodeHeartbeat
from api.score_repo import ScoreRecord


ALERT_TO_TIER = {
    "GREEN": 0,
    "YELLOW": 1,
    "ORANGE": 1,
    "RED": 2,
}


READ_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS agent_score_history (
    id BIGSERIAL PRIMARY KEY,
    agent_wallet TEXT NOT NULL,
    epoch BIGINT,
    score INTEGER NOT NULL,
    alert TEXT DEFAULT 'YELLOW',
    alert_tier SMALLINT,
    success_rate_score INTEGER DEFAULT 0,
    consistency_score INTEGER DEFAULT 0,
    stability_score INTEGER DEFAULT 0,
    raw_score INTEGER DEFAULT 0,
    guard_rail_applied BOOLEAN DEFAULT FALSE,
    window_success_rate DOUBLE PRECISION DEFAULT 0,
    window_tx_count INTEGER DEFAULT 0,
    window_sol_volatility DOUBLE PRECISION DEFAULT 0,
    baseline_hash TEXT DEFAULT '',
    baseline_algo_version TEXT DEFAULT '',
    anomaly_flag BOOLEAN DEFAULT FALSE,
    scoring_algo_version TEXT DEFAULT '',
    weights_version TEXT DEFAULT '',
    flags INTEGER NOT NULL DEFAULT 0,
    immediate_red BOOLEAN NOT NULL DEFAULT FALSE,
    signer_count INTEGER NOT NULL DEFAULT 3,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    onchain_tx_signature TEXT
);

ALTER TABLE agent_score_history ADD COLUMN IF NOT EXISTS epoch BIGINT;
ALTER TABLE agent_score_history ADD COLUMN IF NOT EXISTS alert_tier SMALLINT;
ALTER TABLE agent_score_history ADD COLUMN IF NOT EXISTS flags INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agent_score_history ADD COLUMN IF NOT EXISTS immediate_red BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE agent_score_history ADD COLUMN IF NOT EXISTS signer_count INTEGER NOT NULL DEFAULT 3;
ALTER TABLE agent_score_history ADD COLUMN IF NOT EXISTS computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
CREATE INDEX IF NOT EXISTS idx_agent_score_history_agent_epoch
    ON agent_score_history (agent_wallet, epoch DESC NULLS LAST, id DESC);
CREATE INDEX IF NOT EXISTS idx_agent_score_history_computed_at
    ON agent_score_history (computed_at DESC);

CREATE TABLE IF NOT EXISTS byzantine_flags (
    id BIGSERIAL PRIMARY KEY,
    node_id TEXT NOT NULL,
    epoch BIGINT NOT NULL,
    subject_agent TEXT NOT NULL,
    accused_score INTEGER NOT NULL,
    cluster_median INTEGER NOT NULL,
    deviation DOUBLE PRECISION NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_byzantine_flags_epoch
    ON byzantine_flags (epoch DESC, node_id);

CREATE TABLE IF NOT EXISTS oracle_node_reveals (
    id BIGSERIAL PRIMARY KEY,
    node_id TEXT NOT NULL,
    epoch BIGINT NOT NULL,
    agent_wallet TEXT NOT NULL,
    score INTEGER NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_oracle_node_reveals_lookup
    ON oracle_node_reveals (epoch, agent_wallet, node_id);

CREATE TABLE IF NOT EXISTS oracle_challenges (
    challenge_index BIGINT NOT NULL,
    accused_node TEXT NOT NULL,
    proof_type SMALLINT NOT NULL,
    subject_epoch BIGINT NOT NULL,
    subject_agent TEXT NOT NULL,
    accused_score INTEGER NOT NULL,
    cluster_median INTEGER NOT NULL,
    evidence_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    filed_at BIGINT NOT NULL,
    PRIMARY KEY (accused_node, challenge_index)
);

CREATE TABLE IF NOT EXISTS oracle_heartbeats (
    node_id TEXT PRIMARY KEY,
    last_seen_unix BIGINT NOT NULL,
    epoch BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS epoch_submission_log (
    epoch BIGINT PRIMARY KEY,
    submitted_count INTEGER NOT NULL,
    agent_count INTEGER NOT NULL,
    verified_nodes TEXT[] NOT NULL DEFAULT '{}',
    byzantine_nodes TEXT[] NOT NULL DEFAULT '{}',
    unreachable_nodes TEXT[] NOT NULL DEFAULT '{}',
    elapsed_seconds DOUBLE PRECISION NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_epoch_submission_log_computed_at
    ON epoch_submission_log (computed_at DESC);
"""


TIMESCALE_OPTIONAL_SQL = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM create_hypertable(
            'agent_score_history',
            'computed_at',
            if_not_exists => TRUE,
            migrate_data => TRUE
        );
        PERFORM create_hypertable(
            'byzantine_flags',
            'computed_at',
            if_not_exists => TRUE,
            migrate_data => TRUE
        );
        PERFORM create_hypertable(
            'oracle_node_reveals',
            'computed_at',
            if_not_exists => TRUE,
            migrate_data => TRUE
        );
        PERFORM create_hypertable(
            'epoch_submission_log',
            'computed_at',
            if_not_exists => TRUE,
            migrate_data => TRUE
        );
    END IF;
END $$;
"""


def ensure_read_schema(db_url: str) -> None:
    """Create the read-side tables if they do not exist.

    This is safe to run on every service start: all DDL is idempotent.
    Production migrations can still manage these tables explicitly; the
    adapter keeps devnet/canary deployments from serving fake empty data
    just because a table was not created yet.
    """
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(READ_SCHEMA_SQL)
            cur.execute(TIMESCALE_OPTIONAL_SQL)


@contextlib.contextmanager
def _dict_conn(db_url: str) -> Iterator[Any]:
    conn = psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        yield conn
    finally:
        conn.close()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _alert_tier(row: dict[str, Any]) -> int:
    explicit = row.get("alert_tier")
    if explicit is not None:
        return int(explicit)
    label = str(row.get("alert") or "YELLOW").upper()
    return ALERT_TO_TIER.get(label, 1)


def _score_record(row: dict[str, Any]) -> ScoreRecord:
    return ScoreRecord(
        agent_wallet=str(row["agent_wallet"]),
        epoch=int(row["epoch"]),
        score=int(row["score"]),
        alert_tier=_alert_tier(row),
        flags=int(row.get("flags") or 0),
        immediate_red=bool(row.get("immediate_red")),
        signer_count=int(row.get("signer_count") or 1),
        computed_at=_as_utc(row["computed_at"]),
    )


class TimescaleScoreRepo:
    def __init__(self, db_url: str) -> None:
        self._db_url = db_url

    def latest_score(self, agent_wallet: str) -> ScoreRecord | None:
        with _dict_conn(self._db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT agent_wallet,
                           COALESCE(epoch, id)::BIGINT AS epoch,
                           score, alert, alert_tier, flags, immediate_red,
                           signer_count, computed_at
                    FROM agent_score_history
                    WHERE agent_wallet = %s
                    ORDER BY COALESCE(epoch, id) DESC, computed_at DESC, id DESC
                    LIMIT 1
                    """,
                    (agent_wallet,),
                )
                row = cur.fetchone()
                return _score_record(row) if row else None

    def score_at_epoch(self, agent_wallet: str, epoch: int) -> ScoreRecord | None:
        with _dict_conn(self._db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT agent_wallet,
                           COALESCE(epoch, id)::BIGINT AS epoch,
                           score, alert, alert_tier, flags, immediate_red,
                           signer_count, computed_at
                    FROM agent_score_history
                    WHERE agent_wallet = %s
                      AND COALESCE(epoch, id) = %s
                    ORDER BY computed_at DESC, id DESC
                    LIMIT 1
                    """,
                    (agent_wallet, epoch),
                )
                row = cur.fetchone()
                return _score_record(row) if row else None

    def score_history(
        self,
        agent_wallet: str,
        *,
        from_epoch: int | None = None,
        to_epoch: int | None = None,
        limit: int = 100,
    ) -> list[ScoreRecord]:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if limit > 1000:
            raise ValueError("limit must be <= 1000")

        clauses = ["agent_wallet = %s"]
        params: list[Any] = [agent_wallet]
        if from_epoch is not None:
            clauses.append("COALESCE(epoch, id) >= %s")
            params.append(from_epoch)
        if to_epoch is not None:
            clauses.append("COALESCE(epoch, id) <= %s")
            params.append(to_epoch)
        params.append(limit)

        with _dict_conn(self._db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT agent_wallet,
                           COALESCE(epoch, id)::BIGINT AS epoch,
                           score, alert, alert_tier, flags, immediate_red,
                           signer_count, computed_at
                    FROM agent_score_history
                    WHERE {' AND '.join(clauses)}
                    ORDER BY COALESCE(epoch, id) DESC, computed_at DESC, id DESC
                    LIMIT %s
                    """,
                    tuple(params),
                )
                return [_score_record(row) for row in cur.fetchall()]

    def known_agents(self) -> list[str]:
        with _dict_conn(self._db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT DISTINCT agent_wallet
                    FROM agent_score_history
                    ORDER BY agent_wallet
                    """
                )
                return [str(row["agent_wallet"]) for row in cur.fetchall()]


class TimescaleByzantineRepo:
    def __init__(self, db_url: str) -> None:
        self._db_url = db_url

    def recent_flags(
        self, *, since_epoch: int | None = None, limit: int = 100,
    ) -> list[ByzantineFlagRecord]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit out of bounds")
        clauses: list[str] = []
        params: list[Any] = []
        if since_epoch is not None:
            clauses.append("epoch >= %s")
            params.append(since_epoch)
        params.append(limit)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with _dict_conn(self._db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT node_id, epoch, subject_agent, accused_score,
                           cluster_median, deviation
                    FROM byzantine_flags
                    {where_sql}
                    ORDER BY epoch DESC, node_id
                    LIMIT %s
                    """,
                    tuple(params),
                )
                return [
                    ByzantineFlagRecord(
                        node_id=str(row["node_id"]),
                        epoch=int(row["epoch"]),
                        subject_agent=str(row["subject_agent"]),
                        accused_score=int(row["accused_score"]),
                        cluster_median=int(row["cluster_median"]),
                        deviation=float(row["deviation"]),
                    )
                    for row in cur.fetchall()
                ]

    def strike_summary(self) -> list[StrikeSummary]:
        with _dict_conn(self._db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT f.node_id,
                           COUNT(*)::INTEGER AS strikes,
                           ARRAY_AGG(f.epoch ORDER BY f.epoch)::BIGINT[] AS flagged_epochs,
                           EXISTS (
                               SELECT 1
                               FROM oracle_challenges c
                               WHERE c.accused_node = f.node_id
                           ) AS challenged
                    FROM byzantine_flags f
                    GROUP BY f.node_id
                    ORDER BY f.node_id
                    """
                )
                return [
                    StrikeSummary(
                        node_id=str(row["node_id"]),
                        strikes=int(row["strikes"]),
                        flagged_epochs=tuple(int(e) for e in row["flagged_epochs"]),
                        challenged=bool(row["challenged"]),
                    )
                    for row in cur.fetchall()
                ]

    def per_node_reveals(
        self, *, epoch: int, agent_wallet: str,
    ) -> list[NodeRevealRecord]:
        with _dict_conn(self._db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT node_id, epoch, agent_wallet, score
                    FROM oracle_node_reveals
                    WHERE epoch = %s AND agent_wallet = %s
                    ORDER BY node_id
                    """,
                    (epoch, agent_wallet),
                )
                return [
                    NodeRevealRecord(
                        node_id=str(row["node_id"]),
                        epoch=int(row["epoch"]),
                        agent_wallet=str(row["agent_wallet"]),
                        score=int(row["score"]),
                    )
                    for row in cur.fetchall()
                ]

    def challenges_for(self, node_id: str) -> list[ChallengeRecord]:
        with _dict_conn(self._db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT challenge_index, accused_node, proof_type,
                           subject_epoch, subject_agent, accused_score,
                           cluster_median, evidence_hash, status, filed_at
                    FROM oracle_challenges
                    WHERE accused_node = %s
                    ORDER BY challenge_index DESC
                    """,
                    (node_id,),
                )
                return [
                    ChallengeRecord(
                        challenge_index=int(row["challenge_index"]),
                        accused_node=str(row["accused_node"]),
                        proof_type=int(row["proof_type"]),
                        subject_epoch=int(row["subject_epoch"]),
                        subject_agent=str(row["subject_agent"]),
                        accused_score=int(row["accused_score"]),
                        cluster_median=int(row["cluster_median"]),
                        evidence_hash=str(row["evidence_hash"]),
                        status=str(row["status"]),
                        filed_at=int(row["filed_at"]),
                    )
                    for row in cur.fetchall()
                ]


class TimescaleClusterHealthRepo:
    def __init__(self, db_url: str) -> None:
        self._db_url = db_url

    def heartbeats(self) -> list[NodeHeartbeat]:
        with _dict_conn(self._db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT node_id, last_seen_unix, epoch
                    FROM oracle_heartbeats
                    ORDER BY node_id
                    """
                )
                return [
                    NodeHeartbeat(
                        node_id=str(row["node_id"]),
                        last_seen_unix=int(row["last_seen_unix"]),
                        epoch=int(row["epoch"]),
                    )
                    for row in cur.fetchall()
                ]

    def recent_epochs(self, *, limit: int = 10) -> list[EpochSummary]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit out of bounds")
        with _dict_conn(self._db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT epoch, submitted_count, agent_count, verified_nodes,
                           byzantine_nodes, unreachable_nodes, elapsed_seconds,
                           computed_at
                    FROM epoch_submission_log
                    ORDER BY epoch DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                return [
                    EpochSummary(
                        epoch=int(row["epoch"]),
                        submitted_count=int(row["submitted_count"]),
                        agent_count=int(row["agent_count"]),
                        verified_nodes=tuple(row["verified_nodes"] or ()),
                        byzantine_nodes=tuple(row["byzantine_nodes"] or ()),
                        unreachable_nodes=tuple(row["unreachable_nodes"] or ()),
                        elapsed_seconds=float(row["elapsed_seconds"]),
                        computed_at=_as_utc(row["computed_at"]),
                    )
                    for row in cur.fetchall()
                ]


def open_repos(db_url: str, *, ensure_schema: bool = True):
    if ensure_schema:
        ensure_read_schema(db_url)
    return (
        TimescaleScoreRepo(db_url),
        TimescaleByzantineRepo(db_url),
        TimescaleClusterHealthRepo(db_url),
    )
