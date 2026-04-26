"""
tests/scoring/test_score_engine.py — integration tests against testcontainers PG.

Covers the orchestrator that combines baseline + window + score persistence.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest
import pytest_asyncio

from scoring import baseline_engine, score_engine, score_repo
from scoring.engine import DEFAULT_WEIGHTS


UTC = timezone.utc


@pytest_asyncio.fixture
async def fully_seeded(db_pool, seeded_agent):
    """Agent + 100 baseline-window txs + 50 recent-window txs."""
    agent = seeded_agent
    now = datetime.now(tz=UTC)

    async with db_pool.acquire() as conn:
        # 100 txs spread over 30 days for baseline
        for i in range(100):
            day_offset = (i % 25) + 5  # days 5-29 ago
            block_time = now - timedelta(days=day_offset, hours=i)
            await conn.execute(
                """
                INSERT INTO agent_transactions
                    (agent_wallet, tx_signature, slot, block_time, success,
                     program_ids, sol_change, fee, raw_meta, source)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '{}'::jsonb, 'webhook')
                """,
                agent,
                f"BSL{i:04d}" + "x" * 80,
                100_000_000 + i,
                block_time,
                i % 10 != 0,                  # 90% success rate
                ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
                100_000 * (1 + i % 5),
                5000,
            )

        # 50 txs in last 7 days for window (so window stats can compute)
        for i in range(50):
            day_offset = i % 7
            block_time = now - timedelta(days=day_offset, hours=i)
            await conn.execute(
                """
                INSERT INTO agent_transactions
                    (agent_wallet, tx_signature, slot, block_time, success,
                     program_ids, sol_change, fee, raw_meta, source)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '{}'::jsonb, 'webhook')
                """,
                agent,
                f"WIN{i:04d}" + "x" * 80,
                200_000_000 + i,
                block_time,
                i % 10 != 0,                  # 90% success rate (matches baseline)
                ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
                100_000 * (1 + i % 5),
                5000,
            )

        # Compute baseline so it exists for the score_one call
        await baseline_engine.compute_and_store(conn, agent)

    return agent


# =============================================================================
# score_one
# =============================================================================

class TestScoreOne:

    @pytest.mark.asyncio
    async def test_writes_score_row(self, db_pool, fully_seeded):
        agent = fully_seeded
        async with db_pool.acquire() as conn:
            result = await score_engine.score_one(conn, agent)

        assert result is not None
        assert 0 <= result.score <= 1000
        assert result.alert in ("GREEN", "YELLOW", "RED")

        async with db_pool.acquire() as conn:
            row = await score_repo.get_full_current_score(conn, agent)
        assert row is not None
        assert row["score"] == result.score
        assert row["alert"] == result.alert

    @pytest.mark.asyncio
    async def test_appends_history_row(self, db_pool, fully_seeded):
        agent = fully_seeded
        async with db_pool.acquire() as conn:
            await score_engine.score_one(conn, agent)
            await score_engine.score_one(conn, agent)

        async with db_pool.acquire() as conn:
            count = await conn.fetchval(
                "SELECT COUNT(*) FROM agent_score_history WHERE agent_wallet = $1",
                agent,
            )
        assert count == 2

    @pytest.mark.asyncio
    async def test_overwrites_current_row(self, db_pool, fully_seeded):
        agent = fully_seeded
        async with db_pool.acquire() as conn:
            await score_engine.score_one(conn, agent)
            await score_engine.score_one(conn, agent)
            count = await conn.fetchval(
                "SELECT COUNT(*) FROM agent_scores WHERE agent_wallet = $1",
                agent,
            )
        assert count == 1

    @pytest.mark.asyncio
    async def test_returns_none_without_baseline(self, db_pool, seeded_agent):
        # Agent has no baseline
        async with db_pool.acquire() as conn:
            result = await score_engine.score_one(conn, seeded_agent)
        assert result is None

    @pytest.mark.asyncio
    async def test_guard_rail_applied_after_first_score(self, db_pool, fully_seeded):
        """Second score with same data shouldn't move much."""
        agent = fully_seeded

        async with db_pool.acquire() as conn:
            r1 = await score_engine.score_one(conn, agent)
            r2 = await score_engine.score_one(conn, agent)

        # Identical inputs → identical scores (within rounding)
        assert r1.score == r2.score


# =============================================================================
# Persistence + retrieval
# =============================================================================

class TestPersistence:

    @pytest.mark.asyncio
    async def test_get_current_score_returns_int(self, db_pool, fully_seeded):
        agent = fully_seeded
        async with db_pool.acquire() as conn:
            await score_engine.score_one(conn, agent)
            score = await score_repo.get_current_score(conn, agent)
        assert isinstance(score, int)
        assert 0 <= score <= 1000

    @pytest.mark.asyncio
    async def test_get_current_score_none_for_unknown(self, db_pool, seeded_agent):
        async with db_pool.acquire() as conn:
            score = await score_repo.get_current_score(conn, seeded_agent)
        assert score is None

    @pytest.mark.asyncio
    async def test_breakdown_persisted(self, db_pool, fully_seeded):
        agent = fully_seeded
        async with db_pool.acquire() as conn:
            result = await score_engine.score_one(conn, agent)
            row = await score_repo.get_full_current_score(conn, agent)

        assert row["success_rate_score"] == result.breakdown.success_rate_score
        assert row["consistency_score"]  == result.breakdown.consistency_score
        assert row["stability_score"]    == result.breakdown.stability_score
        assert row["raw_score"]          == result.breakdown.raw_score
        assert row["baseline_hash"]      == result.baseline_hash


# =============================================================================
# Day 7 hooks
# =============================================================================

class TestOnchainSync:

    @pytest.mark.asyncio
    async def test_unsynced_includes_new_score(self, db_pool, fully_seeded):
        agent = fully_seeded
        async with db_pool.acquire() as conn:
            await score_engine.score_one(conn, agent)
            unsynced = await score_repo.find_unsynced_scores(conn)
        assert agent in unsynced

    @pytest.mark.asyncio
    async def test_mark_onchain_removes_from_unsynced(self, db_pool, fully_seeded):
        agent = fully_seeded
        async with db_pool.acquire() as conn:
            await score_engine.score_one(conn, agent)
            await score_repo.mark_score_onchain(conn, agent, "TXSIG" + "z" * 80)
            unsynced = await score_repo.find_unsynced_scores(conn)
        assert agent not in unsynced

    @pytest.mark.asyncio
    async def test_mark_onchain_annotates_history(self, db_pool, fully_seeded):
        agent = fully_seeded
        sig = "TXSIG" + "z" * 80
        async with db_pool.acquire() as conn:
            await score_engine.score_one(conn, agent)
            await score_repo.mark_score_onchain(conn, agent, sig)
            row = await conn.fetchrow(
                """
                SELECT onchain_tx_signature
                FROM agent_score_history
                WHERE agent_wallet = $1
                ORDER BY computed_at DESC
                LIMIT 1
                """,
                agent,
            )
        assert row["onchain_tx_signature"] == sig


# =============================================================================
# Batch scoring
# =============================================================================

class TestBatch:

    @pytest.mark.asyncio
    async def test_score_all_due_processes_each(self, db_pool, fully_seeded):
        async with db_pool.acquire() as conn:
            outcomes = await score_engine.score_all_due(conn)
        assert fully_seeded in outcomes
        assert outcomes[fully_seeded] == "scored"
