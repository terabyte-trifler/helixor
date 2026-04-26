"""
tests/scoring/test_baseline_engine.py — integration tests against testcontainers PG.

Covers the orchestrator that combines signal compute + DB persistence.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from scoring import baseline_engine, repo


UTC = timezone.utc


@pytest_asyncio.fixture
async def seeded_with_50_tx(db_pool):
    """Insert 50 txs across 5 active days for a dedicated baseline agent."""
    agent = "AGENT22222222222222222222222222222222222222"
    now = datetime.now(tz=UTC)

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO registered_agents
                (agent_wallet, owner_wallet, name, registration_pda,
                 registered_at, onchain_signature, active)
            VALUES ($1, $2, $3, $4, $5, $6, TRUE)
            """,
            agent,
            "OWNER22222222222222222222222222222222222222",
            "baseline-agent",
            "REGPDA22222222222222222222222222222222222222",
            now,
            "SIG22222222222222222222222222222222222222222",
        )
        for i in range(50):
            day_offset = i % 5
            block_time = now - timedelta(days=day_offset, hours=i)
            await conn.execute(
                """
                INSERT INTO agent_transactions
                    (agent_wallet, tx_signature, slot, block_time, success,
                     program_ids, sol_change, fee, raw_meta, source)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, 'webhook')
                """,
                agent,
                f"SIG{i:04d}" + "x" * 80,
                100_000_000 + i,
                block_time,
                i % 7 != 0,                           # ~85% success rate
                ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
                100 * (1 + i % 3),                   # varying sol flow
                5000,
                "{}",
            )
    return agent


# =============================================================================
# Compute + store
# =============================================================================

class TestComputeAndStore:

    @pytest.mark.asyncio
    async def test_writes_baseline_row(self, db_pool, seeded_with_50_tx):
        agent = seeded_with_50_tx

        async with db_pool.acquire() as conn:
            result = await baseline_engine.compute_and_store(conn, agent)

        assert result.tx_count == 50
        assert 0 < result.signals.success_rate <= 1.0
        assert result.signals.median_daily_tx >= 1

        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM agent_baselines WHERE agent_wallet = $1", agent,
            )
        assert row is not None
        assert row["tx_count"] == 50
        assert row["baseline_hash"] == result.baseline_hash

    @pytest.mark.asyncio
    async def test_appends_history_row(self, db_pool, seeded_with_50_tx):
        agent = seeded_with_50_tx

        # Compute twice
        async with db_pool.acquire() as conn:
            await baseline_engine.compute_and_store(conn, agent)
            await baseline_engine.compute_and_store(conn, agent)

        async with db_pool.acquire() as conn:
            count = await conn.fetchval(
                "SELECT COUNT(*) FROM agent_baseline_history WHERE agent_wallet = $1",
                agent,
            )
        assert count == 2

    @pytest.mark.asyncio
    async def test_recompute_overwrites_current_row(self, db_pool, seeded_with_50_tx):
        agent = seeded_with_50_tx

        async with db_pool.acquire() as conn:
            await baseline_engine.compute_and_store(conn, agent)
            count_after_first = await conn.fetchval(
                "SELECT COUNT(*) FROM agent_baselines WHERE agent_wallet = $1", agent,
            )

            await baseline_engine.compute_and_store(conn, agent)
            count_after_second = await conn.fetchval(
                "SELECT COUNT(*) FROM agent_baselines WHERE agent_wallet = $1", agent,
            )

        # Still exactly one row in the current table
        assert count_after_first  == 1
        assert count_after_second == 1

    @pytest.mark.asyncio
    async def test_insufficient_data_raises(self, db_pool, seeded_agent):
        # No transactions seeded
        async with db_pool.acquire() as conn:
            from scoring.signals import InsufficientData
            with pytest.raises(InsufficientData):
                await baseline_engine.compute_and_store(conn, seeded_agent)

        # No baseline row created
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM agent_baselines WHERE agent_wallet = $1", seeded_agent,
            )
        assert row is None


# =============================================================================
# get_or_compute caching
# =============================================================================

class TestGetOrCompute:

    @pytest.mark.asyncio
    async def test_first_call_computes(self, db_pool, seeded_with_50_tx):
        agent = seeded_with_50_tx
        async with db_pool.acquire() as conn:
            result = await baseline_engine.get_or_compute(conn, agent)
        assert result is not None

    @pytest.mark.asyncio
    async def test_second_call_uses_cache(self, db_pool, seeded_with_50_tx):
        agent = seeded_with_50_tx

        async with db_pool.acquire() as conn:
            r1 = await baseline_engine.get_or_compute(conn, agent)

            # Get computed_at — second call should return the SAME row,
            # so computed_at shouldn't change
            ca1 = await conn.fetchval(
                "SELECT computed_at FROM agent_baselines WHERE agent_wallet = $1",
                agent,
            )

            r2 = await baseline_engine.get_or_compute(conn, agent)
            ca2 = await conn.fetchval(
                "SELECT computed_at FROM agent_baselines WHERE agent_wallet = $1",
                agent,
            )

        assert r1.baseline_hash == r2.baseline_hash
        assert ca1 == ca2  # not recomputed

    @pytest.mark.asyncio
    async def test_returns_none_if_uncomputable(self, db_pool, seeded_agent):
        # Agent registered but no txs
        async with db_pool.acquire() as conn:
            result = await baseline_engine.get_or_compute(conn, seeded_agent)
        assert result is None


# =============================================================================
# Repo: stale + missing detection
# =============================================================================

class TestRepoFunctions:

    @pytest.mark.asyncio
    async def test_find_agents_without_baseline(self, db_pool, seeded_agent):
        # Agent is registered but no baseline yet
        async with db_pool.acquire() as conn:
            missing = await repo.find_agents_without_baseline(conn)
        assert seeded_agent in missing

    @pytest.mark.asyncio
    async def test_find_stale_baselines(self, db_pool, seeded_with_50_tx):
        agent = seeded_with_50_tx

        async with db_pool.acquire() as conn:
            await baseline_engine.compute_and_store(
                conn, agent, valid_for_seconds=1,
            )

        # Wait a moment for valid_until to be in the past
        import asyncio
        await asyncio.sleep(2)

        async with db_pool.acquire() as conn:
            stale = await repo.find_stale_baselines(conn)
        assert agent in stale


# =============================================================================
# Batch recompute
# =============================================================================

class TestBatchRecompute:

    @pytest.mark.asyncio
    async def test_batch_collects_outcomes(self, db_pool, seeded_agent, seeded_with_50_tx):
        async with db_pool.acquire() as conn:
            outcomes = await baseline_engine.batch_recompute(
                conn, [seeded_agent, seeded_with_50_tx],
            )

        # seeded_agent has no tx → insufficient_tx
        # seeded_with_50_tx has 50 → computed
        assert outcomes[seeded_agent]      == "insufficient_tx"
        assert outcomes[seeded_with_50_tx] == "computed"
