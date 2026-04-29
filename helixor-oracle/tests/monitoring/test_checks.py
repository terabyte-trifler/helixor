"""
tests/monitoring/test_checks.py — check functions return correct CheckResult.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from monitoring.checks import system_checks, agent_checks


@pytest_asyncio.fixture
async def reset_data(db_pool):
    async with db_pool.acquire() as conn:
        await conn.execute("TRUNCATE webhook_events RESTART IDENTITY CASCADE")
        await conn.execute("DELETE FROM agent_scores")
        await conn.execute("DELETE FROM monitored_agents")


# =============================================================================
# Webhook freshness
# =============================================================================

class TestWebhookFreshness:

    @pytest.mark.asyncio
    async def test_no_events_unhealthy(self, db_pool, reset_data):
        async with db_pool.acquire() as conn:
            r = await system_checks.check_webhook_freshness(conn)
        assert not r.healthy

    @pytest.mark.asyncio
    async def test_recent_event_healthy(self, db_pool, reset_data):
        async with db_pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO webhook_events
                    (received_at, request_id, tx_count, inserted_count, skipped_count, duration_ms)
                VALUES (NOW(), 'test1', 1, 1, 0, 5)
            """)
            r = await system_checks.check_webhook_freshness(conn)
        assert r.healthy

    @pytest.mark.asyncio
    async def test_old_event_unhealthy(self, db_pool, reset_data):
        async with db_pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO webhook_events
                    (received_at, request_id, tx_count, inserted_count, skipped_count, duration_ms)
                VALUES (NOW() - INTERVAL '3 hours', 'old1', 1, 1, 0, 5)
            """)
            r = await system_checks.check_webhook_freshness(conn, max_age_minutes=60)
        assert not r.healthy
        assert "180min" in r.body or "3" in r.title


# =============================================================================
# Epoch freshness
# =============================================================================

class TestEpochFreshness:

    @pytest.mark.asyncio
    async def test_never_synced_critical(self, db_pool, reset_data):
        async with db_pool.acquire() as conn:
            r = await system_checks.check_epoch_freshness(conn)
        assert not r.healthy
        assert r.severity == "critical"

    @pytest.mark.asyncio
    async def test_recent_sync_healthy(self, db_pool, reset_data, seeded_agent):
        async with db_pool.acquire() as conn:
            await _insert_score(conn, seeded_agent, written_at_offset_hours=2)
            r = await system_checks.check_epoch_freshness(conn)
        assert r.healthy

    @pytest.mark.asyncio
    async def test_old_sync_critical(self, db_pool, reset_data, seeded_agent):
        async with db_pool.acquire() as conn:
            await _insert_score(conn, seeded_agent, written_at_offset_hours=30)
            r = await system_checks.check_epoch_freshness(conn, max_age_hours=26)
        assert not r.healthy
        assert r.severity == "critical"


# =============================================================================
# Per-agent score check
# =============================================================================

class TestAgentScoreFresh:

    @pytest.mark.asyncio
    async def test_no_score_unhealthy_warning(self, db_pool, reset_data, seeded_agent):
        async with db_pool.acquire() as conn:
            r = await agent_checks.check_agent_score_fresh(
                conn, seeded_agent, "test-agent",
            )
        assert not r.healthy
        assert r.severity == "warning"
        assert r.key == f"agent_score_stale:{seeded_agent}"

    @pytest.mark.asyncio
    async def test_fresh_score_healthy(self, db_pool, reset_data, seeded_agent):
        async with db_pool.acquire() as conn:
            await _insert_score(conn, seeded_agent, written_at_offset_hours=1)
            r = await agent_checks.check_agent_score_fresh(
                conn, seeded_agent, "test-agent",
            )
        assert r.healthy
        assert "1.0h" in r.body or "score" in r.body.lower()


# =============================================================================
# Agent score floor
# =============================================================================

class TestAgentScoreFloor:

    @pytest.mark.asyncio
    async def test_above_floor_healthy(self, db_pool, reset_data, seeded_agent):
        async with db_pool.acquire() as conn:
            await _insert_score(conn, seeded_agent, score=800)
            r = await agent_checks.check_agent_score_floor(
                conn, seeded_agent, "test", 600,
            )
        assert r.healthy

    @pytest.mark.asyncio
    async def test_below_floor_warning(self, db_pool, reset_data, seeded_agent):
        async with db_pool.acquire() as conn:
            await _insert_score(conn, seeded_agent, score=550)
            r = await agent_checks.check_agent_score_floor(
                conn, seeded_agent, "test", 600,
            )
        assert not r.healthy
        assert r.severity == "warning"

    @pytest.mark.asyncio
    async def test_far_below_floor_critical(self, db_pool, reset_data, seeded_agent):
        async with db_pool.acquire() as conn:
            await _insert_score(conn, seeded_agent, score=200)
            r = await agent_checks.check_agent_score_floor(
                conn, seeded_agent, "test", 600,
            )
        assert not r.healthy
        assert r.severity == "critical"

    @pytest.mark.asyncio
    async def test_no_floor_skips(self, db_pool, reset_data, seeded_agent):
        async with db_pool.acquire() as conn:
            r = await agent_checks.check_agent_score_floor(
                conn, seeded_agent, "test", None,
            )
        assert r.healthy


# =============================================================================
# Helper
# =============================================================================

async def _insert_score(
    conn,
    agent: str,
    *,
    score: int = 800,
    written_at_offset_hours: float = 1.0,
):
    written_at = datetime.now(tz=timezone.utc) - timedelta(hours=written_at_offset_hours)
    await conn.execute(
        """
        INSERT INTO agent_scores (
            agent_wallet, score, alert,
            success_rate_score, consistency_score, stability_score,
            raw_score, guard_rail_applied,
            window_success_rate, window_tx_count, window_sol_volatility,
            baseline_hash, baseline_algo_version,
            anomaly_flag, scoring_algo_version, weights_version,
            computed_at, written_onchain_at
        ) VALUES (
            $1, $2,
            CASE WHEN $2 >= 700 THEN 'GREEN'
                 WHEN $2 >= 400 THEN 'YELLOW' ELSE 'RED' END,
            500, 200, 100, $2, FALSE, 0.95, 50, 1000000,
            'abc' || repeat('0', 61), 1,
            FALSE, 1, 1, $3, $3
        )
        ON CONFLICT (agent_wallet) DO UPDATE SET
            score              = EXCLUDED.score,
            alert              = EXCLUDED.alert,
            written_onchain_at = EXCLUDED.written_onchain_at,
            computed_at        = EXCLUDED.computed_at
        """,
        agent, score, written_at,
    )
