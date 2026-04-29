"""
tests/monitoring/test_alert_state.py — alert deduplication tests.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from monitoring.alert_state import (
    COOLDOWN_BY_SEVERITY,
    evaluate,
    record_slo_sample,
)
from monitoring.types import CheckResult


@pytest_asyncio.fixture
async def reset_alert_state(db_pool):
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM monitoring_alerts")
        await conn.execute("DELETE FROM monitoring_alert_state")
        await conn.execute("DELETE FROM monitoring_slo_samples")
    yield


# =============================================================================
# Healthy path
# =============================================================================

class TestHealthyPath:

    @pytest.mark.asyncio
    async def test_healthy_check_no_state_returns_none(self, db_pool, reset_alert_state):
        result = CheckResult(name="x", healthy=True)
        async with db_pool.acquire() as conn:
            decision = await evaluate(conn, result)
        assert decision is None

    @pytest.mark.asyncio
    async def test_healthy_after_failure_emits_resolution(self, db_pool, reset_alert_state):
        bad  = CheckResult(name="x", healthy=False, severity="warning",
                           title="bad", body="things")
        good = CheckResult(name="x", healthy=True)

        async with db_pool.acquire() as conn:
            d1 = await evaluate(conn, bad)
            d2 = await evaluate(conn, good)

        assert d1 is not None and d1.is_new
        assert d2 is not None
        assert d2.is_resolution
        assert d2.severity == "info"


# =============================================================================
# Dedup + cooldown
# =============================================================================

class TestDedup:

    @pytest.mark.asyncio
    async def test_first_unhealthy_notifies(self, db_pool, reset_alert_state):
        result = CheckResult(name="x", healthy=False, severity="warning",
                             title="t", body="b")
        async with db_pool.acquire() as conn:
            d = await evaluate(conn, result)
        assert d is not None
        assert d.is_new
        assert d.should_notify

    @pytest.mark.asyncio
    async def test_immediate_repeat_does_not_notify(self, db_pool, reset_alert_state):
        result = CheckResult(name="x", healthy=False, severity="warning",
                             title="t", body="b")
        async with db_pool.acquire() as conn:
            await evaluate(conn, result)
            d2 = await evaluate(conn, result)
        # within cooldown, no second notify
        assert d2 is not None
        assert not d2.is_new
        assert not d2.should_notify
        assert d2.fire_count == 2

    @pytest.mark.asyncio
    async def test_critical_uses_shorter_cooldown(self):
        assert COOLDOWN_BY_SEVERITY["critical"] < COOLDOWN_BY_SEVERITY["warning"]

    @pytest.mark.asyncio
    async def test_resolution_after_repeat_works(self, db_pool, reset_alert_state):
        bad  = CheckResult(name="x", healthy=False, severity="warning",
                           title="t", body="b")
        good = CheckResult(name="x", healthy=True)

        async with db_pool.acquire() as conn:
            await evaluate(conn, bad)
            await evaluate(conn, bad)   # repeat (suppressed)
            d3 = await evaluate(conn, good)

        assert d3 is not None
        assert d3.is_resolution


# =============================================================================
# Different keys = independent alerts
# =============================================================================

class TestIndependentKeys:

    @pytest.mark.asyncio
    async def test_two_keys_get_two_notifications(self, db_pool, reset_alert_state):
        a = CheckResult(name="checkA", key="k_a", healthy=False, severity="warning",
                        title="A", body="b")
        b = CheckResult(name="checkB", key="k_b", healthy=False, severity="warning",
                        title="B", body="b")
        async with db_pool.acquire() as conn:
            d1 = await evaluate(conn, a)
            d2 = await evaluate(conn, b)
        assert d1.should_notify and d1.is_new
        assert d2.should_notify and d2.is_new


# =============================================================================
# SLO samples persisted
# =============================================================================

class TestSloSamples:

    @pytest.mark.asyncio
    async def test_record_slo_inserts(self, db_pool, reset_alert_state):
        result = CheckResult(name="api_latency", healthy=True, value_ms=42)
        async with db_pool.acquire() as conn:
            await record_slo_sample(conn, result)
            n = await conn.fetchval(
                "SELECT COUNT(*) FROM monitoring_slo_samples WHERE check_name = $1",
                "api_latency",
            )
        assert n == 1
