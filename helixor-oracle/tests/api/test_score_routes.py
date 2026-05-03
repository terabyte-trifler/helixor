"""
tests/api/test_score_routes.py — integration tests for the API.

Uses testcontainers PG (from conftest.py) and FastAPI TestClient.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient


UTC = timezone.utc


@pytest_asyncio.fixture
async def app_client(db_pool, postgres_url, monkeypatch):
    """Spin up the FastAPI API app with a real DB pool."""
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.delenv("REDIS_URL", raising=False)

    from api import main
    from api.rate_limit import reset_rate_limiter
    from api.service import score_service
    from indexer import db

    db._pool = None
    score_service._cache.clear()  # fresh cache per test
    reset_rate_limiter()

    with TestClient(main.app) as client:
        yield client


@pytest_asyncio.fixture
async def scored_agent(db_pool, seeded_agent):
    """Inject a fully-scored agent into the DB."""
    agent = seeded_agent
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO agent_scores
              (agent_wallet, score, alert,
               success_rate_score, consistency_score, stability_score,
               raw_score, guard_rail_applied,
               window_success_rate, window_tx_count, window_sol_volatility,
               baseline_hash, baseline_algo_version,
               anomaly_flag, scoring_algo_version, weights_version,
               computed_at)
            VALUES ($1, 850, 'GREEN',
                    500, 300, 50, 850, FALSE,
                    0.97, 70, 1500000,
                    'abc' || repeat('0', 61), 1,
                    FALSE, 1, 1,
                    NOW())
            """,
            agent,
        )
    return agent


# =============================================================================
# Validation
# =============================================================================

class TestValidation:

    def test_invalid_pubkey_returns_400(self, app_client):
        r = app_client.get("/score/notavalidpubkey")
        assert r.status_code == 400
        assert r.json()["code"] == "INVALID_AGENT_WALLET"
        assert "request_id" in r.json()

    def test_pubkey_too_short_returns_400(self, app_client):
        r = app_client.get("/score/abc")
        assert r.status_code == 400

    def test_pubkey_with_special_chars_returns_400(self, app_client):
        r = app_client.get("/score/abc!def@ghi#jkl$mno%pqr^stu&vwx*yza+bcd-ef")
        assert r.status_code == 400


# =============================================================================
# 404 path
# =============================================================================

class TestNotFound:

    def test_unknown_agent_returns_404(self, app_client):
        # Valid base58 but not registered
        r = app_client.get("/score/AGENT11111111111111111111111111111111111111")
        assert r.status_code == 404
        assert r.json()["code"] == "AGENT_NOT_FOUND"


# =============================================================================
# Happy path
# =============================================================================

class TestHappyPath:

    @pytest.mark.asyncio
    async def test_scored_agent_returns_full_response(self, app_client, scored_agent):
        r = app_client.get(f"/score/{scored_agent}")
        assert r.status_code == 200

        body = r.json()
        assert body["agent_wallet"] == scored_agent
        assert body["score"]        == 850
        assert body["alert"]        == "GREEN"
        assert body["source"]       == "live"
        assert body["success_rate"] == 97.0
        assert body["anomaly_flag"] is False
        assert body["is_fresh"]     is True
        assert body["cached"]       is False  # first hit
        assert "served_at"          in body
        assert body["breakdown"]["success_rate_score"] == 500
        assert body["breakdown"]["consistency_score"]  == 300
        assert body["breakdown"]["stability_score"]    == 50

    @pytest.mark.asyncio
    async def test_provisional_for_registered_unscored(self, app_client, seeded_agent):
        # seeded_agent is registered but has no agent_scores row
        r = app_client.get(f"/score/{seeded_agent}")
        assert r.status_code == 200
        body = r.json()
        assert body["score"]   == 500
        assert body["alert"]   == "YELLOW"
        assert body["source"]  == "provisional"
        assert body["is_fresh"] is False
        assert body["updated_at"] == 0


# =============================================================================
# Caching
# =============================================================================

class TestCaching:

    @pytest.mark.asyncio
    async def test_second_request_is_cached(self, app_client, scored_agent):
        r1 = app_client.get(f"/score/{scored_agent}")
        assert r1.json()["cached"] is False

        r2 = app_client.get(f"/score/{scored_agent}")
        assert r2.json()["cached"] is True

    @pytest.mark.asyncio
    async def test_force_refresh_bypasses_cache(self, app_client, scored_agent):
        app_client.get(f"/score/{scored_agent}")  # warm cache
        r = app_client.get(f"/score/{scored_agent}?force_refresh=true")
        assert r.json()["cached"] is False


# =============================================================================
# Headers + request id
# =============================================================================

class TestHeaders:

    def test_response_time_header_present(self, app_client):
        r = app_client.get("/health")
        assert "x-response-time" in {k.lower() for k in r.headers}

    def test_request_id_header_present(self, app_client):
        r = app_client.get("/health")
        assert "x-request-id" in {k.lower() for k in r.headers}

    def test_request_id_echoed_when_provided(self, app_client):
        r = app_client.get("/health", headers={"X-Request-ID": "test-12345"})
        assert r.headers["x-request-id"] == "test-12345"


# =============================================================================
# Rate limit
# =============================================================================

class TestRateLimit:

    def test_high_burst_returns_429(self, app_client):
        # Default capacity 100 — issue 200 quickly to trigger 429
        seen_429 = False
        for _ in range(200):
            r = app_client.get("/score/AGENT11111111111111111111111111111111111111")
            if r.status_code == 429:
                seen_429 = True
                assert r.json()["code"] == "RATE_LIMITED"
                assert "retry-after" in {k.lower() for k in r.headers}
                break
        assert seen_429, "Expected at least one 429 in 200 quick requests"


# =============================================================================
# Listing
# =============================================================================

class TestListing:

    @pytest.mark.asyncio
    async def test_list_empty(self, app_client, db_pool):
        # Truncated by fixture
        r = app_client.get("/agents")
        assert r.status_code == 200
        body = r.json()
        assert body["items"] == []
        assert body["total"] == 0

    @pytest.mark.asyncio
    async def test_list_with_one_agent(self, app_client, scored_agent):
        r = app_client.get("/agents")
        body = r.json()
        assert body["total"] == 1
        assert len(body["items"]) == 1
        assert body["items"][0]["score"] == 850

    @pytest.mark.asyncio
    async def test_list_pagination(self, app_client, scored_agent):
        r = app_client.get("/agents?limit=10&offset=0")
        assert r.status_code == 200
        assert r.json()["limit"] == 10


# =============================================================================
# Operational
# =============================================================================

class TestOperational:

    def test_health_returns_ok(self, app_client):
        r = app_client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_status_reports_db_reachable(self, app_client):
        r = app_client.get("/status")
        body = r.json()
        assert body["status"] == "ok"
        assert body["db_reachable"] is True
        assert "uptime_seconds" in body

    def test_metrics_returns_prometheus_format(self, app_client):
        r = app_client.get("/metrics")
        assert r.status_code == 200
        assert "helixor_api_uptime_seconds" in r.text
        assert "helixor_api_cache_hit_rate" in r.text


# =============================================================================
# Error envelope
# =============================================================================

class TestErrorEnvelope:

    def test_404_includes_request_id(self, app_client):
        r = app_client.get("/score/AGENT11111111111111111111111111111111111111")
        body = r.json()
        assert "request_id" in body
        assert "code" in body
        assert "error" in body

    def test_400_includes_request_id(self, app_client):
        r = app_client.get("/score/badpubkey")
        body = r.json()
        assert "request_id" in body
        assert body["code"] == "INVALID_AGENT_WALLET"
