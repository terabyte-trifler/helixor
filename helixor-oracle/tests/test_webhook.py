"""
tests/test_webhook.py — integration tests for the FastAPI webhook receiver.

Uses testcontainers PostgreSQL and FastAPI TestClient.
Marked async to use pytest-asyncio.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import asyncpg
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient


@pytest_asyncio.fixture
async def app_client(postgres_url, monkeypatch):
    """Spin up the FastAPI app with a real DB pool, return a TestClient."""
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.setenv("WEBHOOK_QUEUE_ENABLED", "false")

    # Import lazily so env vars are set first
    from indexer.config import settings
    from indexer import db, webhook_receiver

    # TestClient runs the ASGI app in its own event loop. asyncpg pools are
    # loop-bound, so the app must create/close its own pool inside that loop.
    settings.database_url = postgres_url
    settings.webhook_queue_enabled = False
    db._pool = None

    with TestClient(webhook_receiver.app) as client:
        yield client


def _valid_helius_payload(*, agent_wallet: str, signature: str | None = None):
    return [{
        "signature":   signature or ("SIG" + "a" * 84),
        "slot":        265_000_000,
        "timestamp":   int(datetime.now(tz=timezone.utc).timestamp()),
        "type":        "TRANSFER",
        "feePayer":    agent_wallet,
        "fee":         5000,
        "instructions": [{"programId": "11111111111111111111111111111111"}],
        "accountData":  [{"account": agent_wallet, "nativeBalanceChange": -5000}],
    }]


# =============================================================================
# Authentication
# =============================================================================

class TestAuth:

    def test_missing_auth_header_returns_401(self, app_client):
        resp = app_client.post("/webhook", json=[])
        assert resp.status_code == 401

    def test_wrong_auth_token_returns_401(self, app_client):
        resp = app_client.post(
            "/webhook",
            json=[],
            headers={"Authorization": "wrong-token"},
        )
        assert resp.status_code == 401

    def test_valid_auth_token_accepted(self, app_client):
        # Empty body returns 200 since there's nothing to parse
        resp = app_client.post(
            "/webhook",
            json=[],
            headers={"Authorization": "test-auth-token-1234567890123456"},
        )
        assert resp.status_code == 200


# =============================================================================
# Body validation
# =============================================================================

class TestBodyValidation:

    def test_non_array_body_returns_400(self, app_client):
        resp = app_client.post(
            "/webhook",
            json={"not": "an array"},
            headers={"Authorization": "test-auth-token-1234567890123456"},
        )
        assert resp.status_code == 400
        assert "JSON array" in resp.text

    def test_empty_array_returns_200_with_zero_counts(self, app_client):
        resp = app_client.post(
            "/webhook",
            json=[],
            headers={"Authorization": "test-auth-token-1234567890123456"},
        )
        assert resp.status_code == 200
        assert resp.json()["received"] == 0
        assert resp.json()["inserted"] == 0


# =============================================================================
# Insertion
# =============================================================================

class TestInsertion:

    @pytest.mark.asyncio
    async def test_inserts_tx_for_registered_agent(self, app_client, seeded_agent, db_pool):
        payload = _valid_helius_payload(agent_wallet=seeded_agent)

        resp = app_client.post(
            "/webhook",
            json=payload,
            headers={"Authorization": "test-auth-token-1234567890123456"},
        )
        assert resp.status_code == 200
        assert resp.json()["received"]  == 1
        assert resp.json()["inserted"]  == 1
        assert resp.json()["skipped"]   == 0

        # Verify row in DB
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM agent_transactions WHERE agent_wallet = $1",
                seeded_agent,
            )
        assert row is not None
        assert row["success"] is True
        assert row["fee"] == 5000
        assert row["source"] == "webhook"

    @pytest.mark.asyncio
    async def test_skips_unknown_agent(self, app_client, db_pool):
        # No registered_agents row exists for this wallet
        payload = _valid_helius_payload(agent_wallet="UNKNOWN" + "x" * 36)

        resp = app_client.post(
            "/webhook",
            json=payload,
            headers={"Authorization": "test-auth-token-1234567890123456"},
        )
        assert resp.status_code == 200
        assert resp.json()["inserted"] == 0
        assert resp.json()["skipped"]  == 1

        # Verify NO row was inserted
        async with db_pool.acquire() as conn:
            count = await conn.fetchval("SELECT COUNT(*) FROM agent_transactions")
        assert count == 0

    @pytest.mark.asyncio
    async def test_idempotent_on_duplicate_signature(self, app_client, seeded_agent, db_pool):
        payload = _valid_helius_payload(agent_wallet=seeded_agent, signature="DUP" + "a" * 84)

        # First call inserts
        r1 = app_client.post("/webhook", json=payload,
                             headers={"Authorization": "test-auth-token-1234567890123456"})
        assert r1.json()["inserted"] == 1

        # Second call with same signature is a no-op
        r2 = app_client.post("/webhook", json=payload,
                             headers={"Authorization": "test-auth-token-1234567890123456"})
        assert r2.json()["inserted"] == 0
        assert r2.json()["skipped"]  == 1

        # Only one row in DB
        async with db_pool.acquire() as conn:
            count = await conn.fetchval("SELECT COUNT(*) FROM agent_transactions")
        assert count == 1

    @pytest.mark.asyncio
    async def test_old_transactions_rejected(self, app_client, seeded_agent, db_pool):
        # Tx from 2 hours ago — older than max_webhook_tx_age_seconds (default 1h)
        old_ts = int(datetime.now(tz=timezone.utc).timestamp()) - 7200
        payload = _valid_helius_payload(agent_wallet=seeded_agent)
        payload[0]["timestamp"] = old_ts

        resp = app_client.post("/webhook", json=payload,
                               headers={"Authorization": "test-auth-token-1234567890123456"})
        assert resp.status_code == 200
        assert resp.json()["inserted"] == 0
        assert resp.json()["skipped"]  == 1

    @pytest.mark.asyncio
    async def test_partial_batch_with_parse_failures(self, app_client, seeded_agent):
        valid   = _valid_helius_payload(agent_wallet=seeded_agent, signature="VALID" + "a" * 82)[0]
        invalid = {"signature": None, "slot": None}  # missing required fields

        resp = app_client.post("/webhook", json=[valid, invalid],
                               headers={"Authorization": "test-auth-token-1234567890123456"})
        assert resp.status_code == 200
        assert resp.json()["received"]  == 2
        assert resp.json()["inserted"]  == 1
        # invalid contributes to skipped via parse_failure path
        assert resp.json()["skipped"]   >= 1


# =============================================================================
# Operational endpoints
# =============================================================================

class TestOperational:

    def test_health_returns_ok(self, app_client):
        resp = app_client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_status_reports_db_reachable(self, app_client):
        resp = app_client.get("/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ready"
        assert body["db_reachable"] is True
        assert "last_5min" in body

    def test_metrics_returns_prometheus_format(self, app_client):
        resp = app_client.get("/metrics")
        assert resp.status_code == 200
        assert "helixor_webhook_events_total" in resp.text
        assert resp.headers["content-type"].startswith("text/plain")


# =============================================================================
# Audit log
# =============================================================================

class TestAuditLog:

    @pytest.mark.asyncio
    async def test_each_webhook_call_audited(self, app_client, seeded_agent, db_pool):
        payload = _valid_helius_payload(agent_wallet=seeded_agent)

        app_client.post("/webhook", json=payload,
                        headers={"Authorization": "test-auth-token-1234567890123456"})

        async with db_pool.acquire() as conn:
            count = await conn.fetchval("SELECT COUNT(*) FROM webhook_events")
        assert count == 1

        async with db_pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM webhook_events")
        assert row["tx_count"] == 1
        assert row["inserted_count"] == 1
        assert row["error"] is None
        assert row["duration_ms"] >= 0
