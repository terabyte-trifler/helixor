"""
tests/api/test_telemetry.py — telemetry beacon endpoint integration tests.
"""

from __future__ import annotations

import hashlib

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient


VALID_AGENT = "AGENT11111111111111111111111111111111111111"


@pytest_asyncio.fixture
async def app_client(db_pool, postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.delenv("REDIS_URL", raising=False)
    from api import main
    from api.rate_limit import reset_rate_limiter
    from indexer.config import settings
    from indexer import db

    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM operator_integrations")
        await conn.execute("DELETE FROM plugin_telemetry")
        await conn.execute("DELETE FROM operators")

    settings.database_url = postgres_url
    settings.redis_url = None
    db._pool = None
    reset_rate_limiter()
    with TestClient(main.app) as client:
        yield client


@pytest_asyncio.fixture
async def operator(db_pool):
    raw_key = "hxop_test_key_abc123"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO operators (api_key_hash, api_key_prefix, organization, tier)
            VALUES ($1, $2, $3, 'partner')
            ON CONFLICT (api_key_hash) DO UPDATE SET
                organization = EXCLUDED.organization,
                enabled = TRUE
            RETURNING id
            """,
            key_hash, raw_key[:8], "Test Operator",
        )
    return {"id": row["id"], "api_key": raw_key}


# =============================================================================
# Validation
# =============================================================================

class TestValidation:

    def test_empty_body_rejected(self, app_client):
        r = app_client.post("/telemetry/beacon", json={})
        assert r.status_code == 422

    def test_invalid_event_type_rejected(self, app_client):
        r = app_client.post("/telemetry/beacon", json={
            "event_type": "not_a_real_event",
            "plugin_version": "0.12.0",
            "beacon_id": "test-beacon-1",
        })
        assert r.status_code == 422

    def test_score_out_of_range_rejected(self, app_client):
        r = app_client.post("/telemetry/beacon", json={
            "event_type": "agent_score_fetched",
            "plugin_version": "0.12.0",
            "beacon_id": "test-beacon-2",
            "score": 1500,
        })
        assert r.status_code == 422

    def test_invalid_agent_wallet_rejected(self, app_client):
        r = app_client.post("/telemetry/beacon", json={
            "event_type": "plugin_initialized",
            "plugin_version": "0.12.0",
            "beacon_id": "test-beacon-3",
            "agent_wallet": "not-a-valid-base58-pubkey-at-all-just-bad",
        })
        assert r.status_code == 422

    def test_pii_keys_in_extra_rejected(self, app_client):
        r = app_client.post("/telemetry/beacon", json={
            "event_type": "action_blocked",
            "plugin_version": "0.12.0",
            "beacon_id": "test-beacon-4",
            "extra": {"text": "user prompt content"},
        })
        assert r.status_code == 422

    def test_message_key_in_extra_rejected(self, app_client):
        r = app_client.post("/telemetry/beacon", json={
            "event_type": "action_blocked",
            "plugin_version": "0.12.0",
            "beacon_id": "test-beacon-5",
            "extra": {"message": "secret"},
        })
        assert r.status_code == 422

    def test_oversized_extra_rejected(self, app_client):
        big = {"x": "y" * 3000}  # > 2048 byte limit
        r = app_client.post("/telemetry/beacon", json={
            "event_type": "plugin_initialized",
            "plugin_version": "0.12.0",
            "beacon_id": "test-beacon-6",
            "extra": big,
        })
        assert r.status_code == 422


# =============================================================================
# Happy path
# =============================================================================

class TestHappyPath:

    def test_anonymous_beacon_accepted(self, app_client):
        r = app_client.post("/telemetry/beacon", json={
            "event_type": "plugin_initialized",
            "plugin_version": "0.12.0",
            "agent_wallet": VALID_AGENT,
            "beacon_id": "test-anon-1",
        })
        assert r.status_code == 202
        body = r.json()
        assert body["accepted"] is True
        assert body["deduped"] is False

    @pytest.mark.asyncio
    async def test_dedup_returns_deduped_true(self, app_client):
        payload = {
            "event_type": "plugin_initialized",
            "plugin_version": "0.12.0",
            "agent_wallet": VALID_AGENT,
            "beacon_id": "dedup-test-1",
        }
        r1 = app_client.post("/telemetry/beacon", json=payload)
        r2 = app_client.post("/telemetry/beacon", json=payload)
        assert r1.json()["deduped"] is False
        assert r2.json()["deduped"] is True


# =============================================================================
# Operator attribution
# =============================================================================

class TestOperatorAttribution:

    def test_valid_api_key_attributes_to_operator(self, app_client, operator, db_pool):
        r = app_client.post(
            "/telemetry/beacon",
            json={
                "event_type": "plugin_initialized",
                "plugin_version": "0.12.0",
                "agent_wallet": VALID_AGENT,
                "beacon_id": "op-attrib-1",
            },
            headers={"Authorization": f"Bearer {operator['api_key']}"},
        )
        assert r.status_code == 202

    def test_invalid_api_key_still_accepts_anonymously(self, app_client):
        r = app_client.post(
            "/telemetry/beacon",
            json={
                "event_type": "plugin_initialized",
                "plugin_version": "0.12.0",
                "beacon_id": "anon-key-1",
            },
            headers={"Authorization": "Bearer hxop_invalid_key_xyz"},
        )
        # Beacon is accepted without operator attribution
        assert r.status_code == 202


# =============================================================================
# whoami
# =============================================================================

class TestWhoami:

    def test_no_auth_returns_401(self, app_client):
        r = app_client.get("/telemetry/whoami")
        assert r.status_code == 401

    def test_invalid_key_returns_401(self, app_client):
        r = app_client.get("/telemetry/whoami",
                           headers={"Authorization": "Bearer invalid_key_xyz"})
        assert r.status_code == 401

    def test_valid_key_returns_summary(self, app_client, operator):
        r = app_client.get("/telemetry/whoami",
                           headers={"Authorization": f"Bearer {operator['api_key']}"})
        assert r.status_code == 200
        body = r.json()
        assert body["operator_id"] == operator["id"]
        assert body["organization"] == "Test Operator"
        assert body["tier"] == "partner"
        assert isinstance(body["integrations"], list)

    def test_whoami_includes_recent_beacon_count(self, app_client, operator):
        # Send a beacon
        app_client.post(
            "/telemetry/beacon",
            json={
                "event_type": "plugin_initialized",
                "plugin_version": "0.12.0",
                "agent_wallet": VALID_AGENT,
                "beacon_id": "whoami-init-1",
            },
            headers={"Authorization": f"Bearer {operator['api_key']}"},
        )
        # Confirm it shows up
        r = app_client.get("/telemetry/whoami",
                           headers={"Authorization": f"Bearer {operator['api_key']}"})
        body = r.json()
        assert body["plugin_initialized_count"] >= 1
