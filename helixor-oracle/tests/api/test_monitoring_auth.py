"""
tests/api/test_monitoring_auth.py — operator monitoring endpoints require auth.
"""

from __future__ import annotations

import pytest_asyncio
from fastapi.testclient import TestClient


@pytest_asyncio.fixture
async def app_client(db_pool, postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.setenv("MONITORING_ADMIN_TOKEN", "test-monitoring-admin-token")

    from api import main
    from api.rate_limit import reset_rate_limiter
    from indexer import db

    db._pool = None
    reset_rate_limiter()

    with TestClient(main.app) as client:
        yield client


def test_monitoring_requires_bearer_token(app_client):
    r = app_client.get("/monitoring/slos")
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_REQUIRED"


def test_monitoring_accepts_admin_token(app_client):
    r = app_client.get(
        "/monitoring/slos",
        headers={"Authorization": "Bearer test-monitoring-admin-token"},
    )
    assert r.status_code == 200
