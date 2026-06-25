"""
tests/test_vuln23_safe_score.py — VULN-23 safe_score endpoint contract.

The /agents/{wallet}/safe_score endpoint is the HTTP mirror of the SDK's
SafeCertReader. These tests pin EVERY guard-rail branch (ok / stale /
velocity / insufficient) so a future regression that loosens the wrapper
fails CI.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.auth import ApiKey, ApiKeyRegistry
from api.byzantine_repo import InMemoryByzantineRepo
from api.cluster_health import InMemoryClusterHealthRepo
from api.rate_limit import SlidingWindowLimiter
from api.safe_score import (
    CERT_MAX_AGE_SECONDS,
    MAX_SCORE_VELOCITY,
    MIN_HISTORY_REQUIRED,
    REASON_INSUFFICIENT_HISTORY,
    REASON_STALE_CERT,
    REASON_VELOCITY_EXCEEDED,
    VELOCITY_WINDOW_EPOCHS,
    SafeScoreOk,
    SafeScoreRejected,
    compute_safe_score,
)
from api.score_repo import InMemoryScoreRepo, ScoreRecord

from tests.conftest import (
    TEST_API_KEY_ID,
    TEST_API_KEY_SECRET,
    TEST_RATE_LIMIT_PER_MIN,
    WALLET_A,
    WALLET_B,
    WALLET_UNKNOWN,
)


# =============================================================================
# Helpers — build deterministic certs at a chosen wall-clock instant
# =============================================================================

NOW = int(datetime(2026, 5, 25, 12, 0, 0, tzinfo=timezone.utc).timestamp())


def _cert(wallet: str, epoch: int, score: int, *,
          tier: int = 0, issued_offset: int = -60) -> ScoreRecord:
    """A ScoreRecord at `NOW + issued_offset` seconds."""
    return ScoreRecord(
        agent_wallet=wallet, epoch=epoch, score=score,
        alert_tier=tier, flags=0, immediate_red=False, signer_count=3,
        computed_at=datetime.fromtimestamp(NOW + issued_offset, tz=timezone.utc),
    )


# =============================================================================
# Constants pin — audit values must not drift silently
# =============================================================================

def test_constants_match_audit_mandate():
    assert CERT_MAX_AGE_SECONDS == 48 * 60 * 60, "48h ceiling is the audit mandate"
    assert MAX_SCORE_VELOCITY == 200, "must mirror off-chain per-epoch clamp"
    assert VELOCITY_WINDOW_EPOCHS == 3
    assert MIN_HISTORY_REQUIRED == 2


def test_constants_match_sdk_constants():
    """The SDK and the API must agree on the numbers — a drift between
    the two would silently weaken whichever side is laxer."""
    sdk_path = (
        __import__("pathlib").Path(__file__).resolve()
        .parents[2] / "phylanx-sdk" / "src" / "safe_reader.ts"
    )
    text = sdk_path.read_text()
    assert f"CERT_MAX_AGE_SECONDS = {48 * 60 * 60}" in text \
        or "CERT_MAX_AGE_SECONDS = 48 * 60 * 60" in text
    assert "MAX_SCORE_VELOCITY = 200" in text
    assert "VELOCITY_WINDOW_EPOCHS = 3" in text
    assert "MIN_HISTORY_REQUIRED = 2" in text


# =============================================================================
# Pure-function tests against compute_safe_score
# =============================================================================

def test_ok_flat_scores_inside_window():
    repo = InMemoryScoreRepo([
        _cert(WALLET_A, 28, 700),
        _cert(WALLET_A, 29, 720),
        _cert(WALLET_A, 30, 730, issued_offset=-60),
    ])
    r = compute_safe_score(repo, WALLET_A, now_unix=NOW)
    assert isinstance(r, SafeScoreOk)
    assert r.score == 730
    assert r.epoch == 30
    assert r.velocity_min == 700
    assert r.velocity_max == 730
    assert r.window_epochs == (28, 29, 30)


def test_ok_velocity_exactly_200_allowed():
    repo = InMemoryScoreRepo([
        _cert(WALLET_A, 28, 500),
        _cert(WALLET_A, 30, 700, issued_offset=-60),
    ])
    r = compute_safe_score(repo, WALLET_A, now_unix=NOW)
    assert isinstance(r, SafeScoreOk)
    assert r.velocity_max - r.velocity_min == 200


def test_ok_freshness_exactly_at_48h_allowed():
    repo = InMemoryScoreRepo([
        _cert(WALLET_A, 29, 700),
        _cert(WALLET_A, 30, 710, issued_offset=-CERT_MAX_AGE_SECONDS),
    ])
    r = compute_safe_score(repo, WALLET_A, now_unix=NOW)
    assert isinstance(r, SafeScoreOk)


def test_reject_stale_one_second_past_limit():
    repo = InMemoryScoreRepo([
        _cert(WALLET_A, 29, 700),
        _cert(WALLET_A, 30, 710, issued_offset=-CERT_MAX_AGE_SECONDS - 1),
    ])
    r = compute_safe_score(repo, WALLET_A, now_unix=NOW)
    assert isinstance(r, SafeScoreRejected)
    assert r.reason == REASON_STALE_CERT


def test_reject_velocity_201_trips():
    repo = InMemoryScoreRepo([
        _cert(WALLET_A, 29, 500),
        _cert(WALLET_A, 30, 701, issued_offset=-60),
    ])
    r = compute_safe_score(repo, WALLET_A, now_unix=NOW)
    assert isinstance(r, SafeScoreRejected)
    assert r.reason == REASON_VELOCITY_EXCEEDED
    assert "201" in r.detail


def test_reject_velocity_drop():
    repo = InMemoryScoreRepo([
        _cert(WALLET_A, 28, 900),
        _cert(WALLET_A, 30, 600, issued_offset=-60),
    ])
    r = compute_safe_score(repo, WALLET_A, now_unix=NOW)
    assert isinstance(r, SafeScoreRejected)
    assert r.reason == REASON_VELOCITY_EXCEEDED


def test_reject_insufficient_history_no_certs():
    repo = InMemoryScoreRepo()
    r = compute_safe_score(repo, WALLET_UNKNOWN, now_unix=NOW)
    assert isinstance(r, SafeScoreRejected)
    assert r.reason == REASON_INSUFFICIENT_HISTORY


def test_reject_insufficient_history_single_cert():
    repo = InMemoryScoreRepo([
        _cert(WALLET_A, 30, 700, issued_offset=-60),
    ])
    r = compute_safe_score(repo, WALLET_A, now_unix=NOW)
    assert isinstance(r, SafeScoreRejected)
    assert r.reason == REASON_INSUFFICIENT_HISTORY


def test_compute_rejects_bad_options():
    repo = InMemoryScoreRepo()
    with pytest.raises(ValueError, match="window_epochs"):
        compute_safe_score(repo, WALLET_A, window_epochs=1)
    with pytest.raises(ValueError, match="max_age_seconds"):
        compute_safe_score(repo, WALLET_A, max_age_seconds=0)
    with pytest.raises(ValueError, match="max_velocity"):
        compute_safe_score(repo, WALLET_A, max_velocity=-1)


# =============================================================================
# HTTP endpoint tests — wire-format pinning
# =============================================================================

@pytest.fixture
def safe_score_app():
    """A FastAPI app whose repo we can freely mutate per test."""
    repo = InMemoryScoreRepo()
    app = create_app(
        score_repo=repo,
        byzantine_repo=InMemoryByzantineRepo(),
        cluster_repo=InMemoryClusterHealthRepo(),
        network="localnet", is_production=False,
        key_registry=ApiKeyRegistry([
            ApiKey.from_secret(
                key_id=TEST_API_KEY_ID, secret=TEST_API_KEY_SECRET,
                tier="test", rate_limit_per_minute=TEST_RATE_LIMIT_PER_MIN,
            ),
        ]),
        rate_limiter=SlidingWindowLimiter(),
        public_rate_limit_per_minute=TEST_RATE_LIMIT_PER_MIN,
    )
    app.state.score_repo_under_test = repo
    return app


@pytest.fixture
def safe_score_client(safe_score_app):
    c = TestClient(safe_score_app)
    c.headers["X-API-Key"] = TEST_API_KEY_SECRET
    return c


def test_http_ok_response_shape(safe_score_client, safe_score_app):
    repo: InMemoryScoreRepo = safe_score_app.state.score_repo_under_test
    # Use real wall-clock times so the freshness check passes.
    now = int(time.time())
    repo.add(ScoreRecord(
        WALLET_A, 29, 700, 0, 0, False, 3,
        datetime.fromtimestamp(now - 3600, tz=timezone.utc),
    ))
    repo.add(ScoreRecord(
        WALLET_A, 30, 710, 0, 0, False, 3,
        datetime.fromtimestamp(now - 60, tz=timezone.utc),
    ))

    resp = safe_score_client.get(f"/agents/{WALLET_A}/safe_score")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["score"] == 710
    assert body["alert_tier"] == "GREEN"
    assert body["epoch"] == 30
    assert body["velocity_window"]["min_score"] == 700
    assert body["velocity_window"]["max_score"] == 710
    assert body["reason"] is None
    assert body["detail"] is None
    # Must NOT be CDN-cacheable — the freshness boundary moves every second.
    assert "no-store" in resp.headers.get("cache-control", "")


def test_http_velocity_rejection_shape(safe_score_client, safe_score_app):
    repo: InMemoryScoreRepo = safe_score_app.state.score_repo_under_test
    now = int(time.time())
    repo.add(ScoreRecord(
        WALLET_A, 29, 300, 1, 0, False, 3,
        datetime.fromtimestamp(now - 3600, tz=timezone.utc),
    ))
    repo.add(ScoreRecord(
        WALLET_A, 30, 700, 0, 0, False, 3,
        datetime.fromtimestamp(now - 60, tz=timezone.utc),
    ))

    resp = safe_score_client.get(f"/agents/{WALLET_A}/safe_score")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["reason"] == REASON_VELOCITY_EXCEEDED
    assert body["score"] is None
    assert "400" in body["detail"]


def test_http_stale_rejection_shape(safe_score_client, safe_score_app):
    repo: InMemoryScoreRepo = safe_score_app.state.score_repo_under_test
    now = int(time.time())
    old = now - CERT_MAX_AGE_SECONDS - 10
    repo.add(ScoreRecord(
        WALLET_A, 29, 700, 0, 0, False, 3,
        datetime.fromtimestamp(old - 86400, tz=timezone.utc),
    ))
    repo.add(ScoreRecord(
        WALLET_A, 30, 710, 0, 0, False, 3,
        datetime.fromtimestamp(old, tz=timezone.utc),
    ))

    resp = safe_score_client.get(f"/agents/{WALLET_A}/safe_score")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["reason"] == REASON_STALE_CERT


def test_http_insufficient_history_for_unknown_agent(safe_score_client):
    resp = safe_score_client.get(f"/agents/{WALLET_UNKNOWN}/safe_score")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["reason"] == REASON_INSUFFICIENT_HISTORY


def test_http_400_on_malformed_wallet(safe_score_client):
    # VULN-20 wallet validation must still fire.
    resp = safe_score_client.get("/agents/'%3B%20DROP/safe_score")
    assert resp.status_code == 400
    assert resp.json()["error"] == "bad_request"
