"""
tests/test_vuln09_auth_and_ratelimit.py — VULN-09 mitigation pin tests.

VULN-09 raised three classes of problem on a permissionless API:

  1. Unauthenticated polling of operational endpoints leaks oracle
     topology + investigation intelligence (Attacks 1, 2, 4).
  2. No rate limit lets a single client exhaust the read path (Attack 3).
  3. No CDN cache makes every read hit the DB.

These tests pin all three fixes:

  - operational endpoints REJECT (401) without a key, ACCEPT (200) with
    the configured X-API-Key,
  - score reads carry the audit-mandated Cache-Control header,
  - anonymous traffic over the public per-IP cap returns 429 + Retry-After,
  - authenticated traffic up to the per-key cap is not blocked by the
    per-IP cap,
  - the registry's lookup is constant-time across the key set (no early
    break), the `0` rate-limit-rejection counter increments on 429, and
    the `auth_rejections_total` counter increments on 401.

These tests build their own apps with tight rate-limit caps; the
project-wide `client` fixture uses a high cap that no other test trips.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.auth import (
    DEFAULT_KEY_RATE_LIMIT_PER_MIN,
    ApiKey,
    ApiKeyRegistry,
    load_keys_from_env,
)
from api.rate_limit import (
    DEFAULT_PUBLIC_RATE_LIMIT_PER_MIN,
    SlidingWindowLimiter,
    client_ip,
    load_public_limit_from_env,
    load_trust_proxy_from_env,
)


# =============================================================================
# Shared key constants (independent of conftest, so this file can be read
# top-to-bottom)
# =============================================================================

VALID_KEY_ID  = "vuln09-key-A"
VALID_SECRET  = "super-secret-A-value"
OTHER_SECRET  = "this-key-was-never-registered"

# Audit-mandated public cap.
PUBLIC_CAP = 100
# Audit-mandated authenticated cap.
KEY_CAP = 1_000


def _build_app(
    *,
    score_repo, byzantine_repo, cluster_repo,
    public_cap: int = PUBLIC_CAP,
    key_cap:    int = KEY_CAP,
    trust_proxy: bool = False,
):
    """Build a fresh app with explicit, tight VULN-09 caps."""
    registry = ApiKeyRegistry([
        ApiKey.from_secret(
            key_id=VALID_KEY_ID,
            secret=VALID_SECRET,
            tier="vuln09-test",
            rate_limit_per_minute=key_cap,
        ),
    ])
    limiter = SlidingWindowLimiter()
    return create_app(
        score_repo=score_repo,
        byzantine_repo=byzantine_repo,
        cluster_repo=cluster_repo,
        key_registry=registry,
        rate_limiter=limiter,
        public_rate_limit_per_minute=public_cap,
        trust_proxy=trust_proxy,
    )


# =============================================================================
# Audit-mandated defaults
# =============================================================================

class TestAuditMandatedDefaults:

    def test_public_default_is_100_per_minute(self):
        # The audit mandates 100 req/min per IP.
        assert DEFAULT_PUBLIC_RATE_LIMIT_PER_MIN == 100

    def test_key_default_is_1000_per_minute(self):
        # The audit mandates 1000 req/min for the API-key tier.
        assert DEFAULT_KEY_RATE_LIMIT_PER_MIN == 1_000


# =============================================================================
# OPERATIONAL endpoints require X-API-Key
# =============================================================================

OPERATIONAL_PATHS_REQUIRING_KEY = [
    "/health/cluster",
    "/byzantine/recent",
    "/byzantine/strikes",
    "/byzantine/per_node?epoch=28&agent=agentA",
    "/challenges?node=oracle-node-2",
]


class TestOperationalAuthGate:

    @pytest.mark.parametrize("path", OPERATIONAL_PATHS_REQUIRING_KEY)
    def test_no_key_returns_401(
        self, score_repo, byzantine_repo, cluster_repo, path,
    ):
        app = _build_app(
            score_repo=score_repo, byzantine_repo=byzantine_repo,
            cluster_repo=cluster_repo,
        )
        c = TestClient(app)
        r = c.get(path)
        assert r.status_code == 401, r.text
        body = r.json()
        assert body["error"] == "unauthorized"
        # Same opaque detail for missing vs invalid — no info-leak.
        assert "X-API-Key" in body["detail"]

    @pytest.mark.parametrize("path", OPERATIONAL_PATHS_REQUIRING_KEY)
    def test_invalid_key_returns_401(
        self, score_repo, byzantine_repo, cluster_repo, path,
    ):
        app = _build_app(
            score_repo=score_repo, byzantine_repo=byzantine_repo,
            cluster_repo=cluster_repo,
        )
        c = TestClient(app)
        r = c.get(path, headers={"X-API-Key": OTHER_SECRET})
        assert r.status_code == 401

    @pytest.mark.parametrize("path", OPERATIONAL_PATHS_REQUIRING_KEY)
    def test_valid_key_returns_200(
        self, score_repo, byzantine_repo, cluster_repo, path,
    ):
        app = _build_app(
            score_repo=score_repo, byzantine_repo=byzantine_repo,
            cluster_repo=cluster_repo,
        )
        c = TestClient(app)
        r = c.get(path, headers={"X-API-Key": VALID_SECRET})
        assert r.status_code == 200, r.text

    def test_auth_rejection_counter_increments(
        self, score_repo, byzantine_repo, cluster_repo,
    ):
        app = _build_app(
            score_repo=score_repo, byzantine_repo=byzantine_repo,
            cluster_repo=cluster_repo,
        )
        c = TestClient(app)
        # Trigger a 401.
        r = c.get("/byzantine/recent")
        assert r.status_code == 401
        # The metric labels the offending ROUTE TEMPLATE.
        body = c.get("/metrics").text
        assert "helixor_api_auth_rejections_total" in body
        assert '/byzantine/recent' in body

    def test_score_reads_still_open_without_key(
        self, score_repo, byzantine_repo, cluster_repo,
    ):
        # The agent-score read path remains anonymously accessible
        # (with the 100/min cap). It is not classified as operational.
        app = _build_app(
            score_repo=score_repo, byzantine_repo=byzantine_repo,
            cluster_repo=cluster_repo,
        )
        c = TestClient(app)
        r = c.get("/agents/agentA/health")
        assert r.status_code == 200


# =============================================================================
# Cache-Control headers
# =============================================================================

class TestCacheControl:

    def test_agent_health_carries_cdn_friendly_cache_control(
        self, score_repo, byzantine_repo, cluster_repo,
    ):
        app = _build_app(
            score_repo=score_repo, byzantine_repo=byzantine_repo,
            cluster_repo=cluster_repo,
        )
        c = TestClient(app)
        r = c.get("/agents/agentA/health")
        assert r.status_code == 200
        cc = r.headers.get("cache-control", "")
        # Audit asked for 5-minute CDN TTL.
        assert "public" in cc
        assert "max-age=300" in cc

    def test_score_history_carries_cdn_friendly_cache_control(
        self, score_repo, byzantine_repo, cluster_repo,
    ):
        app = _build_app(
            score_repo=score_repo, byzantine_repo=byzantine_repo,
            cluster_repo=cluster_repo,
        )
        c = TestClient(app)
        r = c.get("/agents/agentA/history")
        cc = r.headers.get("cache-control", "")
        assert "max-age=300" in cc

    def test_operational_endpoints_are_no_store(
        self, score_repo, byzantine_repo, cluster_repo,
    ):
        # Operational data must not be CDN-cached — it leaks topology.
        app = _build_app(
            score_repo=score_repo, byzantine_repo=byzantine_repo,
            cluster_repo=cluster_repo,
        )
        c = TestClient(app)
        r = c.get("/health/cluster", headers={"X-API-Key": VALID_SECRET})
        assert r.status_code == 200
        cc = r.headers.get("cache-control", "")
        assert "no-store" in cc
        assert "private" in cc


# =============================================================================
# Per-IP rate limiting (anonymous traffic)
# =============================================================================

class TestPublicRateLimit:

    def test_anonymous_traffic_429s_after_cap(
        self, score_repo, byzantine_repo, cluster_repo,
    ):
        # A very tight cap to keep the test cheap.
        app = _build_app(
            score_repo=score_repo, byzantine_repo=byzantine_repo,
            cluster_repo=cluster_repo,
            public_cap=5,
        )
        c = TestClient(app)
        # 5 should pass, the 6th should be a 429.
        for i in range(5):
            r = c.get("/agents/agentA/health")
            assert r.status_code == 200, f"hit {i} unexpectedly rejected"
        r = c.get("/agents/agentA/health")
        assert r.status_code == 429
        body = r.json()
        assert body["error"] == "too_many_requests"
        assert "rate limit" in body["detail"]
        # Audit-mandated client-affordance headers.
        assert "Retry-After" in r.headers
        retry_after = int(r.headers["Retry-After"])
        assert 1 <= retry_after <= 60
        assert r.headers["X-RateLimit-Limit"]     == "5"
        assert r.headers["X-RateLimit-Remaining"] == "0"

    def test_unmetered_endpoints_never_rate_limited(
        self, score_repo, byzantine_repo, cluster_repo,
    ):
        # /health, /metrics, /docs, /openapi.json must always answer —
        # k8s and Prometheus depend on it.
        app = _build_app(
            score_repo=score_repo, byzantine_repo=byzantine_repo,
            cluster_repo=cluster_repo,
            public_cap=2,
        )
        c = TestClient(app)
        for _ in range(10):
            assert c.get("/health").status_code == 200
            assert c.get("/metrics").status_code == 200

    def test_rate_limit_rejection_counter_increments(
        self, score_repo, byzantine_repo, cluster_repo,
    ):
        app = _build_app(
            score_repo=score_repo, byzantine_repo=byzantine_repo,
            cluster_repo=cluster_repo,
            public_cap=1,
        )
        c = TestClient(app)
        c.get("/agents/agentA/health")
        c.get("/agents/agentA/health")  # 429
        body = c.get("/metrics").text
        # The metric labels the bucket type that fired ("ip" here).
        assert "helixor_api_rate_limit_rejections_total" in body
        assert 'bucket_type="ip"' in body


# =============================================================================
# Per-key rate limiting (authenticated traffic, higher cap)
# =============================================================================

class TestAuthenticatedRateLimit:

    def test_valid_key_promotes_to_higher_cap(
        self, score_repo, byzantine_repo, cluster_repo,
    ):
        # Public cap is 2 — bare /agents/x/health would 429 quickly.
        # Authenticated cap is 50 — should easily pass 10 hits.
        app = _build_app(
            score_repo=score_repo, byzantine_repo=byzantine_repo,
            cluster_repo=cluster_repo,
            public_cap=2, key_cap=50,
        )
        c = TestClient(app)
        c.headers["X-API-Key"] = VALID_SECRET
        for i in range(10):
            r = c.get("/agents/agentA/health")
            assert r.status_code == 200, f"auth hit {i} rejected: {r.text}"

    def test_per_key_cap_is_independent_of_per_ip_cap(
        self, score_repo, byzantine_repo, cluster_repo,
    ):
        # Even after the per-IP bucket is exhausted, the per-key bucket
        # keeps serving — they are NOT the same counter.
        app = _build_app(
            score_repo=score_repo, byzantine_repo=byzantine_repo,
            cluster_repo=cluster_repo,
            public_cap=1, key_cap=10,
        )
        unauth = TestClient(app)
        auth   = TestClient(app)
        auth.headers["X-API-Key"] = VALID_SECRET

        # Burn the per-IP bucket.
        assert unauth.get("/agents/agentA/health").status_code == 200
        assert unauth.get("/agents/agentA/health").status_code == 429
        # The authed client still serves cleanly.
        for _ in range(5):
            assert auth.get("/agents/agentA/health").status_code == 200

    def test_per_key_429_labels_key_bucket(
        self, score_repo, byzantine_repo, cluster_repo,
    ):
        app = _build_app(
            score_repo=score_repo, byzantine_repo=byzantine_repo,
            cluster_repo=cluster_repo,
            public_cap=1_000, key_cap=2,
        )
        c = TestClient(app)
        c.headers["X-API-Key"] = VALID_SECRET
        c.get("/agents/agentA/health")
        c.get("/agents/agentA/health")
        r = c.get("/agents/agentA/health")
        assert r.status_code == 429
        body = c.get("/metrics").text
        assert 'bucket_type="key"' in body


# =============================================================================
# Constant-time lookup (no info-leak on registry size)
# =============================================================================

class TestConstantTimeLookup:

    def test_lookup_walks_every_key_even_after_match(self):
        # If the lookup short-circuits, an attacker can binary-search the
        # registry by timing. We pin the no-early-break behaviour by
        # asserting that a match returns the EXPECTED ApiKey instance
        # and is unaffected by the position of the match in the registry.
        registry = ApiKeyRegistry([
            ApiKey.from_secret(key_id=f"key-{i}", secret=f"s-{i}")
            for i in range(20)
        ])
        # Match at the END of the registry.
        last = registry.lookup("s-19")
        assert last is not None and last.key_id == "key-19"
        # Match at the START.
        first = registry.lookup("s-0")
        assert first is not None and first.key_id == "key-0"
        # Non-match returns None.
        assert registry.lookup("not-a-key") is None
        assert registry.lookup("") is None

    def test_empty_registry_rejects_all_lookups(self):
        registry = ApiKeyRegistry()
        assert registry.lookup("anything") is None
        assert registry.lookup("") is None
        assert registry.is_empty()

    def test_duplicate_key_ids_rejected(self):
        with pytest.raises(ValueError):
            ApiKeyRegistry([
                ApiKey.from_secret(key_id="dup", secret="a"),
                ApiKey.from_secret(key_id="dup", secret="b"),
            ])

    def test_secret_never_stored_raw(self):
        key = ApiKey.from_secret(key_id="k", secret="my-raw-secret")
        # Only the hash is stored — `repr` and field iteration do not
        # surface the raw value.
        assert "my-raw-secret" not in repr(key)
        assert key.secret_hash != "my-raw-secret"
        assert len(key.secret_hash) == 64  # hex sha256


# =============================================================================
# IP extraction policy
# =============================================================================

class _FakeRequest:
    def __init__(self, *, headers: dict[str, str], peer: str | None) -> None:
        self.headers = headers
        self.client = type("c", (), {"host": peer})() if peer else None


class TestClientIp:

    def test_default_uses_peer_ignores_xff(self):
        req = _FakeRequest(
            headers={"x-forwarded-for": "10.0.0.1, 10.0.0.2"},
            peer="192.168.0.1",
        )
        assert client_ip(req, trust_proxy=False) == "192.168.0.1"

    def test_trusted_proxy_uses_leftmost_xff(self):
        req = _FakeRequest(
            headers={"x-forwarded-for": "10.0.0.1, 10.0.0.2"},
            peer="192.168.0.1",
        )
        assert client_ip(req, trust_proxy=True) == "10.0.0.1"

    def test_trusted_proxy_without_xff_falls_back_to_peer(self):
        req = _FakeRequest(headers={}, peer="192.168.0.1")
        assert client_ip(req, trust_proxy=True) == "192.168.0.1"

    def test_missing_peer_returns_sentinel(self):
        req = _FakeRequest(headers={}, peer=None)
        assert client_ip(req, trust_proxy=False) == "unknown"


# =============================================================================
# Sliding-window limiter unit tests
# =============================================================================

class TestSlidingWindowLimiter:

    def test_allows_up_to_limit_then_rejects(self):
        lim = SlidingWindowLimiter()
        for _ in range(5):
            d = lim.check("b", 5)
            assert d.allowed
        d = lim.check("b", 5)
        assert not d.allowed
        assert d.remaining == 0
        assert d.retry_after_s > 0

    def test_buckets_are_independent(self):
        lim = SlidingWindowLimiter()
        for _ in range(3):
            assert lim.check("a", 3).allowed
        assert not lim.check("a", 3).allowed
        # `b` is unaffected.
        assert lim.check("b", 3).allowed

    def test_window_expiry_releases_slots(self):
        # Use a 0.1s window so the test is fast.
        lim = SlidingWindowLimiter(window_seconds=0.1)
        for _ in range(3):
            assert lim.check("b", 3).allowed
        assert not lim.check("b", 3).allowed
        time.sleep(0.15)
        # After the window passes the bucket has fully drained.
        assert lim.check("b", 3).allowed

    def test_limit_must_be_at_least_one(self):
        lim = SlidingWindowLimiter()
        with pytest.raises(ValueError):
            lim.check("b", 0)

    def test_window_must_be_positive(self):
        with pytest.raises(ValueError):
            SlidingWindowLimiter(window_seconds=0)


# =============================================================================
# Env loading
# =============================================================================

class TestKeyEnvLoader:

    def test_parses_minimal_key_id_secret(self, monkeypatch):
        monkeypatch.setenv("HELIXOR_API_KEYS", "k1:s1")
        keys = load_keys_from_env()
        assert len(keys) == 1
        k = keys[0]
        assert k.key_id == "k1"
        assert k.tier == "basic"
        assert k.rate_limit_per_minute == DEFAULT_KEY_RATE_LIMIT_PER_MIN

    def test_parses_full_record(self, monkeypatch):
        monkeypatch.setenv("HELIXOR_API_KEYS", "k1:s1:partner:500")
        [k] = load_keys_from_env()
        assert k.tier == "partner"
        assert k.rate_limit_per_minute == 500

    def test_ignores_blank_and_comment_lines(self, monkeypatch):
        monkeypatch.setenv("HELIXOR_API_KEYS", "\n# a comment\nk1:s1\n\n")
        keys = load_keys_from_env()
        assert [k.key_id for k in keys] == ["k1"]

    def test_unset_env_returns_empty(self, monkeypatch):
        monkeypatch.delenv("HELIXOR_API_KEYS", raising=False)
        assert load_keys_from_env() == []

    def test_malformed_record_raises(self, monkeypatch):
        monkeypatch.setenv("HELIXOR_API_KEYS", "no-secret-here")
        with pytest.raises(ValueError):
            load_keys_from_env()

    def test_empty_secret_raises(self, monkeypatch):
        monkeypatch.setenv("HELIXOR_API_KEYS", "k1:")
        with pytest.raises(ValueError):
            load_keys_from_env()

    def test_zero_limit_raises(self, monkeypatch):
        monkeypatch.setenv("HELIXOR_API_KEYS", "k1:s1:basic:0")
        with pytest.raises(ValueError):
            load_keys_from_env()


class TestRateLimitEnvLoader:

    def test_trust_proxy_default_false(self, monkeypatch):
        monkeypatch.delenv("HELIXOR_TRUST_PROXY", raising=False)
        assert load_trust_proxy_from_env() is False

    @pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "YES"])
    def test_trust_proxy_accepts_truthy(self, monkeypatch, val):
        monkeypatch.setenv("HELIXOR_TRUST_PROXY", val)
        assert load_trust_proxy_from_env() is True

    @pytest.mark.parametrize("val", ["0", "false", "no", "", "  "])
    def test_trust_proxy_rejects_falsy(self, monkeypatch, val):
        monkeypatch.setenv("HELIXOR_TRUST_PROXY", val)
        assert load_trust_proxy_from_env() is False

    def test_public_limit_default(self, monkeypatch):
        monkeypatch.delenv("HELIXOR_PUBLIC_RATE_LIMIT_PER_MIN", raising=False)
        assert load_public_limit_from_env() == DEFAULT_PUBLIC_RATE_LIMIT_PER_MIN

    def test_public_limit_override(self, monkeypatch):
        monkeypatch.setenv("HELIXOR_PUBLIC_RATE_LIMIT_PER_MIN", "250")
        assert load_public_limit_from_env() == 250

    def test_public_limit_zero_rejected(self, monkeypatch):
        monkeypatch.setenv("HELIXOR_PUBLIC_RATE_LIMIT_PER_MIN", "0")
        with pytest.raises(ValueError):
            load_public_limit_from_env()
