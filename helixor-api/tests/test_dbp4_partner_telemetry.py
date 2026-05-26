"""
tests/test_dbp4_partner_telemetry.py — DBP-4b mitigation pin tests.

DBP-4 closes the fourth substrate of the Path-4 (DeFi Bypass) chain by
turning the Verified-Integrator tier into a measurable revenue surface.
The first deliverable (DBP-4b) is **per-partner safe-reader share
telemetry** — a Prometheus counter that records, for every
Verified-Integrator key, whether each value-bearing score read came
from the safe (`/safe_score`) or raw (`/health`, `/health/{epoch}`,
`/history`) surface.

These tests pin:

  - `ApiKey.partner_wallet` is parsed from the 5th colon field of the
    `HELIXOR_API_KEYS` env var.
  - `load_keys_from_env` rejects malformed partner wallets at startup
    (bad length, non-base58 chars).
  - The `safe_reader_share_total{partner_wallet, surface}` counter
    increments on:
      - `safe`: `/agents/{wallet}/safe_score`
      - `raw` : `/agents/{wallet}/health`,
                `/agents/{wallet}/health/{epoch}`,
                `/agents/{wallet}/history`
  - Calls that DON'T carry a partner-bound key (no key, or a key
    without partner_wallet) do NOT increment the counter — the
    leaderboard ranks Verified-Integrator traffic only.
  - 4xx/5xx calls do NOT increment the counter — the metric represents
    successful score reads, not malformed requests.
  - Calls to routes that aren't score-reads (`/version`, `/byzantine/*`)
    do NOT increment the counter even when made with a partner key.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.auth import ApiKey, ApiKeyRegistry, load_keys_from_env
from api.rate_limit import SlidingWindowLimiter
from tests.conftest import (
    TEST_RATE_LIMIT_PER_MIN,
    WALLET_A,
    WALLET_B,
)


# =============================================================================
# Test constants
# =============================================================================

PARTNER_WALLET_X = "P1" * 22                    # 44-char base58 placeholder
PARTNER_WALLET_Y = "Q2" * 22

PARTNER_KEY_ID_X = "dbp4-partner-x"
PARTNER_SECRET_X = "dbp4-partner-x-secret"

PARTNER_KEY_ID_Y = "dbp4-partner-y"
PARTNER_SECRET_Y = "dbp4-partner-y-secret"

# A key with NO partner binding — the "basic"-tier control group.
BASIC_KEY_ID  = "dbp4-basic-key"
BASIC_SECRET  = "dbp4-basic-secret"


# =============================================================================
# Fixtures — build a fresh app whose registry carries the partner keys
# =============================================================================

@pytest.fixture
def partner_registry() -> ApiKeyRegistry:
    return ApiKeyRegistry([
        ApiKey.from_secret(
            key_id=PARTNER_KEY_ID_X, secret=PARTNER_SECRET_X,
            tier="partner", rate_limit_per_minute=TEST_RATE_LIMIT_PER_MIN,
            partner_wallet=PARTNER_WALLET_X,
        ),
        ApiKey.from_secret(
            key_id=PARTNER_KEY_ID_Y, secret=PARTNER_SECRET_Y,
            tier="partner", rate_limit_per_minute=TEST_RATE_LIMIT_PER_MIN,
            partner_wallet=PARTNER_WALLET_Y,
        ),
        ApiKey.from_secret(
            key_id=BASIC_KEY_ID, secret=BASIC_SECRET,
            tier="basic", rate_limit_per_minute=TEST_RATE_LIMIT_PER_MIN,
        ),
    ])


@pytest.fixture
def partner_app(score_repo, byzantine_repo, cluster_repo, partner_registry):
    return create_app(
        score_repo=score_repo,
        byzantine_repo=byzantine_repo,
        cluster_repo=cluster_repo,
        network="localnet",
        is_production=False,
        key_registry=partner_registry,
        rate_limiter=SlidingWindowLimiter(),
        public_rate_limit_per_minute=TEST_RATE_LIMIT_PER_MIN,
    )


def _client_for(app, secret: str | None) -> TestClient:
    c = TestClient(app)
    if secret is not None:
        c.headers["X-API-Key"] = secret
    return c


def _counter_value(app, partner_wallet: str, surface: str) -> float:
    """Read the current safe_reader_share_total sample for a label pair.
    Returns 0.0 if the label combination hasn't been observed yet."""
    counter = app.state.metrics.safe_reader_share_total
    metric = counter.labels(partner_wallet, surface)
    return metric._value.get()


# =============================================================================
# ApiKey.from_secret partner-wallet validation
# =============================================================================

class TestApiKeyPartnerWallet:

    def test_partner_wallet_default_is_none(self) -> None:
        key = ApiKey.from_secret(
            key_id="k", secret="s", tier="basic",
            rate_limit_per_minute=1000,
        )
        assert key.partner_wallet is None

    def test_partner_wallet_is_stored(self) -> None:
        key = ApiKey.from_secret(
            key_id="k", secret="s", tier="partner",
            rate_limit_per_minute=1000,
            partner_wallet=PARTNER_WALLET_X,
        )
        assert key.partner_wallet == PARTNER_WALLET_X

    def test_empty_partner_wallet_becomes_none(self) -> None:
        # An empty string is normalised to None so the leaderboard
        # never sees a `""` partner_wallet label.
        key = ApiKey.from_secret(
            key_id="k", secret="s", tier="partner",
            rate_limit_per_minute=1000,
            partner_wallet="",
        )
        assert key.partner_wallet is None

    def test_short_wallet_rejected(self) -> None:
        with pytest.raises(ValueError, match="32..44-char base58"):
            ApiKey.from_secret(
                key_id="k", secret="s", tier="partner",
                rate_limit_per_minute=1000,
                partner_wallet="tooShort",
            )

    def test_long_wallet_rejected(self) -> None:
        with pytest.raises(ValueError, match="32..44-char base58"):
            ApiKey.from_secret(
                key_id="k", secret="s", tier="partner",
                rate_limit_per_minute=1000,
                partner_wallet="A" * 45,
            )

    def test_non_base58_wallet_rejected(self) -> None:
        # "0" and "O" and "I" and "l" are NOT in the Bitcoin alphabet.
        with pytest.raises(ValueError, match="non-base58"):
            ApiKey.from_secret(
                key_id="k", secret="s", tier="partner",
                rate_limit_per_minute=1000,
                partner_wallet="0" * 44,
            )


# =============================================================================
# load_keys_from_env parses the 5th colon field as partner_wallet
# =============================================================================

class TestLoadKeysFromEnvPartnerWallet:

    def test_5th_field_parsed_as_partner_wallet(self, monkeypatch) -> None:
        monkeypatch.setenv(
            "HELIXOR_API_KEYS",
            f"keyA:secretA:partner:5000:{PARTNER_WALLET_X}",
        )
        keys = load_keys_from_env()
        assert len(keys) == 1
        assert keys[0].partner_wallet == PARTNER_WALLET_X
        assert keys[0].tier == "partner"
        assert keys[0].rate_limit_per_minute == 5000

    def test_4th_field_alone_leaves_partner_wallet_none(
        self, monkeypatch,
    ) -> None:
        monkeypatch.setenv(
            "HELIXOR_API_KEYS",
            "keyA:secretA:basic:5000",
        )
        keys = load_keys_from_env()
        assert len(keys) == 1
        assert keys[0].partner_wallet is None

    def test_too_many_fields_rejected(self, monkeypatch) -> None:
        monkeypatch.setenv(
            "HELIXOR_API_KEYS",
            f"keyA:secretA:partner:5000:{PARTNER_WALLET_X}:extra",
        )
        with pytest.raises(ValueError, match="partner_wallet"):
            load_keys_from_env()


# =============================================================================
# safe_reader_share_total counter increments
# =============================================================================

class TestSafeReaderShareTelemetry:

    def test_safe_score_call_increments_safe_bucket(
        self, partner_app,
    ) -> None:
        client = _client_for(partner_app, PARTNER_SECRET_X)
        before = _counter_value(partner_app, PARTNER_WALLET_X, "safe")
        r = client.get(f"/agents/{WALLET_A}/safe_score")
        assert r.status_code == 200
        after = _counter_value(partner_app, PARTNER_WALLET_X, "safe")
        assert after == before + 1
        # The raw bucket stays at zero.
        assert _counter_value(partner_app, PARTNER_WALLET_X, "raw") == 0

    def test_health_call_increments_raw_bucket(self, partner_app) -> None:
        client = _client_for(partner_app, PARTNER_SECRET_X)
        before = _counter_value(partner_app, PARTNER_WALLET_X, "raw")
        r = client.get(f"/agents/{WALLET_A}/health")
        assert r.status_code == 200
        after = _counter_value(partner_app, PARTNER_WALLET_X, "raw")
        assert after == before + 1
        # The safe bucket stays at zero.
        assert _counter_value(partner_app, PARTNER_WALLET_X, "safe") == 0

    def test_health_at_epoch_increments_raw_bucket(self, partner_app) -> None:
        client = _client_for(partner_app, PARTNER_SECRET_X)
        r = client.get(f"/agents/{WALLET_A}/health/29")
        assert r.status_code == 200
        assert _counter_value(partner_app, PARTNER_WALLET_X, "raw") == 1

    def test_history_call_increments_raw_bucket(self, partner_app) -> None:
        client = _client_for(partner_app, PARTNER_SECRET_X)
        r = client.get(f"/agents/{WALLET_A}/history")
        assert r.status_code == 200
        assert _counter_value(partner_app, PARTNER_WALLET_X, "raw") == 1

    def test_partner_buckets_isolated(self, partner_app) -> None:
        # Partner X calls safe_score 2x, partner Y calls health 3x.
        # The counter buckets are independent — no cross-talk.
        cx = _client_for(partner_app, PARTNER_SECRET_X)
        cy = _client_for(partner_app, PARTNER_SECRET_Y)
        for _ in range(2):
            assert cx.get(f"/agents/{WALLET_A}/safe_score").status_code == 200
        for _ in range(3):
            assert cy.get(f"/agents/{WALLET_A}/health").status_code == 200

        assert _counter_value(partner_app, PARTNER_WALLET_X, "safe") == 2
        assert _counter_value(partner_app, PARTNER_WALLET_X, "raw")  == 0
        assert _counter_value(partner_app, PARTNER_WALLET_Y, "safe") == 0
        assert _counter_value(partner_app, PARTNER_WALLET_Y, "raw")  == 3

    def test_basic_key_without_partner_wallet_does_not_record(
        self, partner_app,
    ) -> None:
        # A "basic" tier key (no partner_wallet) is INVISIBLE to the
        # leaderboard surface. The counter cardinality stays scoped to
        # Verified Integrators only.
        client = _client_for(partner_app, BASIC_SECRET)
        r = client.get(f"/agents/{WALLET_A}/safe_score")
        assert r.status_code == 200
        # No partner label, so we walk the registry and ensure there's
        # NO new sample whose partner_wallet label is empty.
        counter = partner_app.state.metrics.safe_reader_share_total
        # prometheus_client stores child counters keyed by their label
        # tuple. We assert the basic key did NOT create a (`""`, *) row.
        labels_seen = {
            tuple(child) for child in counter._metrics.keys()
        }
        assert ("", "safe") not in labels_seen
        assert ("", "raw") not in labels_seen

    def test_unauthenticated_call_does_not_record(self, partner_app) -> None:
        client = _client_for(partner_app, secret=None)
        # Public score-read with no API key — succeeds at the per-IP cap
        # but is not attributed to any partner.
        r = client.get(f"/agents/{WALLET_A}/safe_score")
        assert r.status_code == 200
        counter = partner_app.state.metrics.safe_reader_share_total
        # No partner_wallet was bound to the call, so the counter
        # registry must be empty.
        assert dict(counter._metrics) == {}

    def test_4xx_does_not_record(self, partner_app) -> None:
        # A 404 (no score for the requested epoch) is a malformed
        # request, not a signal of how the partner reads scores. The
        # counter MUST NOT increment.
        client = _client_for(partner_app, PARTNER_SECRET_X)
        r = client.get(f"/agents/{WALLET_A}/health/9999")
        assert r.status_code == 404
        assert _counter_value(partner_app, PARTNER_WALLET_X, "raw")  == 0
        assert _counter_value(partner_app, PARTNER_WALLET_X, "safe") == 0

    def test_off_surface_route_does_not_record(self, partner_app) -> None:
        # `/version` is not a value-bearing score read. The counter must
        # not bucket it into either surface.
        client = _client_for(partner_app, PARTNER_SECRET_X)
        r = client.get("/version")
        assert r.status_code == 200
        assert _counter_value(partner_app, PARTNER_WALLET_X, "safe") == 0
        assert _counter_value(partner_app, PARTNER_WALLET_X, "raw")  == 0


# =============================================================================
# DBP-4c — /integrations/leaderboard endpoint
# =============================================================================
#
# Reads the safe_reader_share_total counter, aggregates by
# partner_wallet, returns a ranked list. Public endpoint (no key
# required) — the ranking is a misuse-deterrent surface.

class TestIntegrationsLeaderboard:

    def test_endpoint_is_public(self, partner_app) -> None:
        # No X-API-Key header — must still return 200. The leaderboard
        # is a public surface so any consumer can read the ranking.
        client = _client_for(partner_app, secret=None)
        r = client.get("/integrations/leaderboard")
        assert r.status_code == 200
        body = r.json()
        assert body["_v"] == 1
        assert "ranking" in body

    def test_idle_partners_listed_with_safe_share_none(
        self, partner_app,
    ) -> None:
        # Both partner X and partner Y are registered but no traffic
        # has hit the API yet. They must both appear in the response
        # with safe_share = None.
        client = _client_for(partner_app, secret=None)
        body = client.get("/integrations/leaderboard").json()
        wallets = [r["partner_wallet"] for r in body["ranking"]]
        assert PARTNER_WALLET_X in wallets
        assert PARTNER_WALLET_Y in wallets
        for row in body["ranking"]:
            assert row["total_calls"] == 0
            assert row["safe_share"] is None

    def test_basic_key_not_listed(self, partner_app) -> None:
        # The basic-tier key has NO partner_wallet — it must not appear
        # in the leaderboard at all. The leaderboard is a Verified-
        # Integrator surface.
        client = _client_for(partner_app, secret=None)
        body = client.get("/integrations/leaderboard").json()
        wallets = [r["partner_wallet"] for r in body["ranking"]]
        # Three keys are registered (X, Y, basic) — leaderboard has 2.
        assert len(body["ranking"]) == 2
        assert "" not in wallets
        assert None not in wallets

    def test_safe_share_computed_and_ranked_descending(
        self, partner_app,
    ) -> None:
        # X: 4 safe + 1 raw → share 0.80
        # Y: 1 safe + 9 raw → share 0.10
        # X must rank above Y.
        cx = _client_for(partner_app, PARTNER_SECRET_X)
        cy = _client_for(partner_app, PARTNER_SECRET_Y)
        for _ in range(4):
            assert cx.get(f"/agents/{WALLET_A}/safe_score").status_code == 200
        for _ in range(1):
            assert cx.get(f"/agents/{WALLET_A}/health").status_code == 200
        for _ in range(1):
            assert cy.get(f"/agents/{WALLET_A}/safe_score").status_code == 200
        for _ in range(9):
            assert cy.get(f"/agents/{WALLET_A}/health").status_code == 200

        public = _client_for(partner_app, secret=None)
        ranking = public.get("/integrations/leaderboard").json()["ranking"]
        # X first, Y second.
        assert ranking[0]["partner_wallet"] == PARTNER_WALLET_X
        assert ranking[0]["safe_calls"] == 4
        assert ranking[0]["raw_calls"]  == 1
        assert ranking[0]["total_calls"] == 5
        assert ranking[0]["safe_share"] == pytest.approx(0.80)
        assert ranking[1]["partner_wallet"] == PARTNER_WALLET_Y
        assert ranking[1]["safe_calls"] == 1
        assert ranking[1]["raw_calls"]  == 9
        assert ranking[1]["safe_share"] == pytest.approx(0.10)

    def test_total_calls_tiebreaker_when_shares_equal(
        self, partner_app,
    ) -> None:
        # X: 2 safe + 0 raw → share 1.0  total 2
        # Y: 4 safe + 0 raw → share 1.0  total 4
        # Same share; Y must rank above X because it has more traffic.
        cx = _client_for(partner_app, PARTNER_SECRET_X)
        cy = _client_for(partner_app, PARTNER_SECRET_Y)
        for _ in range(2):
            cx.get(f"/agents/{WALLET_A}/safe_score")
        for _ in range(4):
            cy.get(f"/agents/{WALLET_A}/safe_score")

        public = _client_for(partner_app, secret=None)
        ranking = public.get("/integrations/leaderboard").json()["ranking"]
        assert ranking[0]["partner_wallet"] == PARTNER_WALLET_Y
        assert ranking[1]["partner_wallet"] == PARTNER_WALLET_X

    def test_observed_partners_rank_before_idle(self, partner_app) -> None:
        # X has 1 raw call (share 0.0); Y is idle (share None).
        # Observed must rank ABOVE idle so a new partner can never
        # "rank above" a partner with actual traffic just because they
        # haven't been measured yet.
        cx = _client_for(partner_app, PARTNER_SECRET_X)
        cx.get(f"/agents/{WALLET_A}/health")

        public = _client_for(partner_app, secret=None)
        ranking = public.get("/integrations/leaderboard").json()["ranking"]
        assert ranking[0]["partner_wallet"] == PARTNER_WALLET_X
        assert ranking[0]["safe_share"] == pytest.approx(0.0)
        assert ranking[1]["partner_wallet"] == PARTNER_WALLET_Y
        assert ranking[1]["safe_share"] is None
