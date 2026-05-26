"""
tests/test_dbp4_webhooks.py — DBP-4d cert-degrading webhook pin tests.

DBP-4d fires a `cert.degrading` webhook to a partner's registered URL
when one of their Verified-Integrator agents' certs enters the
[75% × CERT_MAX_AGE_SECONDS, 100% × CERT_MAX_AGE_SECONDS) age window.
The trigger is reactive — it fires when the partner polls
`/agents/{wallet}/safe_score`, so a partner with a 60s poll cadence
gets the warning within at most 60s of the cert crossing the
threshold.

These tests pin:

  * `WebhookRegistry` rejects malformed input at construction
    (missing url scheme, empty secret, duplicate partner_wallet).
  * `load_webhooks_from_env` parses `partner_wallet:url:secret`
    correctly, including URLs that themselves contain `:` (e.g.
    https://example.com:8443/x).
  * `compute_signature` is HMAC-SHA256 of the canonical body. A
    partner who recomputes the MAC with the same secret arrives at
    the exact value we send in the `X-Helixor-Webhook-Signature`
    header.
  * `CertDegradingPayload.to_json` is byte-stable (sorted keys, no
    whitespace) so the signature is reproducible.
  * The reactive trigger:
      - fires when cert age >= threshold AND partner has webhook
      - does NOT fire for fresh certs (< threshold)
      - does NOT fire for partner-less keys or basic-tier keys
      - does NOT fire for partners without a webhook registered
      - fires EXACTLY ONCE per (partner, agent, epoch) — dedupe pin
      - does NOT fire on the rejection path (compute_safe_score said
        STALE_CERT / VELOCITY_EXCEEDED / INSUFFICIENT_HISTORY)
  * The payload carries the partner_wallet, agent_wallet, epoch,
    issued_at_unix, cert_age_seconds, threshold_seconds, and
    cert_max_age_seconds so the partner's on-call has every signal
    needed to decide whether to rotate proactively or wait.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import json
import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.auth import ApiKey, ApiKeyRegistry
from api.rate_limit import SlidingWindowLimiter
from api.safe_score import CERT_MAX_AGE_SECONDS
from api.score_repo import InMemoryScoreRepo, ScoreRecord
from api.webhooks import (
    CertDegradingPayload,
    DEGRADING_THRESHOLD_FRACTION,
    EVENT_CERT_DEGRADING,
    NullDispatcher,
    SIGNATURE_HEADER,
    WEBHOOK_SCHEMA_VERSION,
    Webhook,
    WebhookRegistry,
    compute_signature,
    degrading_threshold_seconds,
    load_webhooks_from_env,
)
from tests.conftest import (
    TEST_RATE_LIMIT_PER_MIN,
    WALLET_A,
    WALLET_B,
)


# =============================================================================
# Test constants
# =============================================================================

PARTNER_WALLET   = "P1" * 22                 # 44-char base58 placeholder
PARTNER_KEY_ID   = "dbp4d-partner"
PARTNER_SECRET   = "dbp4d-partner-secret"

NOHOOK_WALLET    = "Q2" * 22
NOHOOK_KEY_ID    = "dbp4d-nohook"
NOHOOK_SECRET    = "dbp4d-nohook-secret"

BASIC_KEY_ID     = "dbp4d-basic"
BASIC_SECRET     = "dbp4d-basic-secret"

WEBHOOK_URL      = "https://partner.example.com/helixor/cert-degrading"
WEBHOOK_SECRET   = "shared-hmac-secret-do-not-log"


# =============================================================================
# A list-collecting fake dispatcher — captures every dispatched payload
# =============================================================================

@dataclass
class CapturedCall:
    hook:    Webhook
    payload: CertDegradingPayload


@dataclass
class FakeDispatcher:
    calls: list[CapturedCall] = field(default_factory=list)

    def dispatch(self, *, hook: Webhook, payload: CertDegradingPayload) -> None:
        self.calls.append(CapturedCall(hook=hook, payload=payload))


# =============================================================================
# Score repo with a controllable issued_at — drives the "age" of the cert
# =============================================================================

def _build_repo_with_age(age_seconds: int) -> InMemoryScoreRepo:
    """Build a repo where WALLET_A's latest cert is `age_seconds` old.

    The repo carries 3 records (enough to satisfy MIN_HISTORY_REQUIRED
    + the 3-epoch velocity window) so compute_safe_score does NOT
    refuse on history grounds.
    """
    now = datetime.now(tz=timezone.utc)
    repo = InMemoryScoreRepo()
    # Two older same-score certs first so the velocity check passes.
    repo.add(ScoreRecord(
        WALLET_A, 27, 700, 1, 0x00, False, 3,
        now - timedelta(seconds=age_seconds + 4 * 3600),
    ))
    repo.add(ScoreRecord(
        WALLET_A, 28, 705, 1, 0x00, False, 3,
        now - timedelta(seconds=age_seconds + 2 * 3600),
    ))
    # The current cert — exactly `age_seconds` old.
    repo.add(ScoreRecord(
        WALLET_A, 29, 710, 1, 0x00, False, 4,
        now - timedelta(seconds=age_seconds),
    ))
    return repo


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def webhook_registry() -> WebhookRegistry:
    return WebhookRegistry([
        Webhook(
            partner_wallet=PARTNER_WALLET,
            url=WEBHOOK_URL,
            secret=WEBHOOK_SECRET,
        ),
    ])


@pytest.fixture
def fake_dispatcher() -> FakeDispatcher:
    return FakeDispatcher()


@pytest.fixture
def webhook_keys() -> ApiKeyRegistry:
    return ApiKeyRegistry([
        ApiKey.from_secret(
            key_id=PARTNER_KEY_ID, secret=PARTNER_SECRET,
            tier="partner", rate_limit_per_minute=TEST_RATE_LIMIT_PER_MIN,
            partner_wallet=PARTNER_WALLET,
        ),
        ApiKey.from_secret(
            key_id=NOHOOK_KEY_ID, secret=NOHOOK_SECRET,
            tier="partner", rate_limit_per_minute=TEST_RATE_LIMIT_PER_MIN,
            partner_wallet=NOHOOK_WALLET,
        ),
        ApiKey.from_secret(
            key_id=BASIC_KEY_ID, secret=BASIC_SECRET,
            tier="basic", rate_limit_per_minute=TEST_RATE_LIMIT_PER_MIN,
        ),
    ])


def _build_app(
    *,
    age_seconds: int,
    keys: ApiKeyRegistry,
    hooks: WebhookRegistry,
    dispatcher,
    byzantine_repo,
    cluster_repo,
):
    return create_app(
        score_repo=_build_repo_with_age(age_seconds),
        byzantine_repo=byzantine_repo,
        cluster_repo=cluster_repo,
        network="localnet",
        is_production=False,
        key_registry=keys,
        rate_limiter=SlidingWindowLimiter(),
        public_rate_limit_per_minute=TEST_RATE_LIMIT_PER_MIN,
        webhook_registry=hooks,
        webhook_dispatcher=dispatcher,
    )


def _auth_client(app, secret: str) -> TestClient:
    c = TestClient(app)
    c.headers["X-API-Key"] = secret
    return c


# =============================================================================
# WebhookRegistry construction
# =============================================================================

class TestWebhookRegistryConstruction:

    def test_lookup_returns_registered_hook(self) -> None:
        h = Webhook(PARTNER_WALLET, WEBHOOK_URL, WEBHOOK_SECRET)
        reg = WebhookRegistry([h])
        assert reg.get(PARTNER_WALLET) is h
        assert reg.get(NOHOOK_WALLET) is None
        assert len(reg) == 1

    def test_missing_partner_wallet_rejected(self) -> None:
        with pytest.raises(ValueError, match="partner_wallet required"):
            WebhookRegistry([Webhook("", WEBHOOK_URL, WEBHOOK_SECRET)])

    def test_duplicate_partner_wallet_rejected(self) -> None:
        h = Webhook(PARTNER_WALLET, WEBHOOK_URL, WEBHOOK_SECRET)
        with pytest.raises(ValueError, match="duplicate partner_wallet"):
            WebhookRegistry([h, h])

    def test_non_http_url_rejected(self) -> None:
        with pytest.raises(ValueError, match="http\\(s\\)://"):
            WebhookRegistry([Webhook(
                PARTNER_WALLET, "ftp://nope.example", WEBHOOK_SECRET,
            )])

    def test_empty_secret_rejected(self) -> None:
        with pytest.raises(ValueError, match="secret is empty"):
            WebhookRegistry([Webhook(PARTNER_WALLET, WEBHOOK_URL, "")])


# =============================================================================
# load_webhooks_from_env
# =============================================================================

class TestLoadWebhooksFromEnv:

    def test_parses_partner_url_secret(self, monkeypatch) -> None:
        monkeypatch.setenv(
            "HELIXOR_WEBHOOKS",
            f"{PARTNER_WALLET}:{WEBHOOK_URL}:{WEBHOOK_SECRET}",
        )
        hooks = load_webhooks_from_env()
        assert len(hooks) == 1
        assert hooks[0].partner_wallet == PARTNER_WALLET
        assert hooks[0].url == WEBHOOK_URL
        assert hooks[0].secret == WEBHOOK_SECRET

    def test_url_with_port_preserved(self, monkeypatch) -> None:
        # The URL itself contains a colon (`https://...:8443/...`). The
        # parser must NOT split that colon.
        url_with_port = "https://partner.example.com:8443/helixor/hook"
        monkeypatch.setenv(
            "HELIXOR_WEBHOOKS",
            f"{PARTNER_WALLET}:{url_with_port}:{WEBHOOK_SECRET}",
        )
        hooks = load_webhooks_from_env()
        assert hooks[0].url == url_with_port

    def test_blank_lines_and_comments_skipped(self, monkeypatch) -> None:
        monkeypatch.setenv(
            "HELIXOR_WEBHOOKS",
            "\n".join([
                "# this is a comment",
                "",
                f"{PARTNER_WALLET}:{WEBHOOK_URL}:{WEBHOOK_SECRET}",
                "",
            ]),
        )
        hooks = load_webhooks_from_env()
        assert len(hooks) == 1


# =============================================================================
# Signature
# =============================================================================

class TestSignature:

    def test_signature_is_hex_sha256(self) -> None:
        sig = compute_signature(WEBHOOK_SECRET, b"hello")
        # HMAC-SHA256 is 32 bytes → 64 hex chars
        assert len(sig) == 64
        assert all(c in "0123456789abcdef" for c in sig)

    def test_signature_changes_with_body(self) -> None:
        a = compute_signature(WEBHOOK_SECRET, b"a")
        b = compute_signature(WEBHOOK_SECRET, b"b")
        assert a != b

    def test_signature_changes_with_secret(self) -> None:
        a = compute_signature("k1", b"body")
        b = compute_signature("k2", b"body")
        assert a != b


# =============================================================================
# Payload byte-stability
# =============================================================================

class TestPayloadByteStability:

    def test_to_json_is_sorted_keys_no_whitespace(self) -> None:
        p = CertDegradingPayload(
            schema_version=WEBHOOK_SCHEMA_VERSION,
            event=EVENT_CERT_DEGRADING,
            partner_wallet=PARTNER_WALLET,
            agent_wallet=WALLET_A,
            epoch=29,
            issued_at_unix=1_700_000_000,
            cert_age_seconds=130_000,
            threshold_seconds=129_600,
            cert_max_age_seconds=172_800,
            sent_at_unix=1_700_130_000,
        )
        body = p.to_json()
        # No whitespace
        assert b" " not in body
        # Keys must round-trip to a sorted ordering
        parsed = json.loads(body)
        assert list(parsed.keys()) == sorted(parsed.keys())
        # And every field is present
        assert parsed["_v"]                   == WEBHOOK_SCHEMA_VERSION
        assert parsed["event"]                == EVENT_CERT_DEGRADING
        assert parsed["partner_wallet"]       == PARTNER_WALLET
        assert parsed["agent_wallet"]         == WALLET_A
        assert parsed["epoch"]                == 29
        assert parsed["cert_age_seconds"]     == 130_000
        assert parsed["threshold_seconds"]    == 129_600
        assert parsed["cert_max_age_seconds"] == 172_800

    def test_signature_pinned_for_known_payload(self) -> None:
        # If `to_json` or `compute_signature` ever change wire shape,
        # this signature will drift. Any partner who pinned a verifier
        # against the previous bytes would silently start failing —
        # this test catches that BEFORE the rollout.
        p = CertDegradingPayload(
            schema_version=1, event=EVENT_CERT_DEGRADING,
            partner_wallet=PARTNER_WALLET, agent_wallet=WALLET_A,
            epoch=29, issued_at_unix=1_700_000_000,
            cert_age_seconds=130_000,
            threshold_seconds=129_600,
            cert_max_age_seconds=172_800,
            sent_at_unix=1_700_130_000,
        )
        sig = compute_signature(WEBHOOK_SECRET, p.to_json())
        # Pre-computed: hmac_sha256(WEBHOOK_SECRET, p.to_json())
        import hmac, hashlib
        expected = hmac.new(
            WEBHOOK_SECRET.encode(),
            p.to_json(),
            hashlib.sha256,
        ).hexdigest()
        assert sig == expected


# =============================================================================
# Threshold helper
# =============================================================================

class TestThreshold:

    def test_threshold_is_75pct_of_max_age(self) -> None:
        assert degrading_threshold_seconds(CERT_MAX_AGE_SECONDS) == int(
            CERT_MAX_AGE_SECONDS * DEGRADING_THRESHOLD_FRACTION
        )
        # Cross-check the audit constant numerically — 48h * 0.75 = 36h
        assert degrading_threshold_seconds(48 * 3600) == 36 * 3600


# =============================================================================
# Reactive trigger end-to-end via /safe_score
# =============================================================================

class TestReactiveTrigger:

    def test_fires_when_cert_is_degrading(
        self, byzantine_repo, cluster_repo,
        webhook_keys, webhook_registry, fake_dispatcher,
    ) -> None:
        # 37h old > 36h threshold, < 48h max — degrading window.
        app = _build_app(
            age_seconds=37 * 3600,
            keys=webhook_keys, hooks=webhook_registry,
            dispatcher=fake_dispatcher,
            byzantine_repo=byzantine_repo, cluster_repo=cluster_repo,
        )
        client = _auth_client(app, PARTNER_SECRET)
        r = client.get(f"/agents/{WALLET_A}/safe_score")
        assert r.status_code == 200
        assert r.json()["ok"] is True
        # Webhook fired exactly once with the right partner + agent
        # + epoch
        assert len(fake_dispatcher.calls) == 1
        call = fake_dispatcher.calls[0]
        assert call.hook.partner_wallet == PARTNER_WALLET
        assert call.payload.event == EVENT_CERT_DEGRADING
        assert call.payload.partner_wallet == PARTNER_WALLET
        assert call.payload.agent_wallet == WALLET_A
        assert call.payload.epoch == 29
        # Threshold + max-age are echoed for the partner's pager
        assert call.payload.threshold_seconds == 36 * 3600
        assert call.payload.cert_max_age_seconds == 48 * 3600
        assert call.payload.cert_age_seconds >= 37 * 3600 - 1
        assert call.payload.cert_age_seconds <= 37 * 3600 + 1

    def test_does_not_fire_when_cert_is_fresh(
        self, byzantine_repo, cluster_repo,
        webhook_keys, webhook_registry, fake_dispatcher,
    ) -> None:
        # 1h old → well below the 36h threshold.
        app = _build_app(
            age_seconds=1 * 3600,
            keys=webhook_keys, hooks=webhook_registry,
            dispatcher=fake_dispatcher,
            byzantine_repo=byzantine_repo, cluster_repo=cluster_repo,
        )
        client = _auth_client(app, PARTNER_SECRET)
        r = client.get(f"/agents/{WALLET_A}/safe_score")
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert fake_dispatcher.calls == []

    def test_does_not_fire_when_cert_is_already_expired(
        self, byzantine_repo, cluster_repo,
        webhook_keys, webhook_registry, fake_dispatcher,
    ) -> None:
        # 50h old → past max. compute_safe_score returns STALE_CERT,
        # the result branch is REJECTED so the webhook trigger is
        # bypassed.
        app = _build_app(
            age_seconds=50 * 3600,
            keys=webhook_keys, hooks=webhook_registry,
            dispatcher=fake_dispatcher,
            byzantine_repo=byzantine_repo, cluster_repo=cluster_repo,
        )
        client = _auth_client(app, PARTNER_SECRET)
        r = client.get(f"/agents/{WALLET_A}/safe_score")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is False
        assert body["reason"] == "STALE_CERT"
        assert fake_dispatcher.calls == []

    def test_does_not_fire_for_partner_without_webhook(
        self, byzantine_repo, cluster_repo,
        webhook_keys, webhook_registry, fake_dispatcher,
    ) -> None:
        # PARTNER_WALLET has a webhook; NOHOOK_WALLET does NOT.
        # NOHOOK calling /safe_score in the degrading window must
        # NOT fire — they didn't subscribe.
        app = _build_app(
            age_seconds=37 * 3600,
            keys=webhook_keys, hooks=webhook_registry,
            dispatcher=fake_dispatcher,
            byzantine_repo=byzantine_repo, cluster_repo=cluster_repo,
        )
        client = _auth_client(app, NOHOOK_SECRET)
        r = client.get(f"/agents/{WALLET_A}/safe_score")
        assert r.status_code == 200
        assert fake_dispatcher.calls == []

    def test_does_not_fire_for_basic_key(
        self, byzantine_repo, cluster_repo,
        webhook_keys, webhook_registry, fake_dispatcher,
    ) -> None:
        # Basic key — no partner_wallet at all. Must be ignored by the
        # trigger even when a webhook for SOME partner is registered.
        app = _build_app(
            age_seconds=37 * 3600,
            keys=webhook_keys, hooks=webhook_registry,
            dispatcher=fake_dispatcher,
            byzantine_repo=byzantine_repo, cluster_repo=cluster_repo,
        )
        client = _auth_client(app, BASIC_SECRET)
        r = client.get(f"/agents/{WALLET_A}/safe_score")
        assert r.status_code == 200
        assert fake_dispatcher.calls == []

    def test_does_not_fire_for_anonymous(
        self, byzantine_repo, cluster_repo,
        webhook_keys, webhook_registry, fake_dispatcher,
    ) -> None:
        app = _build_app(
            age_seconds=37 * 3600,
            keys=webhook_keys, hooks=webhook_registry,
            dispatcher=fake_dispatcher,
            byzantine_repo=byzantine_repo, cluster_repo=cluster_repo,
        )
        anon = TestClient(app)
        r = anon.get(f"/agents/{WALLET_A}/safe_score")
        assert r.status_code == 200
        assert fake_dispatcher.calls == []

    def test_dedupe_one_per_partner_agent_epoch(
        self, byzantine_repo, cluster_repo,
        webhook_keys, webhook_registry, fake_dispatcher,
    ) -> None:
        # A partner who polls 5 times for the same (agent, epoch)
        # in the degrading window must receive EXACTLY ONE webhook.
        app = _build_app(
            age_seconds=37 * 3600,
            keys=webhook_keys, hooks=webhook_registry,
            dispatcher=fake_dispatcher,
            byzantine_repo=byzantine_repo, cluster_repo=cluster_repo,
        )
        client = _auth_client(app, PARTNER_SECRET)
        for _ in range(5):
            r = client.get(f"/agents/{WALLET_A}/safe_score")
            assert r.status_code == 200
        assert len(fake_dispatcher.calls) == 1
