"""
api/webhooks.py — DBP-4d cert-degrading freshness webhook surface.

DBP-4d closes the fourth substrate of the Path-4 (DeFi Bypass) chain
by giving the Insured-tier subscription a programmatic surface that
**warns BEFORE a partner's cert reaches expiry**. The audit-mandated
cert lifetime is 48 hours (`CERT_MAX_AGE_SECONDS`). At 75% of that
budget (36 hours) the cert is "degrading" — still valid, but the
partner's cluster operator has roughly 12 hours left to push a fresh
one before downstream protocols start refusing.

Without a webhook, a partner only learns about an aging cert when
their lending contract refuses a loan — i.e. after the damage.
With one, the partner's pager fires at 36 hours and they can rotate
proactively.

WHAT THIS MODULE PROVIDES
-------------------------
  * `WebhookRegistry`         — partner_wallet -> (url, secret). In-memory,
                                immutable after construction (rotation =
                                process restart, same as ApiKeyRegistry).
  * `compute_signature`       — HMAC-SHA256(secret, body_bytes) → hex.
  * `CertDegradingPayload`    — the JSON body shape.
  * `WebhookDispatcher`       — a Protocol; tests pass a list-collecting
                                fake, production wires an httpx-backed
                                impl. The reactive trigger uses whatever
                                is wired through `create_app`.
  * `CertDegradingTracker`    — dedupes (partner, agent, epoch) so a
                                partner who polls every 60s gets ONE
                                webhook per cert lifecycle, not 720.

WHY REACTIVE INSTEAD OF SCHEDULED
---------------------------------
phylanx-api has no scheduler substrate (no Celery, no APScheduler).
Reactively firing on the partner's own `/safe_score` poll is the
simplest correct behaviour: a partner who isn't polling has bigger
problems than a degrading cert; a partner who is polling gets a
near-real-time warning. The 60s polling cadence the SDK
recommends keeps the lag bound tight.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass
from typing import Protocol


logger = logging.getLogger("phylanx.api.webhooks")


# =============================================================================
# Audit-mandated constants
# =============================================================================
#
# The threshold is 75% of CERT_MAX_AGE_SECONDS so the partner has the
# remaining 25% (12 hours) to rotate before downstream protocols flip
# to STALE_CERT refusal. Bumping the threshold up tightens the warning;
# bumping it down (e.g. 90%) reduces the actionable window.

DEGRADING_THRESHOLD_FRACTION: float = 0.75


def degrading_threshold_seconds(cert_max_age_seconds: int) -> int:
    return int(cert_max_age_seconds * DEGRADING_THRESHOLD_FRACTION)


# =============================================================================
# Webhook registry
# =============================================================================

@dataclass(frozen=True)
class Webhook:
    """One partner's registered cert-degrading webhook.

    `partner_wallet` is the on-chain Verified-Integrator pubkey; the
    same string that's bound to the partner's API key.
    `url` is the HTTPS endpoint that receives the POST.
    `secret` is the HMAC-SHA256 signing key. We hold the RAW secret
    (not a hash) because we need to compute signatures with it — the
    registry is constructed once at startup from a sealed env var and
    never logged.
    """
    partner_wallet: str
    url:            str
    secret:         str


class WebhookRegistry:
    """In-memory immutable registry. Constructed once at startup.

    Operationally this matches the `ApiKeyRegistry` posture: rotation
    is a process restart; the registry never leaks the secrets to logs
    or metric labels.
    """

    def __init__(self, hooks: list[Webhook] | tuple[Webhook, ...] = ()) -> None:
        self._by_partner: dict[str, Webhook] = {}
        for h in hooks:
            if not h.partner_wallet:
                raise ValueError("WebhookRegistry: partner_wallet required")
            if h.partner_wallet in self._by_partner:
                raise ValueError(
                    f"WebhookRegistry: duplicate partner_wallet "
                    f"{h.partner_wallet!r}"
                )
            if not h.url.startswith(("https://", "http://")):
                raise ValueError(
                    f"WebhookRegistry: partner {h.partner_wallet!r} "
                    f"url must be http(s)://"
                )
            if not h.secret:
                raise ValueError(
                    f"WebhookRegistry: partner {h.partner_wallet!r} "
                    f"secret is empty"
                )
            self._by_partner[h.partner_wallet] = h

    def get(self, partner_wallet: str) -> Webhook | None:
        return self._by_partner.get(partner_wallet)

    def __len__(self) -> int:
        return len(self._by_partner)


def load_webhooks_from_env(env_var: str = "PHYLANX_WEBHOOKS") -> list[Webhook]:
    """Parse `partner_wallet:url:secret` lines into Webhook records.

    Blank lines and lines starting with `#` are skipped. Same multi-
    line block + comments shape as `PHYLANX_API_KEYS`.

    The colon separator in URLs (`https://...`) is handled by splitting
    AT MOST 2 times — that preserves the URL intact even when it
    contains a colon (port, scheme).
    """
    raw = os.environ.get(env_var, "")
    hooks: list[Webhook] = []
    for lineno, line in enumerate(raw.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # partner_wallet : url-with-colons : secret-no-colons
        # We split FROM THE RIGHT once to peel off the secret, then
        # FROM THE LEFT once to peel off the partner_wallet.
        head_url, _, secret = line.rpartition(":")
        partner_wallet, _, url = head_url.partition(":")
        partner_wallet = partner_wallet.strip()
        url = url.strip()
        secret = secret.strip()
        if not partner_wallet or not url or not secret:
            raise ValueError(
                f"{env_var} line {lineno}: "
                f"expected partner_wallet:url:secret"
            )
        hooks.append(Webhook(
            partner_wallet=partner_wallet, url=url, secret=secret,
        ))
    return hooks


# =============================================================================
# Payload + signature
# =============================================================================

# Header name partners look for. Pinned at module-level so a rename is
# a visible wire break (the linter could grep for it).
SIGNATURE_HEADER: str = "X-Phylanx-Webhook-Signature"
EVENT_HEADER:     str = "X-Phylanx-Webhook-Event"
EVENT_CERT_DEGRADING: str = "cert.degrading"

# Wire-stable schema version. Adding fields is additive; renaming or
# removing requires a version bump and a partner-coordinated migration.
WEBHOOK_SCHEMA_VERSION: int = 1


@dataclass(frozen=True)
class CertDegradingPayload:
    """The JSON body of the `cert.degrading` webhook.

    Wire shape is canonicalised by `to_json()` (sort_keys + no spaces)
    so the HMAC signature is reproducible on the partner's side.
    """
    schema_version:        int
    event:                 str       # always EVENT_CERT_DEGRADING for this hook
    partner_wallet:        str
    agent_wallet:          str
    epoch:                 int
    issued_at_unix:        int
    cert_age_seconds:      int
    threshold_seconds:     int
    cert_max_age_seconds:  int
    sent_at_unix:          int       # so the partner can detect clock skew

    def to_json(self) -> bytes:
        # Canonical JSON: sort_keys=True + no whitespace → exact bytes
        # the partner re-hashes with the shared secret to verify.
        return json.dumps(
            {
                "_v":                   self.schema_version,
                "event":                self.event,
                "partner_wallet":       self.partner_wallet,
                "agent_wallet":         self.agent_wallet,
                "epoch":                self.epoch,
                "issued_at_unix":       self.issued_at_unix,
                "cert_age_seconds":     self.cert_age_seconds,
                "threshold_seconds":    self.threshold_seconds,
                "cert_max_age_seconds": self.cert_max_age_seconds,
                "sent_at_unix":         self.sent_at_unix,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


def compute_signature(secret: str, body_bytes: bytes) -> str:
    """HMAC-SHA256(secret, body) → hex. The wire format the partner
    re-computes to verify a delivery is from Phylanx and not a forgery."""
    mac = hmac.new(
        secret.encode("utf-8"),
        body_bytes,
        hashlib.sha256,
    )
    return mac.hexdigest()


# =============================================================================
# Dispatcher protocol
# =============================================================================

class WebhookDispatcher(Protocol):
    """The contract the safe_score handler depends on.

    Tests pass a list-collecting fake; production wires an httpx-backed
    impl. The dispatcher MUST NOT block the request handler — it
    schedules the POST on the event loop and returns immediately.
    """
    def dispatch(
        self,
        *,
        hook:    Webhook,
        payload: CertDegradingPayload,
    ) -> None:
        ...


class NullDispatcher:
    """A no-op dispatcher. Default when no dispatcher is wired —
    the trigger still computes whether the cert is degrading (so
    metrics could be added later) but no HTTP call is made."""

    def dispatch(
        self,
        *,
        hook:    Webhook,
        payload: CertDegradingPayload,
    ) -> None:
        return None


# =============================================================================
# Per-process dedupe — fire ONE webhook per (partner, agent, epoch)
# =============================================================================

class CertDegradingTracker:
    """Tracks which (partner, agent, epoch) triples have already fired
    a cert.degrading webhook in this process.

    A partner who polls every 60s would otherwise receive 720 webhooks
    over the 12-hour degrading window for the same cert. We fire ONE,
    on first observation, then suppress until the cert advances to a
    new epoch.

    The tracker is in-memory and resets on process restart — that is
    intentional. A restart re-sends the warning on the next poll,
    which is exactly the desired behaviour after an unplanned outage.
    """

    def __init__(self) -> None:
        self._seen: set[tuple[str, str, int]] = set()

    def should_fire(self, partner_wallet: str, agent_wallet: str, epoch: int) -> bool:
        """Returns True iff this (partner, agent, epoch) has not yet
        fired in this process. Marks it as fired on True."""
        key = (partner_wallet, agent_wallet, epoch)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True

    def reset(self) -> None:
        self._seen.clear()
