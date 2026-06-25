"""
api/auth.py — VULN-09 API key authentication.

Two-tier authentication model:

  - PUBLIC          — no key. Subject to the lower per-IP rate-limit
                      (default 100/min). Sufficient for casual integrators
                      and dashboards.
  - AUTHENTICATED   — an `X-API-Key` header presents a key that was
                      registered with the service at startup. Subject to
                      the higher per-key rate-limit (default 1000/min).

Some endpoints (the SENSITIVE-OPERATIONAL set — `/health/cluster`,
`/byzantine/*`, `/challenges`) require a valid key UNCONDITIONALLY. The
audit flagged these as oracle behavioural fingerprinting + investigation
intelligence; they must not be open to anonymous traffic.

KEY STORAGE
-----------
Keys are stored as `sha256(secret)`. The raw secret is discarded after
construction — it never lives in service memory after startup and never
appears in logs or metric labels. The opaque `key_id` is what we emit.

LOOKUPS ARE CONSTANT-TIME
-------------------------
`ApiKeyRegistry.lookup` walks every registered key on every call and
uses `hmac.compare_digest`. An attacker probing the API cannot time how
close their guess is to a real key, nor learn how many keys are
registered.

ROTATION
--------
The registry is immutable after construction — rotation is a process
restart. This matches the operational pattern: keys are managed by the
deploy system (PHYLANX_API_KEYS env var), and a rotation rolls the
running process.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from dataclasses import dataclass
from typing import Iterable

from fastapi import Header, HTTPException, status


logger = logging.getLogger("phylanx.api.auth")


# =============================================================================
# Defaults
# =============================================================================

DEFAULT_KEY_RATE_LIMIT_PER_MIN: int = 1_000


# =============================================================================
# The key record
# =============================================================================

@dataclass(frozen=True)
class ApiKey:
    """One registered API key.

    `key_id` is an opaque, stable identifier safe to emit in logs and
    metric labels. `secret_hash` is the hex sha256 of the raw secret —
    the raw secret is discarded after construction.

    `tier` is a free-form accounting label ("basic", "partner",
    "internal"). `rate_limit_per_minute` is the per-key sliding-window
    cap that overrides the per-IP cap for authenticated requests.

    DBP-4 — partner identity binding
    --------------------------------
    `partner_wallet` is the base58 Solana pubkey of the on-chain
    `VerifiedConsumer` PDA holder that this key represents. None means
    "no partner binding" — the key is a generic basic/internal key, not
    a Verified-Integrator key. The leaderboard endpoint only ranks keys
    that carry a partner_wallet.
    """

    key_id:                str
    secret_hash:           str   # hex sha256
    tier:                  str
    rate_limit_per_minute: int
    partner_wallet:        str | None = None

    @classmethod
    def from_secret(
        cls,
        *,
        key_id:                str,
        secret:                str,
        tier:                  str = "basic",
        rate_limit_per_minute: int = DEFAULT_KEY_RATE_LIMIT_PER_MIN,
        partner_wallet:        str | None = None,
    ) -> "ApiKey":
        if not key_id:
            raise ValueError("ApiKey.from_secret: key_id is required")
        if not secret:
            raise ValueError("ApiKey.from_secret: secret is required")
        if rate_limit_per_minute < 1:
            raise ValueError(
                "ApiKey.from_secret: rate_limit_per_minute must be >= 1"
            )
        if partner_wallet is not None:
            pw = partner_wallet.strip()
            if not pw:
                # Treat an empty string as "no binding" — same shape as None.
                partner_wallet = None
            else:
                # Solana base58 pubkey: 32..44 chars in the bitcoin alphabet.
                # We validate shape here so the leaderboard / metric labels
                # never carry a malformed value.
                if not (32 <= len(pw) <= 44):
                    raise ValueError(
                        "ApiKey.from_secret: partner_wallet must be a "
                        "32..44-char base58 Solana pubkey"
                    )
                _BASE58 = (
                    "123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
                    "abcdefghijkmnopqrstuvwxyz"
                )
                if not all(c in _BASE58 for c in pw):
                    raise ValueError(
                        "ApiKey.from_secret: partner_wallet contains "
                        "non-base58 characters"
                    )
                partner_wallet = pw
        return cls(
            key_id=key_id,
            secret_hash=hashlib.sha256(secret.encode("utf-8")).hexdigest(),
            tier=tier,
            rate_limit_per_minute=rate_limit_per_minute,
            partner_wallet=partner_wallet,
        )


# =============================================================================
# Registry
# =============================================================================

class ApiKeyRegistry:
    """Immutable in-memory registry of `ApiKey` records.

    Construction validates that key_ids are unique. Lookups are
    constant-time across the registry so an attacker cannot side-channel
    either (a) which guess matched, or (b) how many keys exist.
    """

    def __init__(self, keys: Iterable[ApiKey] = ()) -> None:
        self._keys: tuple[ApiKey, ...] = tuple(keys)
        ids = [k.key_id for k in self._keys]
        if len(ids) != len(set(ids)):
            raise ValueError("ApiKeyRegistry: duplicate key_id")

    def __len__(self) -> int:
        return len(self._keys)

    def is_empty(self) -> bool:
        return not self._keys

    def lookup(self, raw_secret: str) -> ApiKey | None:
        """Constant-time lookup by raw secret. Returns the matched key
        or None.

        The loop runs to completion regardless of an early match so that
        an attacker timing the response cannot determine the position of
        their guess in the registry. With an empty registry this is a
        single guarded return.
        """
        if not raw_secret:
            return None
        if not self._keys:
            return None
        candidate = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()
        matched: ApiKey | None = None
        for key in self._keys:
            if hmac.compare_digest(candidate, key.secret_hash):
                # Keep iterating — early-break would leak timing.
                matched = key
        return matched


# =============================================================================
# FastAPI dependencies
# =============================================================================

def require_api_key(registry: ApiKeyRegistry):
    """Build a FastAPI dependency that requires a valid `X-API-Key`.

    Returns the matched `ApiKey`. Raises 401 on missing/invalid key.

    The detail message is intentionally identical for both cases so an
    attacker cannot distinguish "no key sent" from "wrong key sent".
    """

    def _dep(x_api_key: str | None = Header(default=None)) -> ApiKey:
        key = registry.lookup(x_api_key or "")
        if key is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="X-API-Key header required for this endpoint",
            )
        return key

    return _dep


# =============================================================================
# Env loading — production reads PHYLANX_API_KEYS at startup
# =============================================================================

def load_keys_from_env(env_var: str = "PHYLANX_API_KEYS") -> list[ApiKey]:
    """Parse the configured env var into a list of `ApiKey` records.

    FORMAT: newline-separated
    `key_id:secret[:tier[:limit_per_min[:partner_wallet]]]` records.
    Blank lines and lines starting with `#` are skipped so an operator
    can manage the value as a multi-line block with comments.

    DBP-4: the optional 5th field binds the key to a Solana
    `partner_wallet`. Verified-Integrator keys MUST carry the partner
    wallet so per-partner telemetry (safe-reader share, leaderboard
    rank, cert-degrading webhooks) can attribute every call to the
    correct on-chain identity.

    Unset / empty means "no keys registered". Operational endpoints will
    then 401 every request — the correct posture for an unconfigured
    production service. Public endpoints still serve at the per-IP cap.
    """
    raw = os.environ.get(env_var, "")
    keys: list[ApiKey] = []
    for lineno, line in enumerate(raw.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2 or len(parts) > 5:
            raise ValueError(
                f"{env_var} line {lineno}: expected "
                f"key_id:secret[:tier[:limit_per_min[:partner_wallet]]]"
            )
        key_id = parts[0].strip()
        secret = parts[1]
        tier   = parts[2].strip() if len(parts) >= 3 and parts[2] else "basic"
        limit_str = parts[3].strip() if len(parts) >= 4 else ""
        limit  = int(limit_str) if limit_str else DEFAULT_KEY_RATE_LIMIT_PER_MIN
        partner_wallet = parts[4].strip() if len(parts) >= 5 and parts[4] else None
        if not key_id or not secret:
            raise ValueError(
                f"{env_var} line {lineno}: empty key_id or secret"
            )
        keys.append(ApiKey.from_secret(
            key_id=key_id, secret=secret, tier=tier,
            rate_limit_per_minute=limit,
            partner_wallet=partner_wallet,
        ))
    return keys
