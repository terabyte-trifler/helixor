"""
api/validation.py — VULN-20 input-validation primitives.

WHAT THIS FILE EXISTS FOR
-------------------------
The mitigation list for VULN-20 (TimescaleDB SQL injection) demands input
validation at the API boundary: wallet addresses MUST match a base58
shape BEFORE they are passed downstream. The data path already uses
parameterised queries — `cur.execute(sql, [params])` — so the SQLi
attack surface is already zero. This module is the second wall: a
syntactic gate that refuses obviously-malicious wallet strings at the
edge, so a single regression in the data layer cannot become a
catastrophic exfiltration.

WHY BASE58 AND NOT base58check
------------------------------
Solana addresses are base58-encoded 32-byte Ed25519 public keys. The
encoded form is ALWAYS 32..44 base58 characters from the Bitcoin
alphabet (`0`, `O`, `I`, `l` excluded). Real wallets cluster around
43-44 chars; the lower bound captures the leading-zero edge case. We
deliberately do NOT decode + range-check the underlying integer — that's
what the on-chain layer does. Validating the alphabet + length here
catches every shape an attacker could splice into SQL (quotes, spaces,
semicolons, comment markers, NULs) without needing a base58 library.

USAGE FROM ROUTES
-----------------
    from api.validation import validate_wallet, WalletValidationError
    ...
    @app.get("/agents/{wallet}/health")
    def agent_health(wallet: str = Depends(wallet_path)) -> ...:
        ...

USAGE FROM REPOSITORIES (defense in depth)
------------------------------------------
    from api.validation import ensure_wallet_safe
    def fetch_transactions(self, query):
        ensure_wallet_safe(query.agent_wallet)
        rows = self._conn.execute(_FETCH_WINDOW_SQL, [query.agent_wallet, ...])
"""

from __future__ import annotations

from fastapi import HTTPException


# =============================================================================
# Constants
# =============================================================================

# Bitcoin/Solana base58 alphabet — 0, O, I, l are intentionally excluded
# because they're visually indistinguishable from one another.
BASE58_ALPHABET = frozenset(
    "123456789"
    "ABCDEFGHJKLMNPQRSTUVWXYZ"
    "abcdefghijkmnopqrstuvwxyz"
)

# 32-byte Ed25519 pubkeys encode to 32..44 base58 chars. The lower bound
# is for leading-zero pubkeys (which compress to fewer chars); real
# wallets cluster at 43-44.
MIN_WALLET_LENGTH = 32
MAX_WALLET_LENGTH = 44


# =============================================================================
# Errors
# =============================================================================

class WalletValidationError(ValueError):
    """Raised by the repository-side guard for non-base58 wallets."""


# =============================================================================
# The core check
# =============================================================================

def is_valid_wallet(s: str) -> bool:
    """Pure predicate. True iff `s` looks like a Solana wallet address."""
    if not isinstance(s, str):
        return False
    if not (MIN_WALLET_LENGTH <= len(s) <= MAX_WALLET_LENGTH):
        return False
    return all(c in BASE58_ALPHABET for c in s)


def _explain(s: str) -> str:
    """A specific reason string for the error. Helps the operator debug
    a real client bug while staying generic enough not to leak
    server-side detail."""
    if not isinstance(s, str):
        return "wallet must be a string"
    n = len(s)
    if n < MIN_WALLET_LENGTH:
        return f"wallet too short ({n} chars; min {MIN_WALLET_LENGTH})"
    if n > MAX_WALLET_LENGTH:
        return f"wallet too long ({n} chars; max {MAX_WALLET_LENGTH})"
    bad = next((c for c in s if c not in BASE58_ALPHABET), None)
    if bad is not None:
        return (
            f"wallet contains non-base58 character {bad!r} "
            f"(allowed: {MIN_WALLET_LENGTH}..{MAX_WALLET_LENGTH} chars from "
            f"the Bitcoin base58 alphabet)"
        )
    return "wallet validation failed"


# =============================================================================
# Entrypoint: FastAPI route guard
# =============================================================================

def validate_wallet(wallet: str) -> str:
    """
    FastAPI-friendly validator. Raises HTTPException(400) on rejection,
    returns the (unchanged) wallet on success.

    Use as the very first line of any route that accepts a wallet, OR
    via FastAPI's `Depends(...)` if you want it factored out:

        from fastapi import Depends
        def wallet_path(wallet: str) -> str:
            return validate_wallet(wallet)
        @app.get("/agents/{wallet}/health")
        def health(wallet: str = Depends(wallet_path)): ...
    """
    if not is_valid_wallet(wallet):
        raise HTTPException(status_code=400, detail=_explain(wallet))
    return wallet


# =============================================================================
# Entrypoint: repository-side guard (defense in depth)
# =============================================================================

def ensure_wallet_safe(wallet: str) -> None:
    """
    Library-side guard. Raises `WalletValidationError` — NOT an
    HTTPException — because the oracle code path runs outside FastAPI.
    Use at the entry of any repository method that includes the wallet
    in a SQL parameter list, even though `%s` binding is already safe.
    The intent is to make a future bad refactor (e.g. someone splicing
    `wallet` into an f-string) fail closed: the value is already known
    to be syntactically harmless.
    """
    if not is_valid_wallet(wallet):
        raise WalletValidationError(_explain(wallet))
