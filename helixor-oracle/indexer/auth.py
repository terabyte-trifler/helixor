"""
indexer/auth.py — verify Helius webhook authenticity.

Helius supports an `authHeader` parameter on webhook registration. They send
that exact value back in the Authorization header on every POST. We verify
constant-time to prevent timing attacks.

Without this check, anyone who guesses our webhook URL can flood us with
fake transactions.
"""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status

from indexer.config import settings


def verify_webhook_auth(
    authorization: str | None = Header(default=None),
) -> None:
    """
    FastAPI dependency that verifies the Authorization header.

    Use as: `@app.post("/webhook", dependencies=[Depends(verify_webhook_auth)])`
    """
    expected = settings.helius_webhook_auth_token.get_secret_value()

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    # Constant-time comparison — prevents timing attacks where an attacker
    # measures response time to recover the token byte-by-byte.
    if not hmac.compare_digest(authorization, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization token",
        )
