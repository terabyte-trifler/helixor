"""
api/validation.py — input validation that returns 400, not 500.

Solana pubkeys are base58 strings of length 32-44. solders raises ValueError
on bad input. We catch + return a clean 400 with a usable error message.
"""

from __future__ import annotations

import re

from fastapi import HTTPException, status

# Solana pubkeys are base58, ~32-44 chars
_PUBKEY_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


def validate_agent_wallet(agent_wallet: str) -> str:
    """Validate base58 pubkey shape. Raises HTTPException(400) on invalid."""
    if not agent_wallet:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "agent_wallet is required",
                "code":  "INVALID_AGENT_WALLET",
            },
        )
    if not _PUBKEY_RE.match(agent_wallet):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "agent_wallet is not a valid base58 Solana pubkey",
                "code":  "INVALID_AGENT_WALLET",
            },
        )

    # Defensive: validate via solders too (catches edge cases re_RE misses)
    try:
        from solders.pubkey import Pubkey
        Pubkey.from_string(agent_wallet)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "agent_wallet is not a valid Solana pubkey",
                "code":  "INVALID_AGENT_WALLET",
            },
        )

    return agent_wallet
