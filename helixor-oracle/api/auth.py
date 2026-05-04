"""
api/auth.py — shared helpers for Helixor bearer API keys.
"""

from __future__ import annotations

import hashlib


API_KEY_PREFIX = "hxop_"


def extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.removeprefix("Bearer ").strip()
    return token or None


def hash_api_key(raw: str) -> str:
    """sha256 hex of raw API key. Never store or log the raw key."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def looks_like_operator_key(raw: str | None) -> bool:
    return bool(raw and raw.startswith(API_KEY_PREFIX) and 20 <= len(raw) <= 80)
