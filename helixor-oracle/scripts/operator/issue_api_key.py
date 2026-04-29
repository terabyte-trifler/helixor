#!/usr/bin/env python3
"""
scripts/operator/issue_api_key.py — provision a new Helixor operator + API key.

Day 12: when a real operator wants to integrate the plugin in production,
the Helixor team runs this once to issue them an API key. The key gets:
  - Higher rate limits (free → partner tier)
  - Tagged telemetry (we can answer "what is operator X doing")
  - whoami endpoint access for confirmation

Usage:
    python -m scripts.operator.issue_api_key \
        --org "ACME Trading" \
        --email "ops@acme.example" \
        --discord "acmeops" \
        --tier partner

Prints the API key ONCE. We never store the raw key — only the sha256 hash.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import secrets
import sys

import structlog

from indexer import db

log = structlog.get_logger()


async def run(
    organization: str,
    email:        str | None,
    discord:      str | None,
    tier:         str,
    notes:        str,
) -> int:
    structlog.configure(processors=[structlog.dev.ConsoleRenderer()])
    await db.init_pool()
    pool = await db.get_pool()

    # Generate 32 bytes of randomness, base32 for legibility, prefix `hxop_`
    raw_key = "hxop_" + secrets.token_urlsafe(24).rstrip("=")
    key_hash   = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:8]

    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO operators (
                    api_key_hash, api_key_prefix,
                    contact_email, discord_handle, organization, notes,
                    tier
                ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING id
                """,
                key_hash, key_prefix, email, discord, organization, notes, tier,
            )

        print()
        print("╔══════════════════════════════════════════════════════════╗")
        print("║  Operator provisioned                                    ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print()
        print(f"  operator_id : {row['id']}")
        print(f"  organization: {organization}")
        print(f"  tier        : {tier}")
        print(f"  contact     : {email or '(none)'}")
        print(f"  discord     : {discord or '(none)'}")
        print()
        print("  ┌──────────────────────────────────────────────────────┐")
        print("  │  API KEY (save this — we cannot show it again)       │")
        print("  ├──────────────────────────────────────────────────────┤")
        print(f"  │  {raw_key}")
        print("  └──────────────────────────────────────────────────────┘")
        print()
        print("  Operator config — add to their .env:")
        print(f"      HELIXOR_API_KEY={raw_key}")
        print()
        return 0

    finally:
        await db.close_pool()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--org",     dest="organization", required=True)
    p.add_argument("--email",   default=None)
    p.add_argument("--discord", default=None)
    p.add_argument("--tier",    choices=["free", "partner", "team"],
                   default="partner")
    p.add_argument("--notes",   default="")
    args = p.parse_args()

    sys.exit(asyncio.run(run(args.organization, args.email,
                              args.discord, args.tier, args.notes)))


if __name__ == "__main__":
    main()
