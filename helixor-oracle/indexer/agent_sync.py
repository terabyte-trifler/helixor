"""
indexer/agent_sync.py — sync on-chain AgentRegistration → registered_agents table.

Two strategies (we run both):
  1. Realtime: subscribe to AgentRegistered events via WebSocket logs.
  2. Backfill: poll on a timer and re-fetch all program accounts.

Strategy 2 is the safety net: if the WS connection drops and we miss an
event, the next backfill catches it. Within 2 minutes of registration, the
agent IS in our table, even if the realtime path failed.

Run as: python -m indexer.agent_sync
"""

from __future__ import annotations

import asyncio
import base64
import struct
from datetime import datetime, timezone

import structlog
from solana.rpc.async_api import AsyncClient
from solders.pubkey import Pubkey

from indexer import db, repo
from indexer.config import settings

log = structlog.get_logger(__name__)

POLL_INTERVAL_SECONDS = 30


def parse_agent_registration(data_b64: str, address: Pubkey) -> dict | None:
    """
    Manually deserialize AgentRegistration from raw account data.

    Anchor account layout:
      [0..8]      discriminator (8 bytes — first 8 of sha256("account:AgentRegistration"))
      [8..40]     agent_wallet  (Pubkey, 32)
      [40..72]    owner_wallet  (Pubkey, 32)
      [72..80]    registered_at (i64, 8)
      [80..88]    escrow_lamports (u64, 8)
      [88..89]    active        (bool, 1)
      [89..90]    bump          (u8, 1)
      [90..91]    vault_bump    (u8, 1)
    Total: 91 bytes (8 disc + 83 fields)
    """
    raw = base64.b64decode(data_b64)
    if len(raw) < 91:
        return None

    agent_wallet    = str(Pubkey.from_bytes(raw[8:40]))
    owner_wallet    = str(Pubkey.from_bytes(raw[40:72]))
    registered_at   = struct.unpack("<q", raw[72:80])[0]
    active          = raw[88] == 1

    return {
        "registration_pda": str(address),
        "agent_wallet":     agent_wallet,
        "owner_wallet":     owner_wallet,
        "registered_at":    datetime.fromtimestamp(registered_at, tz=timezone.utc),
        "active":           active,
    }


async def fetch_all_agent_registrations(rpc: AsyncClient) -> list[dict]:
    """
    Fetch every AgentRegistration PDA owned by the health-oracle program.
    Uses getProgramAccounts with a memcmp filter on the discriminator.
    """
    program_id = Pubkey.from_string(settings.health_oracle_program_id)

    # Anchor discriminator for "AgentRegistration" account =
    # first 8 bytes of sha256("account:AgentRegistration")
    # We hardcode it here; a real impl would compute via anchorpy or
    # hashlib at startup.
    import hashlib
    discriminator = hashlib.sha256(b"account:AgentRegistration").digest()[:8]
    discriminator_b58 = base64.b64encode(discriminator).decode()

    resp = await rpc.get_program_accounts(
        program_id,
        commitment="confirmed",
        encoding="base64",
        filters=[
            {"memcmp": {"offset": 0, "bytes": discriminator_b58, "encoding": "base64"}},
            {"dataSize": 91},  # 8 disc + 83 INIT_SPACE
        ],
    )

    out = []
    for account in resp.value or []:
        parsed = parse_agent_registration(
            account.account.data[0],   # base64 payload
            account.pubkey,
        )
        if parsed:
            out.append(parsed)
    return out


async def sync_loop() -> None:
    """Main loop — fetch all registrations, upsert into DB."""
    rpc = AsyncClient(settings.solana_rpc_url)
    pool = await db.init_pool()

    log.info("agent_sync starting", rpc=settings.solana_rpc_url)

    try:
        while True:
            try:
                registrations = await fetch_all_agent_registrations(rpc)
                log.info("fetched_registrations", count=len(registrations))

                async with pool.acquire() as conn:
                    for r in registrations:
                        # We use registration_pda as a proxy for "tx signature"
                        # since we can't easily get the original sig from
                        # getProgramAccounts. Day 5 will improve this with
                        # transaction history scanning.
                        await repo.upsert_registered_agent(
                            conn,
                            agent_wallet      = r["agent_wallet"],
                            owner_wallet      = r["owner_wallet"],
                            name              = None,  # filled from event log on Day 5
                            registration_pda  = r["registration_pda"],
                            registered_at     = r["registered_at"],
                            onchain_signature = r["registration_pda"],  # placeholder
                        )
            except Exception as e:
                log.error("sync_iteration_failed", error=str(e))

            await asyncio.sleep(POLL_INTERVAL_SECONDS)
    finally:
        await rpc.close()
        await db.close_pool()


def main() -> None:
    structlog.configure(
        processors=[structlog.processors.TimeStamper(fmt="iso"), structlog.dev.ConsoleRenderer()],
    )
    asyncio.run(sync_loop())


if __name__ == "__main__":
    main()
