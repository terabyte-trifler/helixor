"""
indexer/reconciler.py — periodic drift detection.

Two responsibilities:

  1. Webhook drift: list webhooks at Helius, compare to our registered_agents
     table. Re-register any agent whose webhook is missing from Helius.

  2. Transaction backfill: for the last hour, ask the RPC for each agent's
     full transaction list. Insert any signature we don't have yet.

This is the safety net for webhook drops. If our webhook receiver was down
for 30 minutes, the next reconciler pass catches up.

Run as: python -m indexer.reconciler
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import structlog
from solana.rpc.async_api import AsyncClient
from solders.pubkey import Pubkey
from solders.signature import Signature

from indexer import db, repo
from indexer.config import settings
from indexer.helius import HeliusClient
from indexer.parser import ParsedTransaction

log = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Webhook drift reconciler
# ─────────────────────────────────────────────────────────────────────────────

async def reconcile_webhooks() -> None:
    """Compare Helius webhook list to our DB; re-register where missing."""
    helius = HeliusClient()
    pool   = await db.get_pool()

    try:
        helius_list = await helius.list_webhooks()
        helius_addresses: set[str] = set()
        for hook in helius_list:
            for addr in hook.get("accountAddresses") or []:
                helius_addresses.add(addr)

        async with pool.acquire() as conn:
            our_agents = await repo.get_active_agent_wallets(conn)

        missing = [a for a in our_agents if a not in helius_addresses]

        if missing:
            log.warning(
                "webhook_drift_detected",
                missing_count=len(missing),
                helius_total=len(helius_addresses),
                our_total=len(our_agents),
            )
            # Mark them as needing re-registration by clearing helius_webhook_id
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE registered_agents
                    SET helius_webhook_id = NULL
                    WHERE agent_wallet = ANY($1::text[])
                    """,
                    missing,
                )
        else:
            log.debug("webhook_state_in_sync", count=len(our_agents))

    finally:
        await helius.aclose()


# ─────────────────────────────────────────────────────────────────────────────
# Transaction backfill — RPC-based catchup
# ─────────────────────────────────────────────────────────────────────────────

async def backfill_agent_transactions(
    rpc: AsyncClient,
    agent_wallet: str,
    *,
    minutes_back: int = 60,
) -> int:
    """
    Fetch recent transactions for one agent via RPC and insert any we're missing.
    Returns count of newly inserted rows.
    """
    pubkey = Pubkey.from_string(agent_wallet)

    # Fetch up to 100 most recent signatures for this account
    resp = await rpc.get_signatures_for_address(pubkey, limit=100)
    sigs = resp.value or []

    if not sigs:
        return 0

    cutoff = datetime.now(tz=timezone.utc) - timedelta(minutes=minutes_back)
    relevant_sigs = [
        s for s in sigs
        if s.block_time and datetime.fromtimestamp(s.block_time, tz=timezone.utc) >= cutoff
    ]

    if not relevant_sigs:
        return 0

    # Check which ones we already have
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        existing = await conn.fetch(
            "SELECT tx_signature FROM agent_transactions WHERE tx_signature = ANY($1::text[])",
            [str(s.signature) for s in relevant_sigs],
        )
        existing_set = {r["tx_signature"] for r in existing}

    missing_sigs = [s for s in relevant_sigs if str(s.signature) not in existing_set]

    if not missing_sigs:
        return 0

    log.info(
        "backfilling_transactions",
        agent=agent_wallet[:12] + "...",
        missing_count=len(missing_sigs),
    )

    # Fetch full tx data for each missing sig
    parsed: list[ParsedTransaction] = []
    for s in missing_sigs:
        try:
            tx_resp = await rpc.get_transaction(
                s.signature,
                encoding="json",
                max_supported_transaction_version=0,
            )
            if tx_resp.value is None:
                continue

            # Convert solana-py response → dict shape that parser expects
            tx_dict = {
                "signature": str(s.signature),
                "slot":      tx_resp.value.slot,
                "timestamp": tx_resp.value.block_time or 0,
                "feePayer":  agent_wallet,
                "fee":       tx_resp.value.transaction.meta.fee if tx_resp.value.transaction.meta else 0,
                "type":      "FAILED" if (tx_resp.value.transaction.meta and tx_resp.value.transaction.meta.err) else "OK",
                "instructions": [],   # simplified; full impl would extract
                "accountData": [],    # simplified
            }

            # Minimal parsed record — backfill loses some richness vs webhook
            from indexer.parser import parse_helius_tx
            parsed.append(parse_helius_tx(tx_dict))
        except Exception as e:
            log.warning("backfill_tx_fetch_failed", sig=str(s.signature), error=str(e))

    if not parsed:
        return 0

    async with pool.acquire() as conn:
        inserted, _ = await repo.insert_transactions_batch(conn, parsed, source="backfill")

    return inserted


async def reconcile_transactions() -> None:
    """Backfill recent transactions for all active agents."""
    rpc  = AsyncClient(settings.solana_rpc_url)
    pool = await db.get_pool()

    try:
        async with pool.acquire() as conn:
            agents = await repo.get_active_agent_wallets(conn)

        total_inserted = 0
        for agent in agents:
            try:
                n = await backfill_agent_transactions(rpc, agent, minutes_back=60)
                total_inserted += n
            except Exception as e:
                log.error("backfill_failed", agent=agent[:12] + "...", error=str(e))

        if total_inserted > 0:
            log.info("backfill_complete", agents=len(agents), inserted=total_inserted)
        else:
            log.debug("backfill_nothing_to_do", agents=len(agents))

    finally:
        await rpc.close()


# ─────────────────────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────────────────────

async def loop() -> None:
    await db.init_pool()
    log.info("reconciler starting", interval=settings.reconciler_interval_seconds)

    try:
        while True:
            try:
                await reconcile_webhooks()
                await reconcile_transactions()
            except Exception as e:
                log.error("reconciler_iteration_failed", error=str(e))

            await asyncio.sleep(settings.reconciler_interval_seconds)
    finally:
        await db.close_pool()


def main() -> None:
    structlog.configure(
        processors=[structlog.processors.TimeStamper(fmt="iso"), structlog.dev.ConsoleRenderer()],
    )
    asyncio.run(loop())


if __name__ == "__main__":
    main()
