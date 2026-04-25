"""
indexer/webhook_registrar.py — register Helius webhooks for newly synced agents.

Lifecycle:
  1. agent_sync inserts a new row into registered_agents with
     helius_webhook_id = NULL.
  2. This process polls agents_pending_webhook every N seconds.
  3. For each pending agent: call Helius API to create a webhook.
  4. On success: write helius_webhook_id back to the row.
  5. On failure: increment webhook_failures; abandon after 5 attempts.

Run as: python -m indexer.webhook_registrar
"""

from __future__ import annotations

import asyncio

import structlog

from indexer import db, repo
from indexer.helius import HeliusClient, HeliusError

log = structlog.get_logger(__name__)

POLL_INTERVAL_SECONDS = 30
MAX_FAILURES = 5  # give up after this many consecutive failures


async def register_pending() -> None:
    """One pass through pending agents."""
    helius = HeliusClient()
    pool   = await db.get_pool()

    try:
        async with pool.acquire() as conn:
            pending = await repo.agents_pending_webhook(conn)

        if not pending:
            return

        log.info("registering_webhooks", count=len(pending))

        for agent in pending:
            agent_wallet = agent["agent_wallet"]
            try:
                webhook_id = await helius.create_webhook(agent_wallet)
                async with pool.acquire() as conn:
                    await repo.attach_webhook_id(conn, agent_wallet, webhook_id)
                log.info(
                    "webhook_registered",
                    agent=agent_wallet[:12] + "...",
                    webhook_id=webhook_id,
                )
            except HeliusError as e:
                log.error(
                    "webhook_registration_failed",
                    agent=agent_wallet[:12] + "...",
                    error=str(e),
                )
                async with pool.acquire() as conn:
                    await repo.record_webhook_failure(conn, agent_wallet, str(e))
    finally:
        await helius.aclose()


async def loop() -> None:
    await db.init_pool()
    log.info("webhook_registrar starting")

    try:
        while True:
            try:
                await register_pending()
            except Exception as e:
                log.error("registrar_iteration_failed", error=str(e))
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
    finally:
        await db.close_pool()


def main() -> None:
    structlog.configure(
        processors=[structlog.processors.TimeStamper(fmt="iso"), structlog.dev.ConsoleRenderer()],
    )
    asyncio.run(loop())


if __name__ == "__main__":
    main()
