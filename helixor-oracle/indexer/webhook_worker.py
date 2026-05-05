"""
indexer/webhook_worker.py — batch worker for queued Helius webhook payloads.

Run as:
    python -m indexer.webhook_worker
"""

from __future__ import annotations

import asyncio
import signal

import structlog

from api.redis_client import close_redis, init_redis
from indexer import db
from indexer.config import settings
from indexer.webhook_queue import pop_webhook_batches, process_webhook_batches

log = structlog.get_logger(__name__)
_stop = asyncio.Event()


def _request_stop() -> None:
    _stop.set()


async def run_once() -> tuple[int, int]:
    batches = await pop_webhook_batches(settings.webhook_worker_batch_size)
    if not batches:
        return (0, 0)

    pool = await db.get_pool()
    async with pool.acquire() as conn:
        inserted, skipped = await process_webhook_batches(conn, batches)

    log.info(
        "webhook_batches_processed",
        batches=len(batches),
        inserted=inserted,
        skipped=skipped,
    )
    return (inserted, skipped)


async def run_forever() -> None:
    await init_redis()
    await db.init_pool()
    log.info(
        "webhook_worker_ready",
        queue=settings.webhook_queue_name,
        batch_size=settings.webhook_worker_batch_size,
    )

    try:
        while not _stop.is_set():
            try:
                await run_once()
            except Exception as exc:
                log.exception("webhook_worker_iteration_failed", error=str(exc))
                await asyncio.sleep(2)
    finally:
        await close_redis()
        await db.close_pool()
        log.info("webhook_worker_stopped")


def main() -> None:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
    )
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _request_stop)
    loop.run_until_complete(run_forever())


if __name__ == "__main__":
    main()
