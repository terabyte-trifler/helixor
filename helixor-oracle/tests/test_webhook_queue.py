from __future__ import annotations

from datetime import datetime, timezone

import pytest

from indexer.parser import ParsedTransaction
from indexer.webhook_queue import QueuedWebhookBatch, process_webhook_batches


def _tx(agent_wallet: str, signature: str) -> ParsedTransaction:
    return ParsedTransaction(
        signature=signature,
        slot=265_000_000,
        block_time=datetime.now(tz=timezone.utc),
        fee_payer=agent_wallet,
        success=True,
        program_ids=["11111111111111111111111111111111"],
        sol_change=-5000,
        fee=5000,
        raw_meta={"signature": signature},
    )


@pytest.mark.asyncio
async def test_process_webhook_batches_inserts_and_audits(db_pool, seeded_agent):
    batch = QueuedWebhookBatch(
        request_id="req-queue-1",
        received=1,
        skipped=0,
        duration_ms=3,
        txs=[_tx(seeded_agent, "QUEUE" + "a" * 83)],
    )

    async with db_pool.acquire() as conn:
        inserted, skipped = await process_webhook_batches(conn, [batch])
        tx_count = await conn.fetchval("SELECT COUNT(*) FROM agent_transactions")
        event = await conn.fetchrow("SELECT * FROM webhook_events")

    assert inserted == 1
    assert skipped == 0
    assert tx_count == 1
    assert event["tx_count"] == 1
    assert event["inserted_count"] == 1
    assert event["skipped_count"] == 0


@pytest.mark.asyncio
async def test_process_webhook_batches_skips_unknown_agents(db_pool):
    batch = QueuedWebhookBatch(
        request_id="req-queue-2",
        received=1,
        skipped=0,
        duration_ms=2,
        txs=[_tx("UNKNOWN" + "x" * 36, "QUEUE" + "b" * 83)],
    )

    async with db_pool.acquire() as conn:
        inserted, skipped = await process_webhook_batches(conn, [batch])

    assert inserted == 0
    assert skipped == 1
