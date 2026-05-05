"""
indexer/webhook_queue.py — Redis queue for webhook ingestion.

The webhook HTTP handler validates and parses Helius payloads, then enqueues a
compact batch. Dedicated workers pop batches and write to Postgres in larger
database batches.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import asyncpg
import structlog

from api.redis_client import RedisError, get_redis, redis_key
from indexer import repo
from indexer.config import settings
from indexer.parser import ParsedTransaction

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class QueuedWebhookBatch:
    request_id: str
    received: int
    skipped: int
    duration_ms: int
    txs: list[ParsedTransaction]


def _tx_to_json(tx: ParsedTransaction) -> dict[str, Any]:
    return {
        "signature": tx.signature,
        "slot": tx.slot,
        "block_time": tx.block_time.isoformat(),
        "fee_payer": tx.fee_payer,
        "success": tx.success,
        "program_ids": tx.program_ids,
        "sol_change": tx.sol_change,
        "fee": tx.fee,
        "raw_meta": tx.raw_meta,
    }


def _tx_from_json(raw: dict[str, Any]) -> ParsedTransaction:
    return ParsedTransaction(
        signature=raw["signature"],
        slot=int(raw["slot"]),
        block_time=datetime.fromisoformat(raw["block_time"]),
        fee_payer=raw["fee_payer"],
        success=bool(raw["success"]),
        program_ids=list(raw["program_ids"]),
        sol_change=int(raw["sol_change"]),
        fee=int(raw["fee"]),
        raw_meta=dict(raw["raw_meta"]),
    )


def _batch_to_json(batch: QueuedWebhookBatch) -> str:
    return json.dumps(
        {
            "request_id": batch.request_id,
            "received": batch.received,
            "skipped": batch.skipped,
            "duration_ms": batch.duration_ms,
            "enqueued_at": int(time.time()),
            "txs": [_tx_to_json(tx) for tx in batch.txs],
        },
        separators=(",", ":"),
    )


def _batch_from_json(raw: str) -> QueuedWebhookBatch:
    payload = json.loads(raw)
    return QueuedWebhookBatch(
        request_id=payload["request_id"],
        received=int(payload["received"]),
        skipped=int(payload["skipped"]),
        duration_ms=int(payload["duration_ms"]),
        txs=[_tx_from_json(tx) for tx in payload["txs"]],
    )


async def enqueue_webhook_batch(batch: QueuedWebhookBatch) -> int:
    client = get_redis()
    if client is None:
        raise RuntimeError("Redis is not available for webhook queue")
    try:
        return int(await client.rpush(redis_key(settings.webhook_queue_name), _batch_to_json(batch)))
    except RedisError as exc:
        raise RuntimeError(f"failed to enqueue webhook batch: {exc}") from exc


async def pop_webhook_batches(max_batches: int) -> list[QueuedWebhookBatch]:
    client = get_redis()
    if client is None:
        raise RuntimeError("Redis is not available for webhook queue")

    queue_key = redis_key(settings.webhook_queue_name)
    try:
        first = await client.blpop(
            queue_key,
            timeout=settings.webhook_worker_poll_timeout_seconds,
        )
        if first is None:
            return []

        raw_items = [first[1]]
        if max_batches > 1:
            rest = await client.lpop(queue_key, max_batches - 1)
            if isinstance(rest, list):
                raw_items.extend(rest)
            elif rest is not None:
                raw_items.append(rest)
    except RedisError as exc:
        raise RuntimeError(f"failed to pop webhook queue: {exc}") from exc

    batches: list[QueuedWebhookBatch] = []
    for raw in raw_items:
        try:
            batches.append(_batch_from_json(raw))
        except Exception as exc:
            log.warning("webhook_queue_decode_failed", error=str(exc))
    return batches


async def process_webhook_batches(
    conn: asyncpg.Connection,
    batches: list[QueuedWebhookBatch],
) -> tuple[int, int]:
    if not batches:
        return (0, 0)

    all_txs = [tx for batch in batches for tx in batch.txs]
    inserted, db_skipped = await repo.insert_transactions_batch(
        conn,
        all_txs,
        source="webhook",
    )

    parse_or_age_skipped = sum(batch.skipped for batch in batches)
    skipped_total = db_skipped + parse_or_age_skipped

    await repo.record_webhook_event(
        conn,
        request_id=f"worker-{str(uuid.uuid4())[:8]}",
        tx_count=sum(batch.received for batch in batches),
        inserted_count=inserted,
        skipped_count=skipped_total,
        duration_ms=sum(batch.duration_ms for batch in batches),
        error=None,
    )

    return (inserted, skipped_total)
