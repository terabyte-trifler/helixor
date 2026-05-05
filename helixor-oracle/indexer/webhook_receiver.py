"""
indexer/webhook_receiver.py — FastAPI app receiving Helius webhooks.

Endpoints:
  POST /webhook  — Helius posts here. Auth via shared token.
  GET  /health   — liveness probe (k8s-style).
  GET  /status   — readiness + recent webhook stats.
  GET  /metrics  — Prometheus text format.

Lifecycle:
  startup  → init asyncpg pool, Redis queue client, init Helius client
  shutdown → close pool, close Helius client

Production notes:
  - Run with: uvicorn indexer.webhook_receiver:app --host 0.0.0.0 --port 8000 --workers 1
  - DO NOT run with multiple workers — each would open its own pool, multiplying
    PG connections. Scale horizontally with multiple containers, not workers.
  - Behind a reverse proxy (nginx/Caddy) with TLS termination + rate limiting.
"""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import structlog
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse

from api.redis_client import close_redis, init_redis
from indexer import db, repo
from indexer.auth import verify_webhook_auth
from indexer.config import settings
from indexer.helius import HeliusClient
from indexer.parser import ParseError, parse_helius_tx
from indexer.webhook_queue import QueuedWebhookBatch, enqueue_webhook_batch

log = structlog.get_logger(__name__)

# Helius client lives at module scope; init in lifespan
_helius: HeliusClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Set up + tear down resources around the app's lifetime."""
    global _helius

    # ── Configure structured logging ──────────────────────────────────────────
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
    )

    log.info("indexer starting", version="0.4.0", port=settings.port)

    # ── DB pool ───────────────────────────────────────────────────────────────
    await db.init_pool()
    if settings.webhook_queue_enabled:
        await init_redis()

    # ── Helius client ─────────────────────────────────────────────────────────
    _helius = HeliusClient()

    log.info("indexer ready")
    try:
        yield
    finally:
        log.info("indexer shutting down")
        if _helius is not None:
            await _helius.aclose()
        await close_redis()
        await db.close_pool()
        log.info("indexer stopped")


app = FastAPI(
    title="Helixor Oracle Indexer",
    version="0.4.0",
    description="Receives Helius webhooks and persists agent transactions.",
    lifespan=lifespan,
)


# =============================================================================
# Webhook endpoint — the hot path
# =============================================================================
@app.post(
    "/webhook",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(verify_webhook_auth)],
)
async def receive_transactions(request: Request):
    """
    Helius POSTs an array of transactions here.

    Contract:
      - Returns 200 OK with {"received": N, "inserted": M, "skipped": K}
      - Returns 401 if auth header is wrong
      - Returns 400 if body is malformed (Helius will retry — not what we want
        for malformed bodies, but better than 500)
      - Returns 200 even if individual tx parses fail (we log + skip)

    Why we never raise 5xx for individual parse failures:
      Helius retries on 5xx. If one tx in the batch is malformed, we don't
      want Helius to keep retrying the entire batch — that just amplifies
      the problem. Log + skip + 200.
    """
    request_id = str(uuid.uuid4())[:8]
    started    = time.perf_counter()

    bound_log = log.bind(request_id=request_id)

    # ── Parse body ────────────────────────────────────────────────────────────
    try:
        body = await request.json()
    except Exception as e:
        bound_log.warning("invalid_json_body", error=str(e))
        raise HTTPException(status_code=400, detail="Body must be JSON array")

    if not isinstance(body, list):
        bound_log.warning("body_not_list", got_type=type(body).__name__)
        raise HTTPException(status_code=400, detail="Body must be a JSON array")

    if len(body) == 0:
        bound_log.info("empty_batch")
        return {"received": 0, "inserted": 0, "skipped": 0}

    # ── Reject very old transactions (replay attack defence) ──────────────────
    # Helius streams in real-time. A flood of old txs is suspicious.
    cutoff = datetime.now(tz=timezone.utc) - timedelta(seconds=settings.max_webhook_tx_age_seconds)

    parsed: list = []
    parse_failures = 0
    too_old        = 0

    for tx in body:
        try:
            p = parse_helius_tx(tx)
            if p.block_time < cutoff:
                too_old += 1
                continue
            parsed.append(p)
        except ParseError as e:
            parse_failures += 1
            bound_log.warning("parse_failure", error=str(e), sig=tx.get("signature"))

    if parse_failures or too_old:
        bound_log.info(
            "filtered_batch",
            received=len(body),
            parsed=len(parsed),
            parse_failures=parse_failures,
            too_old=too_old,
        )

    # ── Enqueue or insert ─────────────────────────────────────────────────────
    error_msg: str | None = None
    inserted = 0
    skipped  = parse_failures + too_old

    if parsed:
        if settings.webhook_queue_enabled:
            try:
                await enqueue_webhook_batch(
                    QueuedWebhookBatch(
                        request_id=request_id,
                        received=len(body),
                        skipped=skipped,
                        duration_ms=int((time.perf_counter() - started) * 1000),
                        txs=parsed,
                    )
                )
            except Exception as e:
                error_msg = f"{type(e).__name__}: {e}"
                bound_log.error("webhook_enqueue_failed", error=error_msg)
        else:
            pool = await db.get_pool()
            try:
                async with pool.acquire() as conn:
                    ins, skp = await repo.insert_transactions_batch(conn, parsed, source="webhook")
                    inserted += ins
                    skipped  += skp
            except Exception as e:
                # DB-level error — log it, audit it, return 500 so Helius retries
                error_msg = f"{type(e).__name__}: {e}"
                bound_log.error("db_insert_failed", error=error_msg)

    duration_ms = int((time.perf_counter() - started) * 1000)

    # ── Audit ─────────────────────────────────────────────────────────────────
    # Queued batches are audited by webhook_worker after durable DB insert.
    if not settings.webhook_queue_enabled or error_msg or not parsed:
        try:
            pool = await db.get_pool()
            async with pool.acquire() as conn:
                await repo.record_webhook_event(
                    conn,
                    request_id     = request_id,
                    tx_count       = len(body),
                    inserted_count = inserted,
                    skipped_count  = skipped,
                    duration_ms    = duration_ms,
                    error          = error_msg,
                )
        except Exception as e:
            bound_log.warning("audit_log_failed", error=str(e))

    bound_log.info(
        "webhook_received",
        received=len(body), inserted=inserted, skipped=skipped,
        queued=len(parsed) if settings.webhook_queue_enabled and not error_msg else 0,
        duration_ms=duration_ms, error=error_msg,
    )

    if error_msg:
        # Returning 500 tells Helius to retry — appropriate for transient DB issues.
        # Helius retries with exponential backoff up to 24h.
        raise HTTPException(status_code=500, detail="Database write failed")

    return {
        "received":  len(body),
        "inserted":  inserted,
        "skipped":   skipped,
        "queued":    len(parsed) if settings.webhook_queue_enabled else 0,
        "duration_ms": duration_ms,
        "request_id": request_id,
    }


# =============================================================================
# Operational endpoints
# =============================================================================

@app.get("/health")
async def health():
    """Liveness probe — used by Kubernetes/load balancer."""
    return {"status": "ok"}


@app.get("/status")
async def status_endpoint():
    """Readiness + recent webhook stats."""
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        # DB reachable?
        await conn.execute("SELECT 1")
        summary = await repo.webhook_health_summary(conn, window_minutes=5)

    return {
        "status":        "ready",
        "version":       app.version,
        "db_reachable":  True,
        "last_5min":     summary,
    }


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics():
    """Prometheus text format — minimal MVP metrics."""
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        summary = await repo.webhook_health_summary(conn, window_minutes=5)

    return (
        f'# HELP helixor_webhook_events_total Number of webhook events in last 5min\n'
        f'helixor_webhook_events_total {summary.get("total_events", 0)}\n'
        f'# HELP helixor_webhook_inserted_total Transactions inserted in last 5min\n'
        f'helixor_webhook_inserted_total {summary.get("total_inserted", 0)}\n'
        f'# HELP helixor_webhook_skipped_total Transactions skipped in last 5min\n'
        f'helixor_webhook_skipped_total {summary.get("total_skipped", 0)}\n'
        f'# HELP helixor_webhook_errors_total Webhook handler errors in last 5min\n'
        f'helixor_webhook_errors_total {summary.get("errors", 0)}\n'
        f'# HELP helixor_webhook_avg_duration_ms Average handler duration\n'
        f'helixor_webhook_avg_duration_ms {summary.get("avg_duration_ms", 0)}\n'
    )
