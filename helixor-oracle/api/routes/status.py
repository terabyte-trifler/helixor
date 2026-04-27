"""
api/routes/status.py — operational endpoints.

GET /status   — readiness + reachability checks
GET /health   — liveness (no DB call, just "process is alive")
GET /metrics  — Prometheus text format
"""

from __future__ import annotations

import time

import structlog
from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from api import schemas
from api.service import score_service
from indexer import db

log = structlog.get_logger(__name__)
router = APIRouter()


_started_at = time.time()


@router.get("/health", summary="Liveness probe")
async def health() -> dict:
    """
    Cheap liveness probe — used by Kubernetes/load balancer.
    Does NOT check DB or RPC. Returns 200 as long as the process is alive.
    """
    return {"status": "ok"}


@router.get(
    "/status",
    response_model=schemas.StatusResponse,
    summary="Readiness probe + cache stats",
)
async def status_endpoint() -> schemas.StatusResponse:
    """
    Readiness probe. Verifies DB connectivity and reports cache stats.
    """
    db_reachable = False
    try:
        pool = await db.get_pool()
        async with pool.acquire() as conn:
            await conn.execute("SELECT 1")
        db_reachable = True
    except Exception as e:
        log.error("status_db_check_failed", error=str(e))

    return schemas.StatusResponse(
        status         = "ok" if db_reachable else "degraded",
        version        = "0.8.0",
        uptime_seconds = int(time.time() - _started_at),
        cache_size     = score_service.cache_size,
        db_reachable   = db_reachable,
        rpc_reachable  = True,   # Not actively checked; Day 8 doesn't use RPC
    )


@router.get("/metrics", response_class=PlainTextResponse, summary="Prometheus metrics")
async def metrics() -> str:
    cs = score_service.cache_stats()
    uptime = int(time.time() - _started_at)
    return (
        f'# HELP helixor_api_uptime_seconds Process uptime\n'
        f'helixor_api_uptime_seconds {uptime}\n'
        f'# HELP helixor_api_cache_size Cache entries\n'
        f'helixor_api_cache_size {cs["size"]}\n'
        f'# HELP helixor_api_cache_hits Cache hits\n'
        f'helixor_api_cache_hits {cs["hits"]}\n'
        f'# HELP helixor_api_cache_misses Cache misses\n'
        f'helixor_api_cache_misses {cs["misses"]}\n'
        f'# HELP helixor_api_cache_hit_rate Cache hit rate\n'
        f'helixor_api_cache_hit_rate {cs["hit_rate"]}\n'
    )
