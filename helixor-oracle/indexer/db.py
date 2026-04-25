"""
indexer/db.py — global asyncpg connection pool.

Why pooling: each FastAPI request acquires a connection from the pool and
releases on completion. Without pooling, every request opens a new TCP
connection, exhausts PostgreSQL's max_connections under load, and adds
~10ms of TCP+auth overhead per request.
"""

from __future__ import annotations

import asyncpg
import structlog

from indexer.config import settings

log = structlog.get_logger(__name__)

_pool: asyncpg.Pool | None = None


async def get_pool() -> asyncpg.Pool:
    """Return the global pool. Must be initialised via init_pool() first."""
    if _pool is None:
        raise RuntimeError("Database pool not initialised. Call init_pool() first.")
    return _pool


async def init_pool() -> asyncpg.Pool:
    """Create the global pool. Safe to call multiple times — idempotent."""
    global _pool

    if _pool is not None:
        return _pool

    log.info(
        "creating database pool",
        url=settings.database_url_safe,
        min_size=settings.db_pool_min,
        max_size=settings.db_pool_max,
    )

    _pool = await asyncpg.create_pool(
        dsn=settings.database_url,
        min_size=settings.db_pool_min,
        max_size=settings.db_pool_max,
        # Recycle connections that have been idle for > 5 min — avoids
        # PG's idle_session_timeout killing them out from under us
        max_inactive_connection_lifetime=300.0,
        # 5s connect timeout — fail fast if PG is unreachable
        timeout=5.0,
        # Add a server-side statement timeout so a runaway query can't
        # hold a pool slot indefinitely
        command_timeout=10.0,
    )

    log.info("database pool ready")
    return _pool


async def close_pool() -> None:
    """Gracefully close the pool. Called on FastAPI shutdown."""
    global _pool
    if _pool is not None:
        log.info("closing database pool")
        await _pool.close()
        _pool = None
