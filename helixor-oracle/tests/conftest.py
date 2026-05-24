"""
tests/conftest.py — pytest fixtures.

Spins up a real PostgreSQL via testcontainers for integration tests.
Run only in CI or when Docker is available locally; unit tests don't need it.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio


# Set required env vars BEFORE importing any indexer module
os.environ.setdefault("HELIUS_API_KEY",            "test-api-key")
os.environ.setdefault("HELIUS_WEBHOOK_URL",        "https://test.helixor.local/webhook")
os.environ.setdefault("HELIUS_WEBHOOK_AUTH_TOKEN", "test-auth-token-1234567890123456")
os.environ.setdefault("HEALTH_ORACLE_PROGRAM_ID",  "HLXorac1eXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
os.environ.setdefault("SOLANA_RPC_URL",            "https://api.devnet.solana.com")
os.environ.setdefault("MONITORING_ADMIN_TOKEN",    "test-monitoring-admin-token")
os.environ.pop("REDIS_URL", None)


async def _has_timescaledb(conn: asyncpg.Connection) -> bool:
    row = await conn.fetchrow(
        "SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb'"
    )
    return row is not None


async def _apply_schema_and_migrations(conn: asyncpg.Connection) -> None:
    root = Path(__file__).parent.parent
    await conn.execute((root / "db" / "schema.sql").read_text())
    migrations_dir = root / "db" / "migrations"
    if not migrations_dir.exists():
        return
    timescale_available = await _has_timescaledb(conn)
    for migration in sorted(migrations_dir.glob("*.sql")):
        if migration.name == "0009_timescaledb.sql" and not timescale_available:
            continue
        await conn.execute(migration.read_text())


@pytest.fixture(scope="session")
def postgres_url():
    """Provide a PostgreSQL URL for the test session.

    CI usually uses testcontainers. Local devnet rehearsals may not have Docker
    installed, so HELIXOR_TEST_DATABASE_URL lets the suite run against an
    operator-provided disposable database instead of failing before collection.
    """
    external_url = os.environ.get("HELIXOR_TEST_DATABASE_URL")
    if external_url:
        os.environ["DATABASE_URL"] = external_url

        async def setup_external():
            conn = await asyncpg.connect(external_url)
            try:
                await _apply_schema_and_migrations(conn)
            finally:
                await conn.close()

        asyncio.run(setup_external())
        yield external_url
        return

    """Spin up a Postgres container for the test session."""
    try:
        from testcontainers.postgres import PostgresContainer
    except ImportError:
        pytest.skip("testcontainers not installed")

    with PostgresContainer("postgres:16-alpine") as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2", "postgresql")
        os.environ["DATABASE_URL"] = url

        # Apply the base schema plus any numbered migrations so testcontainers
        # matches the current day of the project, not just Day 4.
        async def setup():
            conn = await asyncpg.connect(url)
            try:
                await _apply_schema_and_migrations(conn)
            finally:
                await conn.close()

        asyncio.run(setup())
        yield url


@pytest_asyncio.fixture
async def db_pool(postgres_url):
    """A clean asyncpg pool, schema loaded, tables truncated between tests."""
    pool = await asyncpg.create_pool(postgres_url, min_size=1, max_size=2)
    async with pool.acquire() as conn:
        await conn.execute("""
            TRUNCATE webhook_events, agent_transactions,
                     webhook_subscriptions, registered_agents
            RESTART IDENTITY CASCADE
        """)
    yield pool
    await pool.close()


@pytest_asyncio.fixture
async def seeded_agent(db_pool):
    """Insert one active registered agent for tests that need foreign keys."""
    from datetime import datetime, timezone
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO registered_agents
                (agent_wallet, owner_wallet, name, registration_pda,
                 registered_at, onchain_signature, active)
            VALUES ($1, $2, $3, $4, $5, $6, TRUE)
            """,
            "AGENT11111111111111111111111111111111111111",
            "OWNER11111111111111111111111111111111111111",
            "test-agent",
            "REGPDA11111111111111111111111111111111111111",
            datetime.now(tz=timezone.utc),
            "SIG11111111111111111111111111111111111111111",
        )
    return "AGENT11111111111111111111111111111111111111"
