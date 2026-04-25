"""
db/migrate.py — apply schema.sql to the configured database.

Usage:
    python -m db.migrate
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import asyncpg
import structlog

from indexer.config import settings

log = structlog.get_logger()


async def apply_schema() -> None:
    schema_path = Path(__file__).parent / "schema.sql"
    schema_sql = schema_path.read_text()

    log.info("connecting to database", url=settings.database_url_safe)
    conn = await asyncpg.connect(settings.database_url)

    try:
        log.info("applying schema", path=str(schema_path))
        await conn.execute(schema_sql)

        version = await conn.fetchval(
            "SELECT MAX(version) FROM schema_version"
        )
        log.info("schema applied", version=version)
    finally:
        await conn.close()


def main() -> None:
    structlog.configure(
        processors=[structlog.processors.TimeStamper(fmt="iso"), structlog.dev.ConsoleRenderer()],
    )
    try:
        asyncio.run(apply_schema())
    except Exception as e:
        log.error("migration failed", error=str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
