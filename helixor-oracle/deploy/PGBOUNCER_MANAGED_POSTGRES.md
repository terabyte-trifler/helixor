# PgBouncer + Managed Postgres Runbook

Goal: keep application containers from opening direct, unbounded connections
to Postgres. Production apps connect to PgBouncer; PgBouncer maintains a small
server-side pool to a managed Postgres database.

## Target Shape

```
Helixor API / workers
  -> PgBouncer on private network :6432
  -> Managed Postgres with TLS
```

Do not run the production database as a plain container on the app VM. Use a
managed provider with backups, point-in-time recovery, disk alerts, TLS, and
replication.

Good managed options:
- AWS RDS Postgres or Aurora Postgres
- Neon
- Supabase Postgres
- Render Postgres
- Fly Postgres
- Crunchy Bridge

## Application Settings

When PgBouncer uses transaction pooling, asyncpg prepared statement caching
must be disabled:

```bash
DATABASE_URL=postgresql://helixor:<password>@pgbouncer:6432/helixor
DB_STATEMENT_CACHE_SIZE=0
DB_POOL_MIN=2
DB_POOL_MAX=10
```

`DB_POOL_MAX` is the number of client-side asyncpg connections per process.
Keep it modest because PgBouncer is doing the real fan-in.

## PgBouncer Settings

Recommended starting point:

```bash
PGBOUNCER_POOL_MODE=transaction
PGBOUNCER_MAX_CLIENT_CONN=2000
PGBOUNCER_DEFAULT_POOL_SIZE=50
PGBOUNCER_RESERVE_POOL_SIZE=20
```

Tune `DEFAULT_POOL_SIZE` below the managed database `max_connections`, leaving
room for migrations, admin shells, analytics, and provider maintenance.

## Managed Postgres Checklist

- TLS required for database connections.
- Automated backups enabled.
- Point-in-time recovery enabled if provider supports it.
- Disk usage alerts at 70%, 80%, and 90%.
- CPU and connection saturation alerts.
- Database user has only the required privileges.
- Migrations run as a separate one-shot job, not through every app container.
- App containers cannot reach the database directly; they can reach PgBouncer.
- PgBouncer and Postgres are on private networking where the platform allows it.

## Migration Flow

1. Provision managed Postgres.
2. Create the `helixor` database and app user.
3. Run:

   ```bash
   python -m db.migrate
   ```

   against the managed database direct URL, not PgBouncer.

4. Start PgBouncer with the managed host credentials.
5. Point all long-running services at PgBouncer:

   ```bash
   DATABASE_URL=postgresql://helixor:<password>@pgbouncer:6432/helixor
   DB_STATEMENT_CACHE_SIZE=0
   ```

6. Verify `/status` and `/metrics`.
7. Run load tests against the public edge URL.

## Local Development

The default `docker-compose.yml` still runs a local Postgres container, but app
services now connect through PgBouncer. This catches PgBouncer compatibility
issues before production.

Use `deploy/docker-compose.prod.example.yml` as the production starting point:
it intentionally does not define a Postgres container.
