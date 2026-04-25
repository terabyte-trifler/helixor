# Helixor Oracle — Day 4

> **Helius webhook listener → PostgreSQL.**
> Every transaction made by a registered agent lands in the DB within 2 seconds.

---

## Day 4 Status

| Item | Status |
|------|--------|
| PostgreSQL schema (4 tables, 7 indexes) | ✅ |
| FastAPI webhook receiver with auth | ✅ |
| Async asyncpg pool (no per-request connect) | ✅ |
| Helius API client with retries | ✅ |
| `agent_sync` — on-chain → DB sync | ✅ |
| `webhook_registrar` — auto-register webhooks for new agents | ✅ |
| `reconciler` — drift detection + RPC backfill | ✅ |
| Audit log of every webhook POST | ✅ |
| Replay-attack defence (rejects txs > 1h old) | ✅ |
| Constant-time auth check | ✅ |
| Idempotent on duplicate signatures | ✅ |
| Skips unknown agents (no FK violations) | ✅ |
| Prometheus metrics + structured JSON logs | ✅ |
| Docker Compose for local dev | ✅ |
| Unit tests (parser) + integration tests (testcontainers) | ✅ |

---

## Architecture

```
                          ┌──────────────────┐
                          │  Solana devnet   │
                          │  (health-oracle) │
                          └─────────┬────────┘
                                    │  AgentRegistration PDAs
                                    ▼
                          ┌──────────────────┐
                          │   agent_sync     │  polls every 30s
                          │   (RPC fetcher)  │
                          └─────────┬────────┘
                                    │
                          ┌─────────▼────────┐
              ┌───────────│ registered_agents│───────┐
              │           └──────────────────┘       │
              │                  │                   │
  ┌───────────▼─────────┐        │         ┌─────────▼──────────┐
  │ webhook_registrar   │        │         │    reconciler       │
  │ POST /v0/webhooks   │        │         │  (drift detect +    │
  │ to Helius for each  │        │         │   RPC backfill)     │
  │ pending agent       │        │         └─────────────────────┘
  └─────────────────────┘        │
                                 │  registers Helius webhook
                                 ▼
                       ┌──────────────────┐
                       │  Helius webhook  │
                       │  (Helius cloud)  │ ◄─── transactions
                       └─────────┬────────┘      from monitored
                                 │ POST           wallets
                                 ▼
                       ┌──────────────────┐
                       │ webhook_receiver │ ───► agent_transactions
                       │  (FastAPI)       │       (PostgreSQL)
                       └──────────────────┘
```

---

## Quick Start

```bash
# 1. Configure
cp .env.example .env
# Edit .env: set HELIUS_API_KEY, HELIUS_WEBHOOK_URL, HELIUS_WEBHOOK_AUTH_TOKEN

# 2. Generate a strong auth token
openssl rand -hex 32   # paste this as HELIUS_WEBHOOK_AUTH_TOKEN

# 3. One-command setup
bash scripts/setup.sh

# 4. Manual smoke test
bash scripts/test_webhook_manually.sh
```

The setup script:
1. Starts PostgreSQL with schema applied
2. Installs Python deps in a venv
3. Runs unit + integration tests
4. Starts all four services: webhook_receiver, agent_sync, webhook_registrar, reconciler
5. Health-checks the webhook receiver

---

## End-to-End Flow

When an operator registers an agent on-chain (Day 2's `register_agent`):

1. **Within 30s** — `agent_sync` polls the program, sees the new
   `AgentRegistration` PDA, inserts a row into `registered_agents`
   with `helius_webhook_id = NULL`.

2. **Within 60s** — `webhook_registrar` sees the pending agent in the
   `agents_pending_webhook` view, calls Helius API to register a webhook,
   updates the row with the returned `webhook_id`.

3. **Continuously** — Helius streams every transaction for that agent
   wallet to our `/webhook` endpoint via authenticated POST.

4. **Within 2s of tx confirmation** — `webhook_receiver` validates auth,
   parses the payload, inserts a row into `agent_transactions`.

5. **Every 5 minutes** — `reconciler` compares Helius's webhook list
   to our DB and re-registers any that drifted, plus backfills the last
   hour of transactions via RPC for any we missed.

---

## What Got Fixed vs the Spec

| Bug in spec | Fix |
|-------------|-----|
| No webhook authentication | Constant-time `Authorization` header check |
| `psycopg2.connect()` per request | Global `asyncpg` pool (min=2, max=10) |
| Sync DB calls in async handler | All DB calls via `await pool.acquire()` |
| FK violation when agent not in DB | Pre-fetch active set, silently skip unknown |
| Naive `datetime.fromtimestamp()` | Tz-aware UTC (PostgreSQL `TIMESTAMPTZ` correct) |
| No idempotency | `ON CONFLICT (tx_signature) DO NOTHING` |
| No webhook-to-agent linking process | `agent_sync` + `webhook_registrar` |
| No drift recovery | `reconciler` with RPC backfill |
| No audit trail | `webhook_events` table + structured JSON logs |
| No metrics | `/metrics` Prometheus endpoint |
| No tests | 30+ unit + integration tests |
| No Docker | Multi-stage Dockerfile + compose for full stack |

---

## Database Schema

| Table | Purpose | Rows / day (est) |
|-------|---------|------------------|
| `registered_agents` | Cache of on-chain agent registrations | 1 per registration |
| `agent_transactions` | Append-only ledger of every tx | 100/agent/day |
| `webhook_subscriptions` | Helius webhook lifecycle events | 1 per registration |
| `webhook_events` | Audit log of every POST received | 1000+/day |
| `schema_version` | Migration tracking | 1 per migration |

Indexes:
- `(agent_wallet, block_time DESC)` — primary scoring read pattern
- `(block_time DESC)` — global recency queries
- `(tx_signature)` UNIQUE — idempotency
- Partial index on `active = TRUE` — fast active-agent lookup
- Partial index on `error IS NOT NULL` — fast failed-webhook lookup

---

## Operations

```bash
# View live logs
docker compose logs -f webhook_receiver

# Inspect database
docker compose exec postgres psql -U helixor

# Recent webhook stats
curl -s http://localhost:8000/status | jq

# Prometheus metrics
curl -s http://localhost:8000/metrics

# Restart receiver after code change
docker compose up -d --build webhook_receiver

# Run migrations against an existing DB
python -m db.migrate
```

---

## Production Deployment Notes

**Single worker, scale horizontally.** Don't run uvicorn with `--workers 4`.
Each worker would open its own asyncpg pool, multiplying connection count.
Scale by adding more containers behind a load balancer.

**Reverse proxy required.** The webhook receiver expects Helius traffic
only. Put nginx or Caddy in front for TLS termination, rate limiting, and
IP allow-listing (Helius publishes their IP ranges).

**Rotate the auth token.** Treat `HELIUS_WEBHOOK_AUTH_TOKEN` like a database
password. To rotate: update Helius webhook config via API first, then update
this service's env var, then restart.

**PostgreSQL sizing.** Day 4 DB is small — 60 MB after a year of 5 agents.
Day 8+ scoring queries will need `pg_stat_statements` enabled to find slow
queries; revisit indexing then.

---

## File Structure

```
helixor-oracle/
├── db/
│   ├── schema.sql              ← all tables + indexes
│   └── migrate.py              ← schema applier
├── indexer/
│   ├── config.py               ← pydantic settings
│   ├── db.py                   ← asyncpg pool lifecycle
│   ├── auth.py                 ← Helius auth check
│   ├── parser.py               ← Helius tx → ParsedTransaction
│   ├── repo.py                 ← all SQL
│   ├── helius.py               ← Helius API client
│   ├── webhook_receiver.py     ← FastAPI app (the hot path)
│   ├── agent_sync.py           ← on-chain → DB
│   ├── webhook_registrar.py    ← register webhooks for new agents
│   └── reconciler.py           ← drift detection + RPC backfill
├── tests/
│   ├── conftest.py             ← testcontainers PG fixture
│   ├── test_parser.py          ← unit tests (15)
│   └── test_webhook.py         ← integration tests (15)
├── scripts/
│   ├── setup.sh
│   └── test_webhook_manually.sh
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── pytest.ini
└── .env.example
```

---

*Helixor Oracle · Day 4 complete · Next: Day 5 baseline engine*
