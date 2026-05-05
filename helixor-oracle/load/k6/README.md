# Helixor k6 Load Tests

These tests exercise the public read/API paths and the webhook ingestion path:

- `GET /score/{agent_wallet}`
- `GET /agents`
- `POST /telemetry/beacon`
- `POST /webhook`

Install k6:

```bash
brew install k6
```

## API Load

Use seeded wallets that exist in the target environment.

```bash
cd helixor-oracle

API_BASE_URL=http://127.0.0.1:8001 \
SCORE_WALLETS=AGENT11111111111111111111111111111111111111 \
HELIXOR_API_KEY=hxop_optional_partner_key \
DURATION=2m \
SCORE_RPS=20 \
AGENTS_RPS=5 \
TELEMETRY_RPS=10 \
k6 run load/k6/api_load.js
```

If you intentionally test unknown agents, set:

```bash
SCORE_EXPECTED_STATUS=404
```

## Webhook Load

Use wallets that are registered in the target DB if you want inserts instead of
skips.

```bash
cd helixor-oracle

WEBHOOK_BASE_URL=http://127.0.0.1:8000 \
HELIUS_WEBHOOK_AUTH_TOKEN="$HELIUS_WEBHOOK_AUTH_TOKEN" \
WEBHOOK_AGENT_WALLETS=AGENT11111111111111111111111111111111111111 \
WEBHOOK_BATCH_SIZE=10 \
WEBHOOK_RPS=5 \
DURATION=2m \
k6 run load/k6/webhook_load.js
```

## Suggested Gates

Initial staging gates:

- API failure rate `< 1%`
- `/score` p95 `< 250ms`, p99 `< 500ms`
- `/agents` p95 `< 400ms`
- `/telemetry/beacon` p95 `< 500ms`
- `/webhook` p95 `< 500ms`, p99 `< 1000ms`

For production readiness, run against the public edge URL, not localhost. Keep
Redis, PgBouncer, the API, webhook receiver, and webhook workers enabled.

## Environment Knobs

Common:

- `DURATION`
- `MAX_FAILURE_RATE`

API:

- `API_BASE_URL`
- `HELIXOR_API_KEY`
- `SCORE_WALLETS`
- `SCORE_EXPECTED_STATUS`
- `SCORE_RPS`
- `AGENTS_RPS`
- `TELEMETRY_RPS`
- `SCORE_P95_MS`
- `SCORE_P99_MS`
- `AGENTS_P95_MS`
- `TELEMETRY_P95_MS`

Webhook:

- `WEBHOOK_BASE_URL`
- `HELIUS_WEBHOOK_AUTH_TOKEN`
- `WEBHOOK_AGENT_WALLETS`
- `WEBHOOK_BATCH_SIZE`
- `WEBHOOK_RPS`
- `WEBHOOK_P95_MS`
- `WEBHOOK_P99_MS`
