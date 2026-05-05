# Helixor Hard Launch Targets

These are the minimum gates before public launch traffic goes to the production
edge URL.

## Read/API Targets

| Path | Target |
|------|--------|
| `GET /score/{agent_wallet}` cached | `1000 RPS`, p95 `< 100ms`, p99 `< 500ms` |
| `GET /score/{agent_wallet}?force_refresh=true` uncached | p95 `< 300ms` |
| `GET /agents?limit=50` | p95 `< 400ms` |
| `POST /telemetry/beacon` | p95 `< 500ms` |
| API 5xx / failed requests | `< 0.1%` |

Run:

```bash
cd helixor-oracle

K6_PROFILE=launch \
API_BASE_URL=https://api.helixor.xyz \
SCORE_WALLETS=<comma-separated-registered-wallets> \
HELIXOR_API_KEY=<partner-or-team-key> \
./scripts/run_k6_load.sh api
```

The launch profile defaults to:

- `SCORE_RPS=1000`
- `UNCACHED_SCORE_RPS=25`
- `AGENTS_RPS=50`
- `TELEMETRY_RPS=100`
- `DURATION=10m`
- `MAX_FAILURE_RATE=0.001`
- `SCORE_P95_MS=100`
- `UNCACHED_SCORE_P95_MS=300`

## Webhook Targets

| Path | Target |
|------|--------|
| `POST /webhook` acknowledgement | p95 `< 500ms`, p99 `< 1000ms` |
| Webhook failed requests | `< 0.1%` |
| Queue drain | no sustained queue growth for 10 minutes |

Run:

```bash
cd helixor-oracle

WEBHOOK_BASE_URL=https://webhook.helixor.xyz \
HELIUS_WEBHOOK_AUTH_TOKEN=<token> \
WEBHOOK_AGENT_WALLETS=<comma-separated-registered-wallets> \
WEBHOOK_BATCH_SIZE=10 \
WEBHOOK_RPS=100 \
MAX_FAILURE_RATE=0.001 \
./scripts/run_k6_load.sh webhook
```

## Pass Criteria

- All k6 thresholds pass against the public edge URL.
- API process, webhook receiver, webhook worker, Redis, PgBouncer, and managed
  Postgres are all enabled.
- No p95 regression across two consecutive runs.
- No sustained Redis queue growth during the webhook run.
- Error logs contain no new recurring 5xx class.

If any gate fails, do not launch. Fix the bottleneck, rerun the same profile,
and keep the failing run output attached to the release notes.
