# Helixor — Day 8

> **REST API + TypeScript SDK.** DeFi protocols can now query trust scores
> via HTTP and wrap them in a typed SDK with two methods: `getScore` and
> `requireMinScore`.

Day 8 spans two repos:
- `helixor-oracle/` — adds `api/` package (FastAPI on port 8001)
- `helixor-sdk/`    — new package: `@helixor/client`

---

## Day 8 Status

### Python API
| Item | Status |
|------|--------|
| Async FastAPI app on port 8001 | ✅ |
| `GET /score/{agent_wallet}` with full TrustScore response | ✅ |
| `GET /agents` paginated listing | ✅ |
| `GET /health`, `/status`, `/metrics` | ✅ |
| OpenAPI / Swagger docs at `/docs` | ✅ |
| Pubkey validation → 400 (not 500) | ✅ |
| Redis-backed per-IP token-bucket rate limiting | ✅ |
| Shared Redis score cache + in-process L1 cache | ✅ |
| CORS middleware (allow-list configurable) | ✅ |
| Request ID + structured JSON logs | ✅ |
| Standardized error envelope (no stack traces leaked) | ✅ |
| 20+ integration tests with testcontainers | ✅ |

### TypeScript SDK
| Item | Status |
|------|--------|
| `getScore(agentWallet)` with full type safety | ✅ |
| `requireMinScore(agent, min, opts)` with policy enforcement | ✅ |
| `listAgents(limit, offset)` | ✅ |
| Configurable timeout (default 5s) | ✅ |
| Auto-retry with exponential backoff (5xx + network) | ✅ |
| Client-side TTL cache (default 30s) | ✅ |
| Bearer token auth | ✅ |
| Input validation BEFORE network call | ✅ |
| Typed error hierarchy with stable codes | ✅ |
| Injectable fetch (Node < 18 + tests) | ✅ |
| AbortController-based cancellation | ✅ |
| 30+ Vitest unit tests | ✅ |
| Tree-shakeable ESM + CJS bundles | ✅ |

---

## Architecture

```
                 ┌──────────────────────────────┐
                 │  Caller (DeFi protocol,       │
                 │   elizaOS plugin, browser)    │
                 └──────────────┬───────────────┘
                                │
                                ▼
                 ┌──────────────────────────────┐
                 │  @helixor/client (TS SDK)    │
                 │  • timeout + retry + cache   │
                 │  • typed errors              │
                 └──────────────┬───────────────┘
                                │ HTTP
                                ▼
                 ┌──────────────────────────────┐
                 │  Helixor REST API (FastAPI)  │
                 │  • CORS + Redis rate-limit   │
                 │  • shared score cache        │
                 │  • req-id + structured logs  │
                 └──────────────┬───────────────┘
                                │ asyncpg + Redis
                                ▼
                 ┌──────────────────────────────┐
                 │  PostgreSQL agent_scores     │
                 │  (Day 6 persistent storage)  │
                 └──────────────────────────────┘
```

The API serves from PostgreSQL, NOT directly from on-chain. The on-chain
cert is the source of truth for DeFi protocols that integrate via CPI
(Day 3); the API is a fast read-through cache for everyone else.

---

## What Got Fixed vs the Spec

| Bug in spec | Fix |
|-------------|-----|
| `solana.rpc.api.Client` (sync) blocks event loop | All-async with asyncpg + lifespan |
| No caching — every call hits Solana RPC | Redis shared score cache + 60s in-process L1 |
| No rate limiting | Redis-backed per-IP token-bucket: 100/min default |
| No CORS — browsers can't call | CORS middleware, configurable origins |
| `raise HTTPException(detail=f"... {e}")` leaks internals | Standardized `{error, code, request_id}` envelope |
| `fetch_onchain_score` undefined | `ScoreService.get_score()` reads from agent_scores DB |
| No pubkey validation → 500 on bad input | Regex + solders validation → 400 |
| No request IDs | uuid per request, in headers + logs |
| No structured logs | structlog JSON throughout |
| No OpenAPI docs | Auto-generated `/docs` + `/redoc` |
| SDK uses global fetch (Node<18 fails) | Injectable `options.fetch` |
| SDK has no timeout — DeFi tx hangs | 5s default with AbortController |
| SDK has no retries — flaky network breaks integrations | 2 retries, exp backoff, only on 5xx + network |
| SDK has no cache — same agent = N HTTP calls | 30s default cache |
| SDK error class `{} as TrustScore` | Real `AgentNotFoundError` with no fake score |
| `requireMinScore` lacks deactivation/provisional handling | All four sources mapped to distinct errors |
| AgentDeactivated bypassable | NEVER bypassable, even with all options |
| No SDK tests | 30+ vitest with mock fetch — no MSW server needed |
| No package.json publish config | Full ESM+CJS+types config |

---

## Quick Start

### 1. API (Python)

```bash
cd helixor-oracle
bash scripts/setup.sh
# API listening on http://localhost:8001
# Open http://localhost:8001/docs for Swagger UI
```

### 2. SDK (TypeScript)

```bash
cd helixor-sdk
npm install
npm test                     # 30+ tests, no network
npm run build                # produces dist/index.{js,esm.js,d.ts}
```

### 3. End-to-end smoke test

```bash
# Server side
curl http://localhost:8001/score/AGENT_WALLET_PUBKEY

# SDK side
cd helixor-sdk
node -e "
  const { HelixorClient } = require('./dist');
  const c = new HelixorClient({ apiBase: 'http://localhost:8001' });
  c.getScore('AGENT_WALLET').then(s => console.log(s));
"
```

---

## API Endpoints

| Method | Path | Returns |
|--------|------|---------|
| `GET` | `/score/{agent_wallet}` | `ScoreResponse` |
| `GET` | `/score/{agent_wallet}?force_refresh=true` | `ScoreResponse` (bypass cache) |
| `GET` | `/agents?limit=50&offset=0` | `AgentListResponse` |
| `GET` | `/health` | `{status: "ok"}` (liveness) |
| `GET` | `/status` | `StatusResponse` (readiness + cache stats) |
| `GET` | `/metrics` | Prometheus text |
| `GET` | `/docs` | Swagger UI |

### Sample response

```json
{
  "agent_wallet": "AGENT11...",
  "score": 850,
  "alert": "GREEN",
  "source": "live",
  "success_rate": 97.0,
  "anomaly_flag": false,
  "updated_at": 1714000000,
  "is_fresh": true,
  "breakdown": {
    "success_rate_score": 500,
    "consistency_score": 300,
    "stability_score": 50,
    "raw_score": 850,
    "guard_rail_applied": false
  },
  "scoring_algo_version": 1,
  "weights_version": 1,
  "baseline_hash_prefix": "abcdef0123456789abcdef0123456789",
  "served_at": 1714000050,
  "cached": false
}
```

### Error envelope

```json
{
  "error": "Agent not registered with Helixor",
  "code":  "AGENT_NOT_FOUND",
  "request_id": "a1b2c3d4"
}
```

---

## SDK Usage

### Most common pattern: enforce policy in DeFi tx

```typescript
import { HelixorClient, HelixorError } from "@helixor/client";

const helixor = new HelixorClient();

async function executeTradeForAgent(agentWallet: string, tradeArgs: TradeArgs) {
  // One line of policy enforcement.
  await helixor.requireMinScore(agentWallet, 700);

  // If we're here: score ≥ 700, fresh, no anomaly, not deactivated.
  return performTrade(tradeArgs);
}
```

### Switch on error codes

```typescript
try {
  await helixor.requireMinScore(agent, 700);
} catch (err) {
  if (err instanceof HelixorError) {
    switch (err.code) {
      case "SCORE_TOO_LOW":     return { allowed: false, reason: "low_score" };
      case "ANOMALY_DETECTED":  return { allowed: false, reason: "anomaly", flag_for_review: true };
      case "STALE_SCORE":       return { allowed: false, reason: "oracle_stalled" };
      case "AGENT_DEACTIVATED": return { allowed: false, reason: "deactivated" };
      case "PROVISIONAL_SCORE": return { allowed: false, reason: "no_history_yet" };
      case "RATE_LIMITED":      return { allowed: false, reason: "throttled" };
      default:                  throw err;
    }
  }
  throw err;
}
```

---

## File Structure

```
helixor-oracle/
├── api/
│   ├── main.py                  ← FastAPI app + middleware (NEW)
│   ├── schemas.py               ← pydantic response models (NEW)
│   ├── service.py               ← read-through DB layer (NEW)
│   ├── cache.py                 ← in-process L1 TTL cache (NEW)
│   ├── redis_client.py          ← shared Redis lifecycle (NEW)
│   ├── rate_limit.py            ← Redis-backed token-bucket (NEW)
│   ├── validation.py            ← pubkey validation (NEW)
│   └── routes/
│       ├── score.py             ← /score, /agents (NEW)
│       └── status.py            ← /health, /status, /metrics (NEW)
└── tests/api/
    └── test_score_routes.py     ← 20+ integration tests (NEW)

helixor-sdk/                      ← NEW PACKAGE
├── src/
│   ├── index.ts                 ← public exports
│   ├── client.ts                ← HelixorClient
│   ├── errors.ts                ← typed error hierarchy
│   ├── cache.ts                 ← client-side cache
│   └── types.ts                 ← TrustScore + options
├── tests/
│   └── client.test.ts           ← 30+ vitest tests
├── package.json
├── tsconfig.json
├── vitest.config.ts
└── README.md
```

---

## Production Deployment Notes

**Shared hot path.** Set `REDIS_URL` in production. Score reads use a small
in-process L1 plus Redis L2, and rate limits are enforced globally across API
containers instead of multiplying by replica count.

**Tighten CORS in production.** Set `API_CORS_ORIGINS` to the exact browser
origins allowed to call authenticated routes.

**Add API keys for rate-limit tiers.** The current Redis limiter is per IP;
valid operator API keys get Redis-backed per-key buckets by tier.

**Put the API behind an edge.** Use Cloudflare/Fly/Render/AWS ALB for TLS,
WAF, coarse abuse filtering, and private origin networking. See
`helixor-oracle/deploy/EDGE_GATEWAY.md`.

**Cache TTL trade-off.** 60s server cache + 30s client cache = up to ~90s
delay for score updates to propagate. Unknown agents are cached for 30s to
protect Postgres from repeated misses. For real-time use cases, bypass with
`?force_refresh=true`.

**The SDK is the consumer contract.** Once you publish `@helixor/client`,
breaking changes are expensive. Day 8 reserves room for additive evolution:
new error codes, new TrustScore fields, new options. Never remove or rename.

---

*Helixor MVP · Day 8 complete · Next: Day 9 elizaOS plugin*
