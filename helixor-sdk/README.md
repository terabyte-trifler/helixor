# @helixor/client

> TypeScript SDK for the Helixor trust-score API.
>
> Two methods you'll actually use:
> `getScore()` and `requireMinScore()`.

```bash
npm install @helixor/client
```

---

## Quick Start

```typescript
import { HelixorClient } from "@helixor/client";

const helixor = new HelixorClient({
  apiBase: "https://api.helixor.xyz",
});

// Just read the score
const score = await helixor.getScore("AGENT_WALLET_PUBKEY");
console.log(`Score: ${score.score} (${score.alert})`);

// Or enforce a policy — throws if anything is off
await helixor.requireMinScore("AGENT_WALLET_PUBKEY", 700);
//   throws ScoreTooLowError       if score < 700
//   throws StaleScoreError        if cert > 48h old
//   throws AnomalyDetectedError   if anomaly_flag = true
//   throws AgentDeactivatedError  if owner deactivated
//   throws ProvisionalScoreError  if no real score yet
```

---

## DeFi Integration Pattern

```typescript
import { HelixorClient, ScoreTooLowError, StaleScoreError } from "@helixor/client";

const helixor = new HelixorClient();

async function processWithdrawal(agentWallet: string, amount: bigint) {
  try {
    await helixor.requireMinScore(agentWallet, 700);
  } catch (err) {
    if (err instanceof ScoreTooLowError) {
      throw new Error(`Agent score ${err.score?.score} is below threshold.`);
    }
    if (err instanceof StaleScoreError) {
      // Stale — escalate to manual review
      await flagForReview(agentWallet, "stale_helixor_score");
      throw new Error("Cannot process withdrawal — score is stale.");
    }
    throw err;
  }

  // Score is good — proceed
  return performWithdrawal(agentWallet, amount);
}
```

---

## Configuration

```typescript
const helixor = new HelixorClient({
  apiBase:    "https://api.helixor.xyz",  // default
  timeoutMs:  5000,                        // default 5s — DeFi txs can't hang
  maxRetries: 2,                           // default 2 — retries 5xx + network
  apiKey:     process.env.HELIXOR_API_KEY, // optional Bearer token
  cacheTtlMs: 30000,                       // default 30s — same agent ≠ multiple HTTP calls
  fetch:      undici.fetch,                // optional polyfill (Node < 18)
});
```

---

## Error Handling

All errors extend `HelixorError`. Switch on `err.code`:

```typescript
import { HelixorError } from "@helixor/client";

try {
  await helixor.requireMinScore(agent, 700);
} catch (err) {
  if (err instanceof HelixorError) {
    switch (err.code) {
      case "SCORE_TOO_LOW":     /* score below threshold */     break;
      case "STALE_SCORE":       /* cert > 48h old */            break;
      case "ANOMALY_DETECTED":  /* recent behavior anomaly */    break;
      case "AGENT_DEACTIVATED": /* owner deactivated agent */    break;
      case "PROVISIONAL_SCORE": /* no real score yet */          break;
      case "AGENT_NOT_FOUND":   /* not registered with Helixor */ break;
      case "RATE_LIMITED":      /* slow down */                  break;
      case "TIMEOUT":           /* didn't respond in 5s */       break;
      case "NETWORK_ERROR":     /* connection failed */          break;
      case "SERVER_ERROR":      /* persistent 5xx */             break;
    }
  }
}
```

Each error carries:
- `err.code` — stable string, switch on this
- `err.score` — the `TrustScore` (when available)
- `err.requestId` — server request ID for debugging support tickets

---

## Customizing Policy

`requireMinScore` is strict by default. Relax via options:

```typescript
// Allow stale scores (cert > 48h old) — for low-stakes reads
await helixor.requireMinScore(agent, 600, { allowStale: true });

// Allow anomaly-flagged agents — for analytics/monitoring use cases
await helixor.requireMinScore(agent, 600, { allowAnomaly: true });

// Allow newly registered agents (no real score yet)
await helixor.requireMinScore(agent, 500, { allowProvisional: true });
```

`AgentDeactivatedError` is **never** bypassable — once an owner deactivates,
the SDK refuses regardless of options.

---

## Testing Your Integration

The SDK accepts an injected `fetch`, so tests don't need a real network:

```typescript
import { HelixorClient } from "@helixor/client";
import { vi } from "vitest";

const mockFetch = vi.fn(async (url, init) => ({
  ok: true, status: 200,
  headers: new Headers({ "x-request-id": "test-1" }),
  json: async () => ({
    agent_wallet: "...", score: 800, alert: "GREEN",
    source: "live", success_rate: 97.5,
    anomaly_flag: false, updated_at: 1700000000,
    is_fresh: true, served_at: 1700000000, cached: false,
  }),
}));

const helixor = new HelixorClient({ fetch: mockFetch as any });
const score = await helixor.getScore("...");
expect(score.score).toBe(800);
```

---

## Caching

The SDK caches `getScore` results for 30s by default. This means:

- Multiple calls within one DeFi transaction → single HTTP request
- Score updates on-chain → propagate within 30s + 60s server cache = ~90s

Tune via `cacheTtlMs`. Set `0` to disable. Force a refresh with `invalidate(agent)`.

---

## API Reference

### `getScore(agentWallet: string): Promise<TrustScore>`

Returns the latest trust score.

**Throws:** `InvalidAgentWalletError`, `AgentNotFoundError`, `RateLimitedError`,
`TimeoutError`, `NetworkError`, `ServerError`

### `requireMinScore(agentWallet, minimum, opts?): Promise<TrustScore>`

Returns the score if it passes the policy, throws otherwise.

### `listAgents(limit?, offset?): Promise<AgentList>`

Paginated list of registered agents and their scores.

### `invalidate(agentWallet)` / `clearCache()`

Cache control.

---

## License

MIT. See `LICENSE`.
