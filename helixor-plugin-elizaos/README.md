# @elizaos/plugin-helixor

> Helixor trust scoring for elizaOS agents.
>
> Adds two lines to your character file. Your agent gets a real-time trust
> score, can answer `"what is your trust score?"`, and is automatically
> blocked from financial actions when its score falls below your threshold.

```bash
npm install @elizaos/plugin-helixor
```

---

## Two-line integration

```typescript
import { helixorPlugin } from "@elizaos/plugin-helixor";

export default {
  name: "my-defi-agent",
  plugins: [helixorPlugin],                          // ← line 1
  settings: {
    SOLANA_PUBLIC_KEY:    "AGENT_HOT_WALLET_PUBKEY",
    HELIXOR_OWNER_WALLET: "OWNER_COLD_WALLET_PUBKEY",
    HELIXOR_API_URL:      "https://api.helixor.xyz", // ← line 2
  },
};
```

That's it. The plugin:
1. Validates configuration at startup (refuses to run if misconfigured)
2. Fetches the agent's score and prints it to console
3. Starts polling for score updates every 60s
4. Registers a TRUST_GATE evaluator that blocks any financial action when
   the score falls below `HELIXOR_MIN_SCORE` (default 600)
5. Lets users ask the agent for its score via natural language
6. Injects the current score into the agent's prompt context

---

## What's included

### Actions

| Action name | Purpose |
|-------------|---------|
| `HELIXOR_CHECK_TRUST_SCORE` | Triggered by phrases like "what is your trust score" |
| `HELIXOR_PREPARE_REGISTRATION` | Builds an unsigned register_agent transaction for the owner's wallet to sign |

### Evaluators

| Evaluator name | Purpose |
|----------------|---------|
| `HELIXOR_TRUST_GATE` | Runs before any financial action; blocks if score < minimum, stale, anomalous, deactivated, or provisional |

### Providers

| Provider | Purpose |
|----------|---------|
| `score_context` | Injects current score + alert into the LLM prompt so the agent knows its standing |

---

## Configuration

All settings come from `runtime.getSetting()`:

| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| `SOLANA_PUBLIC_KEY` | yes | — | Agent's monitored hot wallet (base58) |
| `HELIXOR_API_URL` | yes | — | API base URL (must include `http://` or `https://`) |
| `HELIXOR_OWNER_WALLET` | no | = agent | Owner's cold wallet (separate from agent) |
| `HELIXOR_MIN_SCORE` | no | 600 | Block financial actions below this |
| `HELIXOR_REFRESH_MS` | no | 60000 | Background score refresh interval |
| `HELIXOR_ALLOW_STALE` | no | false | Allow >48h-old scores |
| `HELIXOR_ALLOW_ANOMALY` | no | false | Allow anomaly-flagged scores |
| `HELIXOR_FINANCIAL_ACTIONS` | no | (defaults) | CSV of action names to gate |
| `HELIXOR_API_KEY` | no | — | Bearer token for authenticated API tier |
| `HELIXOR_TELEMETRY` | no | true | Log Helixor events to console |

---

## Default financial action list

The TRUST_GATE evaluator runs before any of these elizaOS action names:

```
SWAP_TOKEN, TRANSFER_TOKEN, LEND, BORROW,
STAKE, UNSTAKE, BUY, SELL, TRADE,
OPEN_POSITION, CLOSE_POSITION, WITHDRAW, DEPOSIT
```

Override with `HELIXOR_FINANCIAL_ACTIONS=YOUR_ACTION,ANOTHER_ACTION` (comma-separated, case-insensitive).

---

## Registration flow

The plugin will NOT auto-submit a registration transaction (it shouldn't hold
your owner private key). When the agent isn't yet registered, the plugin logs:

```
[Helixor] Agent not registered. Use the HELIXOR_PREPARE_REGISTRATION action
to build a registration tx for your wallet to sign.
```

Trigger the action through any user message ("register me with helixor"). The
plugin returns a base64 transaction. Decode + sign with your wallet (Phantom,
Backpack, hardware), submit to Solana, and Day 4's `agent_sync` will pick up
the registration within ~30s.

For automated infrastructure where you DO want to sign server-side, import
`submitRegistrationWithKeypair` directly:

```typescript
import { submitRegistrationWithKeypair } from "@elizaos/plugin-helixor";

const { signature, registrationPda } = await submitRegistrationWithKeypair(
  { agentWallet, ownerWallet, name: "MyAgent", rpcUrl: "https://..." },
  ownerKeypair, // EXPLICITLY YOURS — never read from env automatically
);
```

---

## Programmatic events

The plugin emits events on the runtime that other plugins can listen for:

```typescript
runtime.on("helixor:blocked", (payload) => {
  console.log(`Action blocked: ${payload.code}, score=${payload.score?.score}`);
});
```

Internally the plugin records telemetry events viewable via:

```typescript
import { getOrInitState, loadConfig } from "@elizaos/plugin-helixor";

const events = getOrInitState(runtime, loadConfig(runtime)).getTelemetry();
// → [{ type: "score_changed", timestamp, data: { from, to, delta } }, ...]
```

Event types include: `score_changed`, `alert_changed`, `anomaly_detected`,
`agent_deactivated`, `action_allowed`, `action_blocked`, `refresh_failed`,
`registration_prepared`, `init_fetch_failed`, `agent_not_registered`.

---

## Local dev / testing

```bash
git clone https://github.com/your-org/helixor-plugin-elizaos.git
cd helixor-plugin-elizaos
npm install
npm test               # 50+ tests across config, gate, registration, state
npm run build          # produces dist/
```

The test suite uses a mock fetch (`globalThis.fetch` override) and a synthetic
runtime — no real network, no real Solana, no real elizaOS host.

---

## What gets blocked

| Condition | Error |
|-----------|-------|
| score < HELIXOR_MIN_SCORE | `helixor:blocked:SCORE_TOO_LOW` |
| cert > 48h old | `helixor:blocked:STALE_SCORE` |
| anomaly_flag = true | `helixor:blocked:ANOMALY_DETECTED` |
| owner deactivated agent | `helixor:blocked:AGENT_DEACTIVATED` ← never overridable |
| no real score yet (provisional) | `helixor:blocked:PROVISIONAL_SCORE` ← never overridable for financial actions |
| API unreachable / unexpected error | `helixor:blocked:GATE_ERROR` ← fail-closed |

---

## License

MIT.
