# @elizaos/plugin-phylanx

> Phylanx trust scoring for elizaOS agents.
>
> Adds two lines to your character file. Your agent gets a real-time trust
> score, can answer `"what is your trust score?"`, and is automatically
> blocked from financial actions when its score falls below your threshold.

```bash
npm install @elizaos/plugin-phylanx
```

---

## Two-line integration

```typescript
import { phylanxPlugin } from "@elizaos/plugin-phylanx";

export default {
  name: "my-defi-agent",
  plugins: [phylanxPlugin],                          // ← line 1
  settings: {
    SOLANA_PUBLIC_KEY:    "AGENT_HOT_WALLET_PUBKEY",
    PHYLANX_OWNER_WALLET: "OWNER_COLD_WALLET_PUBKEY",
    PHYLANX_API_URL:      "https://api.phylanx.xyz", // ← line 2
  },
};
```

That's it. The plugin:
1. Validates configuration at startup (refuses to run if misconfigured)
2. Fetches the agent's score and prints it to console
3. Starts polling for score updates every 60s
4. Registers a TRUST_GATE evaluator that blocks any financial action when
   the score falls below `PHYLANX_MIN_SCORE` (default 600)
5. Lets users ask the agent for its score via natural language
6. Injects the current score into the agent's prompt context

---

## What's included

### Actions

| Action name | Purpose |
|-------------|---------|
| `PHYLANX_CHECK_TRUST_SCORE` | Triggered by phrases like "what is your trust score" |
| `PHYLANX_PREPARE_REGISTRATION` | Builds an unsigned register_agent transaction for the owner's wallet to sign |

### Evaluators

| Evaluator name | Purpose |
|----------------|---------|
| `PHYLANX_TRUST_GATE` | Runs before any financial action; blocks if score < minimum, stale, anomalous, deactivated, or provisional |

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
| `PHYLANX_API_URL` | yes | — | API base URL (must include `http://` or `https://`) |
| `PHYLANX_OWNER_WALLET` | no | = agent | Owner's cold wallet (separate from agent) |
| `PHYLANX_MIN_SCORE` | no | 600 | Block financial actions below this |
| `PHYLANX_REFRESH_MS` | no | 60000 | Background score refresh interval |
| `PHYLANX_ALLOW_STALE` | no | false | Allow >48h-old scores |
| `PHYLANX_ALLOW_ANOMALY` | no | false | Allow anomaly-flagged scores |
| `PHYLANX_FINANCIAL_ACTIONS` | no | (defaults) | CSV of action names to gate |
| `PHYLANX_API_KEY` | no | — | Bearer token for authenticated API tier |
| `PHYLANX_TELEMETRY` | no | true | Log Phylanx events to console |

---

## Default financial action list

The TRUST_GATE evaluator runs before any of these elizaOS action names:

```
SWAP_TOKEN, TRANSFER_TOKEN, LEND, BORROW,
STAKE, UNSTAKE, BUY, SELL, TRADE,
OPEN_POSITION, CLOSE_POSITION, WITHDRAW, DEPOSIT
```

Override with `PHYLANX_FINANCIAL_ACTIONS=YOUR_ACTION,ANOTHER_ACTION` (comma-separated, case-insensitive).

---

## Registration flow

The plugin will NOT auto-submit a registration transaction (it shouldn't hold
your owner private key). When the agent isn't yet registered, the plugin logs:

```
[Phylanx] Agent not registered. Use the PHYLANX_PREPARE_REGISTRATION action
to build a registration tx for your wallet to sign.
```

Trigger the action through any user message ("register me with phylanx"). The
plugin returns a base64 transaction. Decode + sign with your wallet (Phantom,
Backpack, hardware), submit to Solana, and Day 4's `agent_sync` will pick up
the registration within ~30s.

For automated infrastructure where you DO want to sign server-side, import
`submitRegistrationWithKeypair` directly:

```typescript
import { submitRegistrationWithKeypair } from "@elizaos/plugin-phylanx";

const { signature, registrationPda } = await submitRegistrationWithKeypair(
  { agentWallet, ownerWallet, name: "MyAgent", rpcUrl: "https://..." },
  ownerKeypair, // EXPLICITLY YOURS — never read from env automatically
);
```

---

## Programmatic events

The plugin emits events on the runtime that other plugins can listen for:

```typescript
runtime.on("phylanx:blocked", (payload) => {
  console.log(`Action blocked: ${payload.code}, score=${payload.score?.score}`);
});
```

Internally the plugin records telemetry events viewable via:

```typescript
import { getOrInitState, loadConfig } from "@elizaos/plugin-phylanx";

const events = getOrInitState(runtime, loadConfig(runtime)).getTelemetry();
// → [{ type: "score_changed", timestamp, data: { from, to, delta } }, ...]
```

Event types include: `score_changed`, `alert_changed`, `anomaly_detected`,
`agent_deactivated`, `action_allowed`, `action_blocked`, `refresh_failed`,
`registration_prepared`, `init_fetch_failed`, `agent_not_registered`.

---

## Local dev / testing

```bash
git clone https://github.com/your-org/phylanx-plugin-elizaos.git
cd phylanx-plugin-elizaos
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
| score < PHYLANX_MIN_SCORE | `phylanx:blocked:SCORE_TOO_LOW` |
| cert > 48h old | `phylanx:blocked:STALE_SCORE` |
| anomaly_flag = true | `phylanx:blocked:ANOMALY_DETECTED` |
| owner deactivated agent | `phylanx:blocked:AGENT_DEACTIVATED` ← never overridable |
| no real score yet (provisional) | `phylanx:blocked:PROVISIONAL_SCORE` ← never overridable for financial actions |
| API unreachable / unexpected error | `phylanx:blocked:GATE_ERROR` ← fail-closed |

---

## License

MIT.
