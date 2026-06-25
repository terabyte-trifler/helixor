# Operator Onboarding — 10 Minutes

> The minimal sequence to get your elizaOS agent's Phylanx plugin running in
> production. If something doesn't fit on this page, it's not part of Day 12.

## What you'll have when you're done

- Phylanx plugin v0.12 running in your agent
- Plugin reports a real trust score on startup
- Financial actions are gated by score (mode=enforce by default)
- Telemetry is going back to the Phylanx team — they can see your integration
- You can paste a one-line confirmation into Discord/Telegram

## Five steps

### 1. Get your API key from the Phylanx team

Reach out on Discord (`#partners` channel) or email `partners@phylanx.xyz` with:

- Your organization name
- The agent wallet pubkey you'll be monitoring
- Your owner wallet pubkey (the one that funded registration)

You'll get back a key like `hxop_qwertyuiopasdfghjklzxcvbnm`. Save it — we
can't show it again.

### 2. Register your agent on-chain

If you haven't already:

```bash
# In the phylanx-programs directory:
ts-node scripts/register_agent.ts \
    --agent YOUR_AGENT_WALLET_PUBKEY \
    --owner YOUR_OWNER_WALLET_KEYPAIR.json \
    --name "your-agent-name"
```

This transfers 0.01 SOL from owner → escrow PDA. You can deactivate later
to recover the SOL.

### 3. Add the plugin to your character

```typescript
import { phylanxPlugin } from "@elizaos/plugin-phylanx";

export default {
  name: "my-trading-agent",
  plugins: [
    bootstrapPlugin,
    solanaPlugin,
    phylanxPlugin,            // ← this line
  ],
  settings: {
    SOLANA_PUBLIC_KEY:    "AGENT_HOT_WALLET",
    PHYLANX_OWNER_WALLET: "OWNER_COLD_WALLET",
    PHYLANX_API_URL:      "https://api.phylanx.xyz",
    PHYLANX_API_KEY:      "hxop_yourkey",
    // these are the production defaults — leave them as-is
    PHYLANX_MIN_SCORE:    "600",
    PHYLANX_MODE:         "enforce",
    PHYLANX_FAIL_MODE:    "closed",
  },
};
```

### 4. Start your agent

You should see something like this in your logs:

```
[Phylanx] plugin v0.12.0 initialized. agent=ABC123... api=https://api.phylanx.xyz mode=enforce fail_mode=closed minScore=600
[Phylanx] ✓ agent score: 742/1000 (GREEN) source=live fresh=true
```

If you see `Agent not registered`, go back to step 2.

### 5. Confirm via the status command

```bash
PHYLANX_API_KEY=hxop_yourkey npx @elizaos/plugin-phylanx status
```

You'll get a printable confirmation:

```
Phylanx plugin v0.12.0 is running for ACME Trading.
1 agent(s) integrated, 12 actions allowed and 0 blocked in the last 24 hours.
```

Paste that into Discord. The Phylanx team sees the same numbers from their
side — Day 12 is done.

---

## Configuration reference

| Setting | Required | Default | What it does |
|---------|----------|---------|--------------|
| `SOLANA_PUBLIC_KEY`      | yes | — | Your agent's hot wallet |
| `PHYLANX_API_URL`        | yes | — | API base URL — must include scheme |
| `PHYLANX_OWNER_WALLET`   | recommended | = agent | Cold owner wallet |
| `PHYLANX_API_KEY`        | recommended | — | Bearer token for partner tier |
| `PHYLANX_MIN_SCORE`      | no | 600 | Block financial actions below this |
| `PHYLANX_MODE`           | no | enforce | enforce \| warn \| observe |
| `PHYLANX_FAIL_MODE`      | no | closed | closed \| open (network error behavior) |
| `PHYLANX_ALLOW_STALE`    | no | false | Allow >48h old scores |
| `PHYLANX_ALLOW_ANOMALY`  | no | false | Allow anomaly-flagged scores |
| `PHYLANX_REFRESH_MS`     | no | 60000 | Background poll interval (≥5000) |

## Mode picker

| Choose | When |
|--------|------|
| `enforce` | Production. Financial actions are blocked when policy fails. |
| `warn` | First week of integration. Gate would block but allows through. Useful for tuning your `PHYLANX_MIN_SCORE` without disrupting agent behavior. |
| `observe` | Telemetry only — gate never participates. Useful to see what *would* be blocked before opting into `warn` or `enforce`. |

## Fail-mode picker

| Choose | When |
|--------|------|
| `closed` (default) | If Phylanx API is unreachable, BLOCK financial actions. Safer default — partner trust matters more than uptime. |
| `open` | If Phylanx API is unreachable, ALLOW financial actions. Use if your agent's continuous operation is more critical than the trust gate. We don't recommend this for production but it's available. |

## What we (Phylanx) see from your beacon

- Plugin version, elizaOS version, Node version
- Agent wallet, character name (if set)
- Each action that was allowed/blocked — by *action name*, never by content
- Score at the time of each decision

We do **not** see:
- User messages, prompts, or any text content
- Your private keys or signing material
- Anything outside the plugin's gate decisions

The plugin source is open: `src/telemetry/beacon.ts`. The PII filter is in
the same file (`PII_FORBIDDEN_KEYS`).

## When to file an issue

- Plugin logs an unexpected error during startup that isn't `AGENT_NOT_FOUND`
- You're getting blocks for actions you don't think should be blocked
- Status CLI returns 401 with a key the team just issued you
- `whoami` shows your integration but blocks_24h/allows_24h is always 0
  (= telemetry not flowing back to us)

GitHub: github.com/phylanx-protocol/plugin-phylanx/issues
Discord: `#partners`
