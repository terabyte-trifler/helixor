# Phylanx SDK examples

Runnable reference scripts that demonstrate the consumer-side API surface.

## `defi_consumer_demo.ts`

A tiny "demo lending desk" that gates a $25k USDC payout on each borrower's
Phylanx trust score. The decision goes through `SafeCertReader.getSafeScore`,
which applies the audit-mandated guard rails (VULN-23 freshness, velocity
envelope, minimum history). The script then layers a lender-side credit
floor (`MIN_SCORE_FOR_LOAN = 600`) on top.

Five scenarios cover every guard rail branch plus the happy path:

| # | agent                          | score | lender decision           |
| - | ------------------------------ | ----- | ------------------------- |
| 1 | Stable arb bot                 | 941   | ALLOWED                   |
| 2 | Recovering yield agent         | 712   | ALLOWED                   |
| 3 | Drift market maker             | 583   | REFUSED — below floor     |
| 4 | Compromised exfil agent        | 184   | REFUSED — below floor     |
| 5 | Velocity-attack (pumped score) | 820   | REFUSED — VELOCITY_EXCEEDED |

The fifth case is the punchline: the latest score (820) is comfortably above
the floor, but the 540 → 820 trajectory across three epochs trips the
velocity envelope. That is exactly the attack `SafeCertReader` exists to
refuse — a sybil-pumped score consumed just before an adverse downgrade
lands on chain.

### Run

```sh
npx tsx examples/defi_consumer_demo.ts
```

Exit code is non-zero if the demo ever flips to all-approve or all-refuse —
CI uses that as a regression check against the guard rails silently
loosening.

### Adapting to production

The script uses an in-memory `DemoChainReader` so it runs without a
validator. To wire it to mainnet / devnet, swap one line:

```ts
// before
const chain = new DemoChainReader(DEMO_AGENTS);

// after
const chain = new PhylanxChainClient({ connection, programIds });
```

The rest of the script — the lender policy, the decision printer, the
exit-code check — ships unchanged.
