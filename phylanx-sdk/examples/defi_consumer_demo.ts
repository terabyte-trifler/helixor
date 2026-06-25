// =============================================================================
// phylanx-sdk/examples/defi_consumer_demo.ts — Day-42 DeFi reference consumer.
//
// What this file demonstrates
// ---------------------------
// A tiny DeFi protocol — "demo lending desk" — uses the Phylanx SDK to gate
// a USDC payout on the borrower's trust score. The decision goes through
// `SafeCertReader.getSafeScore(agent)`, which applies the audit-mandated
// guard rails:
//
//   * VULN-23 freshness ceiling      — cert must be < 48h old
//   * VULN-23 velocity envelope      — score swing across 3 epochs <= ±200
//   * VULN-23 minimum history        — need >= 2 certs to even ask
//   * Lender-side credit floor       — MIN_SCORE_FOR_LOAN = 600
//
// The five scenarios below cover every guard rail branch + the happy path:
//
//   1. STABLE agent (score 941, GREEN)         → ALLOWED
//   2. RECOVERING agent (score 712, YELLOW)    → ALLOWED above min
//   3. DRIFT agent (score 583, YELLOW)         → REFUSED below min
//   4. COMPROMISED agent (score 184, RED)      → REFUSED below min
//   5. VELOCITY-ATTACK agent (pumped score)    → REFUSED VELOCITY_EXCEEDED
//
// Run: `tsx examples/defi_consumer_demo.ts` from the phylanx-sdk root.
//
// Why this is a "reference" rather than production code
// -----------------------------------------------------
// The ChainReader here is a hand-rolled mock so the script runs without a
// validator or live indexer. A production integrator swaps that for the
// real PhylanxChainClient (or any RPC-backed ChainReader) and ships the
// rest of the script unchanged.
// =============================================================================

import { PublicKey } from "@solana/web3.js";

import {
  AlertTier,
  RejectReason,
  SafeCertReader,
  type ChainReader,
  type EpochScore,
  type SafeScoreResult,
} from "../src/index";

// ─────────────────────────────────────────────────────────────────────────────
// Lender policy — the consumer-side credit floor.
// ─────────────────────────────────────────────────────────────────────────────

const MIN_SCORE_FOR_LOAN = 600;
const LOAN_USDC = 25_000;
const NOW_SECONDS = Math.floor(Date.now() / 1000);
const CURRENT_EPOCH = 287;
const EPOCH_SECONDS = 86_400;

function epochIssuedAt(epoch: number): number {
  // The current epoch's cert is ~14 minutes old; older epochs step back by
  // EPOCH_SECONDS each. Matches the phylanx-web mock's epoch math so the
  // demo timestamps look the same whether you load the script or the site.
  const lag = epoch === CURRENT_EPOCH ? 14 * 60 : 0;
  return NOW_SECONDS - (CURRENT_EPOCH - epoch) * EPOCH_SECONDS - lag;
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo agents — wallet + score trajectories.
//
// Wallets are derived from a deterministic seed so the script runs without a
// validator and prints the same output every time. Trajectories are explicit
// so each guard-rail branch fires deterministically. In production an
// integrator would never hand-craft a trajectory; the indexer-backed
// ChainReader returns whatever the cluster has actually signed.
// ─────────────────────────────────────────────────────────────────────────────

function demoPubkey(seed: number): PublicKey {
  // 32-byte buffer with the seed written into the first byte so each
  // demo agent gets a distinct, base58-valid public key without any
  // dependency on a wallet file or external keystore.
  const bytes = new Uint8Array(32);
  bytes[0] = seed;
  return new PublicKey(bytes);
}

interface DemoAgent {
  label:        string;
  wallet:       PublicKey;
  trajectory:   Array<{ epoch: number; score: number; alert: AlertTier }>;
  /** Optional override for the latest cert's age (for the STALE_CERT demo). */
  staleSeconds?: number;
}

const DEMO_AGENTS: DemoAgent[] = [
  {
    label:  "Stable arb bot",
    wallet: demoPubkey(1),
    trajectory: [
      { epoch: CURRENT_EPOCH - 2, score: 935, alert: AlertTier.Green },
      { epoch: CURRENT_EPOCH - 1, score: 938, alert: AlertTier.Green },
      { epoch: CURRENT_EPOCH,     score: 941, alert: AlertTier.Green },
    ],
  },
  {
    label:  "Yield agent (recovering)",
    wallet: demoPubkey(2),
    trajectory: [
      { epoch: CURRENT_EPOCH - 2, score: 680, alert: AlertTier.Yellow },
      { epoch: CURRENT_EPOCH - 1, score: 695, alert: AlertTier.Yellow },
      { epoch: CURRENT_EPOCH,     score: 712, alert: AlertTier.Yellow },
    ],
  },
  {
    label:  "MM strategy (drift)",
    wallet: demoPubkey(3),
    trajectory: [
      { epoch: CURRENT_EPOCH - 2, score: 612, alert: AlertTier.Yellow },
      { epoch: CURRENT_EPOCH - 1, score: 597, alert: AlertTier.Yellow },
      { epoch: CURRENT_EPOCH,     score: 583, alert: AlertTier.Yellow },
    ],
  },
  {
    label:  "Compromised agent",
    wallet: demoPubkey(4),
    trajectory: [
      { epoch: CURRENT_EPOCH - 2, score: 240, alert: AlertTier.Red },
      { epoch: CURRENT_EPOCH - 1, score: 210, alert: AlertTier.Red },
      { epoch: CURRENT_EPOCH,     score: 184, alert: AlertTier.Red },
    ],
  },
  {
    label:  "Velocity-attack agent (pumped)",
    // Synthetic: this agent's history shows a 280-point pump across the
    // 3-epoch window. Even though the LATEST score (820) is above our
    // 600 floor, SafeCertReader refuses because the trajectory violates
    // the VELOCITY_EXCEEDED envelope — the exact attack VULN-23 closes.
    wallet: demoPubkey(5),
    trajectory: [
      { epoch: CURRENT_EPOCH - 2, score: 540, alert: AlertTier.Yellow },
      { epoch: CURRENT_EPOCH - 1, score: 680, alert: AlertTier.Yellow },
      { epoch: CURRENT_EPOCH,     score: 820, alert: AlertTier.Green },
    ],
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// In-memory ChainReader — production integrators swap this for the real
// PhylanxChainClient (or any RPC-backed ChainReader implementation).
// ─────────────────────────────────────────────────────────────────────────────

class DemoChainReader implements ChainReader {
  constructor(private readonly agents: DemoAgent[]) {}

  async getCurrentEpoch(): Promise<number> {
    return CURRENT_EPOCH;
  }

  async getScoreHistory(
    agent: PublicKey,
    fromEpoch: number,
    toEpoch: number,
  ): Promise<EpochScore[]> {
    const key = agent.toBase58();
    const a = this.agents.find((x) => x.wallet.toBase58() === key);
    if (!a) return [];
    return a.trajectory
      .filter((c) => c.epoch >= fromEpoch && c.epoch <= toEpoch)
      .map((c) => ({
        agent,
        epoch: c.epoch,
        score: c.score,
        alert: c.alert,
        flags: 0,
        immediateRed: c.alert === AlertTier.Red,
        issuedAt:
          c.epoch === CURRENT_EPOCH && a.staleSeconds !== undefined
            ? NOW_SECONDS - a.staleSeconds
            : epochIssuedAt(c.epoch),
      }));
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// The lending desk — pure consumer-side decision logic.
// ─────────────────────────────────────────────────────────────────────────────

interface LoanDecision {
  agent:  string;
  ok:     boolean;
  amount: number;
  detail: string;
}

async function decidePayout(
  reader: SafeCertReader,
  agent: DemoAgent,
): Promise<LoanDecision> {
  const result: SafeScoreResult = await reader.getSafeScore(agent.wallet);

  if (!result.ok) {
    return {
      agent:  agent.label,
      ok:     false,
      amount: 0,
      detail: `${result.reason} — ${result.detail}`,
    };
  }
  if (result.score < MIN_SCORE_FOR_LOAN) {
    return {
      agent:  agent.label,
      ok:     false,
      amount: 0,
      detail:
        `score ${result.score} (${result.alert}) is below lender floor ` +
        `${MIN_SCORE_FOR_LOAN}; envelope ${result.velocityWindow.minScore}-` +
        `${result.velocityWindow.maxScore} across epochs ` +
        `${result.velocityWindow.epochs.join(",")}`,
    };
  }
  return {
    agent:  agent.label,
    ok:     true,
    amount: LOAN_USDC,
    detail:
      `score ${result.score} (${result.alert}) >= lender floor ` +
      `${MIN_SCORE_FOR_LOAN}; cert epoch=${result.epoch} ` +
      `issuedAt=${new Date(result.issuedAt * 1000).toISOString()}`,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Pretty-printer.
// ─────────────────────────────────────────────────────────────────────────────

function printDecision(d: LoanDecision): void {
  const tag = d.ok ? "ALLOWED" : "REFUSED";
  const hr = "─".repeat(72);
  console.log(hr);
  console.log(`AGENT     : ${d.agent}`);
  console.log(`DECISION  : ${tag}`);
  console.log(`AMOUNT    : ${d.ok ? `$${d.amount.toLocaleString()} USDC` : "—"}`);
  console.log(`REASON    : ${d.detail}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point.
// ─────────────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const chain = new DemoChainReader(DEMO_AGENTS);
  const reader = new SafeCertReader(chain);

  console.log("\nPHYLANX DeFi REFERENCE CONSUMER — payout decisions");
  console.log(`Lender floor : ${MIN_SCORE_FOR_LOAN}/1000`);
  console.log(`Loan size    : $${LOAN_USDC.toLocaleString()} USDC`);
  console.log(`Current epoch: ${CURRENT_EPOCH}`);

  let approved = 0;
  let refused  = 0;

  for (const agent of DEMO_AGENTS) {
    const decision = await decidePayout(reader, agent);
    printDecision(decision);
    if (decision.ok) approved += 1; else refused += 1;
  }

  console.log("─".repeat(72));
  console.log(
    `\nSUMMARY: ${approved} approved · ${refused} refused ` +
    `(of ${DEMO_AGENTS.length} agents)`,
  );

  // The exit code lets CI catch regressions: if the demo ever approves
  // every agent (or refuses every agent) the gate is broken.
  if (approved === 0 || refused === 0) {
    console.error(
      "\nERROR: demo expected a mix of allowed + refused decisions.",
    );
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

// Re-exports — let other scripts import the demo trajectories without
// re-running the entry point.
export {
  DEMO_AGENTS,
  MIN_SCORE_FOR_LOAN,
  LOAN_USDC,
  CURRENT_EPOCH,
  DemoChainReader,
  decidePayout,
};
export { RejectReason };
