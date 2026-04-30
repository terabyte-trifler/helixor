// =============================================================================
// helpers/fixtures.ts — DB-direct fixture seeding for integration tests.
//
// Every test uses a UNIQUE agent (Keypair.generate()) so concurrent test
// files don't interfere. Agents tagged source='e2e_seed' for
// targeted teardown. ON CONFLICT DO NOTHING for idempotent re-runs.
// =============================================================================

import { Keypair } from "@solana/web3.js";
import pg from "pg";

import type { IntegrationEnv } from "./env";

const SEED_SOURCE = "e2e_seed";


export interface SeededAgent {
  wallet:      string;
  ownerWallet: string;
  keypair:     Keypair;
}

export interface DbHandle {
  pool:  pg.Pool;
  close: () => Promise<void>;
}

export async function openDb(env: IntegrationEnv): Promise<DbHandle> {
  const pool = new pg.Pool({ connectionString: env.databaseUrl, max: 4 });
  const c = await pool.connect();
  await c.query("SELECT 1");
  c.release();
  return { pool, close: async () => { await pool.end(); } };
}

export function freshAgent(): SeededAgent {
  const agentKp = Keypair.generate();
  const ownerKp = Keypair.generate();
  return {
    wallet:      agentKp.publicKey.toBase58(),
    ownerWallet: ownerKp.publicKey.toBase58(),
    keypair:     agentKp,
  };
}


// ─────────────────────────────────────────────────────────────────────────────
// Registration (DB-only — bypasses on-chain registration since we're testing
// off-chain layers). On-chain tests use a separate path via Anchor.
// ─────────────────────────────────────────────────────────────────────────────

export interface SeedAgentArgs {
  agent:                SeededAgent;
  registeredDaysAgo?:   number;
  active?:              boolean;
  name?:                string;
}

export async function seedRegisteredAgent(
  db:   DbHandle,
  args: SeedAgentArgs,
): Promise<void> {
  const registeredAt = new Date(
    Date.now() - (args.registeredDaysAgo ?? 30) * 86400_000,
  );
  await db.pool.query(
    `INSERT INTO registered_agents
       (agent_wallet, owner_wallet, name, registration_pda,
        registered_at, onchain_signature, active)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (agent_wallet) DO UPDATE SET
       active        = EXCLUDED.active,
       registered_at = LEAST(registered_agents.registered_at, EXCLUDED.registered_at)`,
    [
      args.agent.wallet,
      args.agent.ownerWallet,
      args.name ?? `${SEED_SOURCE}-${args.agent.wallet.slice(0, 8)}`,
      `REG_${args.agent.wallet.slice(0, 8)}_${"x".repeat(36)}`,
      registeredAt,
      `SEED_REG_${args.agent.wallet.slice(0, 16)}`,
      args.active ?? true,
    ],
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// Transactions — deterministic per-wallet RNG so tests are reproducible.
// ─────────────────────────────────────────────────────────────────────────────

export interface SeedTxArgs {
  agent:        SeededAgent;
  txCount:      number;
  activeDays:   number;
  successRate:  number;
  /** Distribute over [now-activeDays, now] (default) or specific window. */
  endTime?:     Date;
  startTime?:   Date;
}

export async function seedTransactions(db: DbHandle, args: SeedTxArgs): Promise<void> {
  const end   = args.endTime   ?? new Date();
  const start = args.startTime ?? new Date(end.getTime() - args.activeDays * 86400_000);
  const span  = end.getTime() - start.getTime();
  if (span <= 0) throw new Error("seed window has non-positive span");

  const rng = mulberry32(hashString(args.agent.wallet));
  const client = await db.pool.connect();
  try {
    await client.query("BEGIN");
    for (let i = 0; i < args.txCount; i++) {
      const blockTime = new Date(start.getTime() + Math.floor(rng() * span));
      const success   = rng() < args.successRate;
      const solChange = Math.floor((rng() - 0.5) * 2_000_000);
      await client.query(
        `INSERT INTO agent_transactions
           (agent_wallet, tx_signature, slot, block_time, success,
            program_ids, sol_change, fee, raw_meta, source)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '{}'::jsonb, $9)
         ON CONFLICT (tx_signature) DO NOTHING`,
        [
          args.agent.wallet,
          deterministicSignature(args.agent.wallet, i),
          100_000_000 + i,
          blockTime,
          success,
          ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
          solChange,
          5000,
          SEED_SOURCE,
        ],
      );
    }
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// Direct score injection — for tests that don't need to drive baseline + scoring
// ─────────────────────────────────────────────────────────────────────────────

export interface InjectScoreArgs {
  agent:           SeededAgent;
  score:           number;
  alert?:          "GREEN" | "YELLOW" | "RED";
  successRate?:    number;
  txCount?:        number;
  anomalyFlag?:    boolean;
  computedAt?:     Date;
  writtenOnchainAt?: Date | null;
  algoVersion?:    number;
  weightsVersion?: number;
}

export async function injectScore(db: DbHandle, args: InjectScoreArgs): Promise<void> {
  const score = args.score;
  const alert = args.alert
              ?? (score >= 700 ? "GREEN" : score >= 400 ? "YELLOW" : "RED");
  const now = new Date();
  const computedAt = args.computedAt ?? now;
  const writtenAt  = args.writtenOnchainAt === undefined ? now : args.writtenOnchainAt;
  const successRate = args.successRate ?? 0.95;
  const txCount     = args.txCount     ?? 50;

  await db.pool.query(
    `INSERT INTO agent_scores (
       agent_wallet, score, alert,
       success_rate_score, consistency_score, stability_score,
       raw_score, guard_rail_applied,
       window_success_rate, window_tx_count, window_sol_volatility,
       baseline_hash, baseline_algo_version,
       anomaly_flag, scoring_algo_version, weights_version,
       computed_at, written_onchain_at
     ) VALUES (
       $1, $2, $3,
       $4, $5, $6,
       $2, FALSE,
       $7, $8, 1000000,
       'abc' || repeat('0', 61), 1,
       $9, $10, $11,
       $12, $13
     )
     ON CONFLICT (agent_wallet) DO UPDATE SET
       score              = EXCLUDED.score,
       alert              = EXCLUDED.alert,
       window_success_rate = EXCLUDED.window_success_rate,
       window_tx_count    = EXCLUDED.window_tx_count,
       anomaly_flag       = EXCLUDED.anomaly_flag,
       computed_at        = EXCLUDED.computed_at,
       written_onchain_at = EXCLUDED.written_onchain_at,
       success_rate_score = EXCLUDED.success_rate_score,
       consistency_score  = EXCLUDED.consistency_score,
       stability_score    = EXCLUDED.stability_score`,
    [
      args.agent.wallet, score, alert,
      Math.min(500, Math.max(0, Math.floor(score * 0.5))),
      Math.min(300, Math.max(0, Math.floor(score * 0.3))),
      Math.min(200, Math.max(0, Math.floor(score * 0.2))),
      successRate, txCount,
      args.anomalyFlag ?? false,
      args.algoVersion    ?? 1,
      args.weightsVersion ?? 1,
      computedAt,
      writtenAt,
    ],
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// Teardown
// ─────────────────────────────────────────────────────────────────────────────

export async function teardownAgent(db: DbHandle, wallet: string): Promise<void> {
  const c = await db.pool.connect();
  try {
    await c.query("BEGIN");
    await c.query("DELETE FROM agent_score_history    WHERE agent_wallet = $1", [wallet]);
    await c.query("DELETE FROM agent_scores           WHERE agent_wallet = $1", [wallet]);
    await c.query("DELETE FROM agent_baseline_history WHERE agent_wallet = $1", [wallet]);
    await c.query("DELETE FROM agent_baselines        WHERE agent_wallet = $1", [wallet]);
    await c.query("DELETE FROM agent_transactions     WHERE agent_wallet = $1", [wallet]);
    await c.query("DELETE FROM monitored_agents       WHERE agent_wallet = $1", [wallet]);
    await c.query("DELETE FROM registered_agents      WHERE agent_wallet = $1", [wallet]);
    await c.query("COMMIT");
  } catch (err) {
    await c.query("ROLLBACK");
    throw err;
  } finally {
    c.release();
  }
}

/** Bulk teardown — removes everything seeded by integration tests. */
export async function teardownAll(db: DbHandle): Promise<number> {
  const r = await db.pool.query(
    `SELECT DISTINCT agent_wallet FROM agent_transactions WHERE source = $1`,
    [SEED_SOURCE],
  );
  const wallets = r.rows.map(row => row.agent_wallet);
  for (const w of wallets) await teardownAgent(db, w);
  return wallets.length;
}


// ─────────────────────────────────────────────────────────────────────────────
// Deterministic helpers
// ─────────────────────────────────────────────────────────────────────────────

function deterministicSignature(wallet: string, idx: number): string {
  const seed = `D13_${wallet.slice(0, 8)}_${String(idx).padStart(6, "0")}`;
  return (seed + "x".repeat(88)).slice(0, 88);
}

function hashString(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) - h) + s.charCodeAt(i);
    h = h & 0x7fffffff;
  }
  return h;
}

function mulberry32(a: number): () => number {
  return () => {
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
