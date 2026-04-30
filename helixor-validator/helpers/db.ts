// =============================================================================
// helpers/db.ts — direct Postgres access for seeding + injecting + reading.
// =============================================================================

import { Keypair } from "@solana/web3.js";
import pg from "pg";

import type { AgentProfile } from "../profiles/profiles";
import type { ValidationEnv } from "./env";

// Reuse the existing allowed synthetic transaction source from Day 10/13 so
// the validator works against the current DB schema without a new migration.
const VALIDATION_SOURCE_TAG = "e2e_seed";
const VALIDATION_AGENT_NAME_PREFIX = "validation_";


export interface DbHandle {
  pool:  pg.Pool;
  close: () => Promise<void>;
}


export async function openDb(env: ValidationEnv): Promise<DbHandle> {
  const pool = new pg.Pool({ connectionString: env.databaseUrl, max: 6 });
  const c = await pool.connect();
  await c.query("SELECT 1");
  c.release();
  return { pool, close: async () => { await pool.end(); } };
}


// =============================================================================
// Seeded agent generation
// =============================================================================

export interface SeededAgent {
  profileId:    string;
  wallet:       string;
  ownerWallet:  string;
  agentKp:      Keypair;
  registrationPda?: string;
  onchainSignature?: string;
}

export function generateAgent(profile: AgentProfile): SeededAgent {
  const agentKp = Keypair.generate();
  const ownerKp = Keypair.generate();
  return {
    profileId:   profile.id,
    wallet:      agentKp.publicKey.toBase58(),
    ownerWallet: ownerKp.publicKey.toBase58(),
    agentKp,
  };
}


// =============================================================================
// Pre-history seeding (the historical baseline before t=0)
// =============================================================================

export async function seedPreHistory(
  db:      DbHandle,
  agent:   SeededAgent,
  profile: AgentProfile,
): Promise<void> {
  // 1. Insert registration
  const registeredAt = new Date(Date.now() - profile.preHistoryDays * 86400_000);
  await db.pool.query(
    `INSERT INTO registered_agents
       (agent_wallet, owner_wallet, name, registration_pda,
        registered_at, onchain_signature, active)
     VALUES ($1, $2, $3, $4, $5, $6, TRUE)
     ON CONFLICT (agent_wallet) DO UPDATE SET active = TRUE`,
    [
      agent.wallet,
      agent.ownerWallet,
      `${VALIDATION_AGENT_NAME_PREFIX}${profile.id}`,
      agent.registrationPda ?? `REG_${agent.wallet.slice(0, 8)}_${"x".repeat(36)}`,
      registeredAt,
      agent.onchainSignature ?? `SEED_REG_${agent.wallet.slice(0, 16)}`,
    ],
  );

  // 2. Pre-history transactions, distributed evenly over preHistoryDays
  const totalTxs = Math.max(1, Math.floor(profile.txsPerDay * profile.preHistoryDays));
  const rng = mulberry32(hashString(agent.wallet + "pre"));

  const startMs = registeredAt.getTime();
  const endMs   = Date.now() - 60 * 60_000;  // stop 1h before now to avoid overlap with t=0

  const client = await db.pool.connect();
  try {
    await client.query("BEGIN");
    for (let i = 0; i < totalTxs; i++) {
      const blockTime = new Date(startMs + (endMs - startMs) * (i / totalTxs));
      const success   = rng() < profile.preHistorySuccessRate;
      const stddev    = profile.solVolatilityLamports ?? 1_000_000;
      const solChange = Math.floor((rng() - 0.5) * stddev * 2);
      await client.query(
        `INSERT INTO agent_transactions
           (agent_wallet, tx_signature, slot, block_time, success,
            program_ids, sol_change, fee, raw_meta, source)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 5000, '{}'::jsonb, $8)
         ON CONFLICT (tx_signature) DO NOTHING`,
        [
          agent.wallet,
          `D14_${agent.wallet.slice(0, 8)}_PRE_${String(i).padStart(7, "0")}`.padEnd(88, "x"),
          90_000_000 + i,
          blockTime,
          success,
          ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
          solChange,
          VALIDATION_SOURCE_TAG,
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


// =============================================================================
// Mid-validation injection — drip-feed transactions to simulate agent activity
// =============================================================================

export interface InjectArgs {
  agent:        SeededAgent;
  profile:      AgentProfile;
  /** Hours since validation start. */
  ageHours:     number;
  /** Number of transactions to inject this batch. */
  count:        number;
}

export async function injectTransactions(db: DbHandle, args: InjectArgs): Promise<{ injected: number; successRate: number }> {
  const successRate = args.profile.successRateAt(args.ageHours);
  const stddev      = args.profile.solVolatilityLamports ?? 1_000_000;
  const baseSlot    = 200_000_000 + Math.floor(args.ageHours * 100_000);

  const rng = mulberry32(hashString(args.agent.wallet + `${args.ageHours}`));
  let inserted = 0;

  const client = await db.pool.connect();
  try {
    await client.query("BEGIN");
    for (let i = 0; i < args.count; i++) {
      const blockTime = new Date();
      const success   = rng() < successRate;
      const solChange = Math.floor((rng() - 0.5) * stddev * 2);
      const r = await client.query(
        `INSERT INTO agent_transactions
           (agent_wallet, tx_signature, slot, block_time, success,
            program_ids, sol_change, fee, raw_meta, source)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 5000, '{}'::jsonb, $8)
         ON CONFLICT (tx_signature) DO NOTHING`,
        [
          args.agent.wallet,
          `D14_${args.agent.wallet.slice(0,8)}_INJ_${String(args.ageHours.toFixed(2)).padStart(6,"0")}_${i.toString().padStart(4,"0")}`
            .padEnd(88, "x"),
          baseSlot + i,
          blockTime, success,
          ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
          solChange,
          VALIDATION_SOURCE_TAG,
        ],
      );
      if ((r.rowCount ?? 0) > 0) inserted++;
    }
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }

  return { injected: inserted, successRate };
}


// =============================================================================
// Teardown
// =============================================================================

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

export async function teardownAllValidationData(db: DbHandle): Promise<number> {
  const r = await db.pool.query(
    `SELECT agent_wallet
       FROM registered_agents
      WHERE name LIKE $1`,
    [`${VALIDATION_AGENT_NAME_PREFIX}%`],
  );
  for (const row of r.rows) {
    await teardownAgent(db, row.agent_wallet);
  }
  return r.rows.length;
}


// =============================================================================
// Deterministic helpers
// =============================================================================

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
