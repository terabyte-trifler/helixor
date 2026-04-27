// =============================================================================
// tests/fixtures.ts — DB-direct test data seeding.
//
// Why direct DB seeding instead of waiting for real Helius webhooks: a CI
// run can't poll Helius for an hour and hope transactions arrive. We inject
// directly into agent_transactions, then trigger the baseline + score
// pipelines manually. Webhook ingestion is tested separately in Day 4.
//
// All seeded transactions use deterministic signatures based on the agent
// wallet so re-runs are idempotent (ON CONFLICT DO NOTHING in inserts).
// =============================================================================

import bs58 from "bs58";
import fs from "node:fs";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import pg from "pg";

import type { E2EEnv } from "./env";

const SOLANA_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

export interface SeedAgentArgs {
  wallet:         string;
  ownerWallet:    string;
  name?:          string;
  txCount:        number;
  activeDays:     number;
  successRate:    number;
  registeredDaysAgo?: number;
}

export interface DbHandle {
  pool: pg.Pool;
  close: () => Promise<void>;
}

const REGISTER_AGENT_DISCRIMINATOR = Uint8Array.from([
  0x87, 0x9d, 0x42, 0xc3, 0x02, 0x71, 0xaf, 0x1e,
]);
const MIN_ESCROW_LAMPORTS = 10_000_000;

export async function openDb(env: E2EEnv): Promise<DbHandle> {
  const pool = new pg.Pool({ connectionString: env.databaseUrl, max: 4 });
  // Verify connectivity once
  const c = await pool.connect();
  await c.query("SELECT 1");
  c.release();
  return { pool, close: async () => { await pool.end(); } };
}

export function newAgentKeypair(): { pubkey: string; keypair: Keypair } {
  const kp = Keypair.generate();
  return { pubkey: kp.publicKey.toBase58(), keypair: kp };
}

export function loadKeypairFromFile(filePath: string): Keypair {
  const secret = JSON.parse(fs.readFileSync(filePath, "utf-8"));
  return Keypair.fromSecretKey(Uint8Array.from(secret));
}

export function deriveAgentPdas(programId: PublicKey, agentWallet: string): {
  registrationPda: PublicKey;
  escrowVaultPda: PublicKey;
} {
  const agent = new PublicKey(agentWallet);
  const [registrationPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("agent"), agent.toBuffer()],
    programId,
  );
  const [escrowVaultPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("escrow"), agent.toBuffer()],
    programId,
  );
  return { registrationPda, escrowVaultPda };
}

export async function registerAgentOnchain(
  env: E2EEnv,
  owner: Keypair,
  agentWallet: string,
  name: string,
): Promise<{ signature: string; registrationPda: string; escrowVaultPda: string }> {
  const conn = new Connection(env.solanaRpcUrl, "confirmed");
  const agent = new PublicKey(agentWallet);
  const { registrationPda, escrowVaultPda } = deriveAgentPdas(env.programId, agentWallet);

  const existing = await conn.getAccountInfo(registrationPda);
  if (existing) {
    return {
      signature: "ALREADY_REGISTERED",
      registrationPda: registrationPda.toBase58(),
      escrowVaultPda: escrowVaultPda.toBase58(),
    };
  }

  const nameBytes = new TextEncoder().encode(name);
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32LE(nameBytes.length, 0);
  const data = Buffer.concat([
    Buffer.from(REGISTER_AGENT_DISCRIMINATOR),
    lenBuf,
    Buffer.from(nameBytes),
  ]);

  const ix = new TransactionInstruction({
    programId: env.programId,
    keys: [
      { pubkey: owner.publicKey, isSigner: true, isWritable: true },
      { pubkey: agent, isSigner: false, isWritable: false },
      { pubkey: registrationPda, isSigner: false, isWritable: true },
      { pubkey: escrowVaultPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });

  const latest = await conn.getLatestBlockhash("confirmed");
  const tx = new Transaction({
    feePayer: owner.publicKey,
    recentBlockhash: latest.blockhash,
  }).add(ix);

  tx.sign(owner);
  const signature = await conn.sendRawTransaction(tx.serialize(), {
    skipPreflight: false,
    preflightCommitment: "confirmed",
  });
  await conn.confirmTransaction(
    {
      signature,
      blockhash: latest.blockhash,
      lastValidBlockHeight: latest.lastValidBlockHeight,
    },
    "confirmed",
  );

  const vaultBalance = await conn.getBalance(escrowVaultPda, "confirmed");
  if (vaultBalance < MIN_ESCROW_LAMPORTS) {
    throw new Error(
      `Expected escrow vault to hold at least ${MIN_ESCROW_LAMPORTS} lamports, got ${vaultBalance}`,
    );
  }

  return {
    signature,
    registrationPda: registrationPda.toBase58(),
    escrowVaultPda: escrowVaultPda.toBase58(),
  };
}

/**
 * Deterministic signature based on wallet + index. Lets re-runs ON CONFLICT
 * cleanly without duplicating data.
 */
function deterministicSignature(wallet: string, idx: number): string {
  // 88-char base58 (typical Solana sig length is 64 bytes -> 88 chars)
  const seed = `SEED_${wallet.slice(0, 8)}_${String(idx).padStart(6, "0")}`;
  // Pad with deterministic chars to ~88 chars, base58-safe
  const padded = (seed + "x".repeat(88)).slice(0, 88);
  return padded;
}

/** Insert a registered_agents row directly. Bypasses on-chain registration. */
export async function seedRegisteredAgent(
  db: DbHandle,
  args: SeedAgentArgs,
): Promise<void> {
  const registeredAt = new Date(
    Date.now() - (args.registeredDaysAgo ?? 30) * 86400_000,
  );

  await db.pool.query(
    `INSERT INTO registered_agents
       (agent_wallet, owner_wallet, name, registration_pda,
        registered_at, onchain_signature, active)
     VALUES ($1, $2, $3, $4, $5, $6, TRUE)
     ON CONFLICT (agent_wallet) DO UPDATE SET
       active = TRUE,
       registered_at = LEAST(registered_agents.registered_at, EXCLUDED.registered_at)`,
    [
      args.wallet,
      args.ownerWallet,
      args.name ?? `e2e-${args.wallet.slice(0, 8)}`,
      `REG_${args.wallet.slice(0, 8)}_${"x".repeat(36)}`,
      registeredAt,
      `SEED_REG_${args.wallet.slice(0, 16)}`,
    ],
  );
}

/** Seed N transactions distributed across active_days, with target success rate. */
export async function seedTransactions(
  db: DbHandle,
  args: SeedAgentArgs,
): Promise<void> {
  const txPerDay = Math.max(1, Math.floor(args.txCount / args.activeDays));
  const remainder = args.txCount - txPerDay * args.activeDays;
  // Determinism: rng seeded from wallet
  let rng = mulberry32(hashString(args.wallet));

  let txIdx = 0;
  const client = await db.pool.connect();
  try {
    await client.query("BEGIN");

    for (let day = 0; day < args.activeDays; day++) {
      const count = txPerDay + (day < remainder ? 1 : 0);
      const dayBase = new Date(Date.now() - day * 86400_000);
      const successTarget = Math.round(count * args.successRate);
      const outcomes = Array.from({ length: count }, (_, idx) => idx < successTarget);
      shuffleInPlace(outcomes, rng);

      for (let i = 0; i < count; i++) {
        txIdx++;
        const blockTime = new Date(dayBase.getTime() - Math.floor(rng() * 86400_000));
        const success   = outcomes[i] ?? false;
        const solChange = Math.floor((rng() - 0.5) * 2_000_000); // ±0.001 SOL

        await client.query(
          `INSERT INTO agent_transactions
             (agent_wallet, tx_signature, slot, block_time, success,
              program_ids, sol_change, fee, raw_meta, source)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '{}'::jsonb, 'e2e_seed')
           ON CONFLICT (tx_signature) DO NOTHING`,
          [
            args.wallet,
            deterministicSignature(args.wallet, txIdx),
            100_000_000 + txIdx,
            blockTime,
            success,
            [SOLANA_TOKEN_PROGRAM],
            solChange,
            5000,
          ],
        );
      }
    }

    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

/** Remove a test agent and its data. Idempotent. */
export async function teardownAgent(
  db: DbHandle,
  agentWallet: string,
): Promise<void> {
  const client = await db.pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("DELETE FROM agent_score_history WHERE agent_wallet = $1", [agentWallet]);
    await client.query("DELETE FROM agent_scores WHERE agent_wallet = $1", [agentWallet]);
    await client.query("DELETE FROM agent_baseline_history WHERE agent_wallet = $1", [agentWallet]);
    await client.query("DELETE FROM agent_baselines WHERE agent_wallet = $1", [agentWallet]);
    await client.query("DELETE FROM agent_transactions WHERE agent_wallet = $1", [agentWallet]);
    await client.query("DELETE FROM registered_agents WHERE agent_wallet = $1", [agentWallet]);
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic RNG so tests are reproducible
// ─────────────────────────────────────────────────────────────────────────────

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

function shuffleInPlace<T>(items: T[], rng: () => number): void {
  for (let i = items.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [items[i], items[j]] = [items[j], items[i]];
  }
}

// Re-export for convenience
export { bs58 };
