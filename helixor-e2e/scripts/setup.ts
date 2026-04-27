#!/usr/bin/env tsx
// =============================================================================
// scripts/setup.ts — bring up the full Helixor stack for E2E.
//
// This is the script you run on a fresh machine to validate the loop.
// It does NOT redeploy the program — that's a separate step the operator
// owns. It does:
//
//   1. Verify the program is deployed at the configured address
//   2. Verify oracle wallet has SOL
//   3. Verify Postgres is migrated
//   4. Verify all required services are reachable
//   5. Print a clean status report
//
// Run before `npm run test:loop`.
// =============================================================================

import { Connection } from "@solana/web3.js";

import { loadEnv, verifyConnectivity } from "../tests/env";
import { openDb } from "../tests/fixtures";


async function main() {
  console.log("");
  console.log("╔══════════════════════════════════════════════════╗");
  console.log("║  Helixor MVP — E2E setup verification            ║");
  console.log("╚══════════════════════════════════════════════════╝");
  console.log("");

  const env = loadEnv();
  console.log(`  api:     ${env.apiUrl}`);
  console.log(`  rpc:     ${env.solanaRpcUrl}`);
  console.log(`  program: ${env.programId.toBase58()}`);
  console.log(`  database: ${env.databaseUrl.replace(/:[^:@]*@/, ":****@")}`);
  console.log("");

  // ── Connectivity ──────────────────────────────────────────────────────────
  process.stdout.write("  • RPC + API + program... ");
  await verifyConnectivity(env);
  console.log("✓");

  // ── Oracle wallet balance ─────────────────────────────────────────────────
  process.stdout.write("  • Oracle wallet balance... ");
  // Reading the keypair file requires fs; we just check it exists
  const fs = await import("node:fs");
  if (!fs.existsSync(env.oracleKeypairPath)) {
    console.log("✗");
    throw new Error(`Oracle keypair not found at ${env.oracleKeypairPath}`);
  }
  const secret = JSON.parse(fs.readFileSync(env.oracleKeypairPath, "utf-8"));
  const { Keypair } = await import("@solana/web3.js");
  const kp = Keypair.fromSecretKey(Uint8Array.from(secret));
  const conn = new Connection(env.solanaRpcUrl, "confirmed");
  const lamports = await conn.getBalance(kp.publicKey);
  const sol = lamports / 1_000_000_000;
  console.log(`✓ ${sol.toFixed(4)} SOL (${kp.publicKey.toBase58()})`);
  if (lamports < 100_000_000) {
    console.log(`    ⚠ Oracle balance below 0.1 SOL — top up before running tests.`);
  }

  // ── DB schema ─────────────────────────────────────────────────────────────
  process.stdout.write("  • DB schema migrations... ");
  const db = await openDb(env);
  try {
    const r = await db.pool.query(`
      SELECT MAX(version) AS v FROM schema_version
    `);
    const v = r.rows[0]?.v ?? 0;
    console.log(`✓ schema_version = ${v}`);
    if (v < 3) {
      console.log(`    ⚠ Expected schema_version >= 3 (Day 6). Run migrations.`);
    }

    // Quick sanity counts
    const counts = await db.pool.query(`
      SELECT
        (SELECT COUNT(*) FROM registered_agents)   AS agents,
        (SELECT COUNT(*) FROM agent_transactions)  AS transactions,
        (SELECT COUNT(*) FROM agent_baselines)     AS baselines,
        (SELECT COUNT(*) FROM agent_scores)        AS scores
    `);
    const c = counts.rows[0];
    console.log(`    agents=${c.agents}  transactions=${c.transactions}  baselines=${c.baselines}  scores=${c.scores}`);
  } finally {
    await db.close();
  }

  // ── Result ────────────────────────────────────────────────────────────────
  console.log("");
  console.log("╔══════════════════════════════════════════════════╗");
  console.log("║  Setup OK — ready for `npm run test:loop`        ║");
  console.log("╚══════════════════════════════════════════════════╝");
  console.log("");
}


main().catch((err) => {
  console.error("");
  console.error(`✗ Setup failed: ${err.message ?? err}`);
  process.exitCode = 1;
});
