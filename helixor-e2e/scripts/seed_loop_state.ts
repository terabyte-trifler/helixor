#!/usr/bin/env tsx
// =============================================================================
// scripts/seed_loop_state.ts — seed three test agents WITHOUT running tests.
//
// Useful for:
//   - Manually verifying the loop in a browser (Swagger UI / curl)
//   - Demoing the protocol without running vitest
//   - Pre-warming state for performance testing
//
// Prints the three agent pubkeys + a curl example so you can copy-paste.
// =============================================================================

import { loadEnv } from "../tests/env";
import {
  newAgentKeypair,
  openDb,
  seedRegisteredAgent,
  seedTransactions,
  teardownAgent,
} from "../tests/fixtures";
import { recomputeForAgent, runEpochOnce } from "../tests/pipeline";


async function main() {
  const env = loadEnv();
  const db  = await openDb(env);

  const stable      = newAgentKeypair().pubkey;
  const failing     = newAgentKeypair().pubkey;
  const provisional = newAgentKeypair().pubkey;
  const owner       = newAgentKeypair().pubkey;

  try {
    console.log("");
    console.log(`stable agent:      ${stable}`);
    console.log(`failing agent:     ${failing}`);
    console.log(`provisional agent: ${provisional}`);
    console.log("");

    await teardownAgent(db, stable);
    await teardownAgent(db, failing);
    await teardownAgent(db, provisional);

    await seedRegisteredAgent(db, {
      wallet: stable, ownerWallet: owner, name: "demo-stable",
      txCount: 100, activeDays: 25, successRate: 0.95, registeredDaysAgo: 35,
    });
    await seedRegisteredAgent(db, {
      wallet: failing, ownerWallet: owner, name: "demo-failing",
      txCount: 100, activeDays: 25, successRate: 0.3, registeredDaysAgo: 35,
    });
    await seedRegisteredAgent(db, {
      wallet: provisional, ownerWallet: owner, name: "demo-provisional",
      txCount: 0, activeDays: 0, successRate: 0, registeredDaysAgo: 1,
    });

    await seedTransactions(db, {
      wallet: stable, ownerWallet: owner,
      txCount: 100, activeDays: 25, successRate: 0.95,
    });
    await seedTransactions(db, {
      wallet: failing, ownerWallet: owner,
      txCount: 100, activeDays: 25, successRate: 0.3,
    });

    console.log("Computing scores...");
    await recomputeForAgent(stable);
    await recomputeForAgent(failing);

    console.log("Submitting on-chain...");
    await runEpochOnce();

    console.log("");
    console.log("──────────────────────────────────────────");
    console.log("Try it:");
    console.log("");
    console.log(`  curl ${env.apiUrl}/score/${stable}      # GREEN`);
    console.log(`  curl ${env.apiUrl}/score/${failing}     # RED`);
    console.log(`  curl ${env.apiUrl}/score/${provisional} # provisional`);
    console.log("");
    console.log(`  Tear down with: npm run teardown`);
    console.log("");
  } finally {
    await db.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
