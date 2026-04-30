#!/usr/bin/env tsx
// =============================================================================
// scripts/teardown_validation.ts — clean up after a validation run.
// Removes ALL agents tagged 'day14_validation' from the DB.
// =============================================================================

import { loadEnv } from "../helpers/env";
import { openDb, teardownAllValidationData } from "../helpers/db";


async function main(): Promise<number> {
  const env = loadEnv();
  const db  = await openDb(env);

  console.log("");
  process.stdout.write("  • removing validation agents ... ");
  try {
    const removed = await teardownAllValidationData(db);
    console.log(`\x1b[32m✓\x1b[0m  (${removed} agents removed)`);
  } finally {
    await db.close();
  }
  console.log("");
  return 0;
}


main().then(c => process.exit(c)).catch(err => { console.error(err); process.exit(1); });
