#!/usr/bin/env tsx
// =============================================================================
// scripts/teardown.ts — remove all e2e_seed transactions + their agents.
//
// Use after a failed test run that left state behind.
// =============================================================================

import { loadEnv } from "../tests/env";
import { openDb } from "../tests/fixtures";

async function main() {
  const env = loadEnv();
  const db  = await openDb(env);

  try {
    // Find all agents that have ANY tx with source='e2e_seed'
    const r = await db.pool.query(`
      SELECT DISTINCT agent_wallet
      FROM agent_transactions
      WHERE source = 'e2e_seed'
    `);
    const agents = r.rows.map(row => row.agent_wallet as string);

    console.log(`Found ${agents.length} test agents to teardown.`);

    for (const agent of agents) {
      const c = await db.pool.connect();
      try {
        await c.query("BEGIN");
        await c.query("DELETE FROM agent_score_history WHERE agent_wallet = $1", [agent]);
        await c.query("DELETE FROM agent_scores WHERE agent_wallet = $1", [agent]);
        await c.query("DELETE FROM agent_baseline_history WHERE agent_wallet = $1", [agent]);
        await c.query("DELETE FROM agent_baselines WHERE agent_wallet = $1", [agent]);
        await c.query("DELETE FROM agent_transactions WHERE agent_wallet = $1", [agent]);
        await c.query("DELETE FROM registered_agents WHERE agent_wallet = $1", [agent]);
        await c.query("COMMIT");
        console.log(`  ✓ ${agent.slice(0, 16)}...`);
      } catch (err) {
        await c.query("ROLLBACK");
        console.error(`  ✗ ${agent.slice(0, 16)}... — ${err}`);
      } finally {
        c.release();
      }
    }
  } finally {
    await db.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
