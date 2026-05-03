#!/usr/bin/env tsx
// =============================================================================
// scripts/stage_validation.ts — STAGE the 48h validation.
//
// Creates 5 agents (one per profile), seeds each with the profile's pre-history,
// runs an initial baseline + score so the system is in a known state at t=0,
// writes state.json with run metadata.
//
// Idempotent: re-running does NOT corrupt prior state — it creates a NEW runId.
// =============================================================================

import crypto from "node:crypto";

import { loadEnv, verifyConnectivity } from "../helpers/env";
import {
  generateAgent, openDb, seedPreHistory, teardownAllValidationData,
} from "../helpers/db";
import { loadKeypairFromFile, registerAgentOnchain } from "../helpers/onchain";
import { recomputeForAgent } from "../helpers/pipeline";
import {
  newState, saveState, type AgentRecord, type ValidationState,
} from "../helpers/state";
import { ALL_PROFILES } from "../profiles/profiles";


const DEFAULT_DURATION_HOURS = 48;
const DEFAULT_SNAPSHOT_INTERVAL_MIN = 30;


async function main(): Promise<number> {
  console.log("");
  console.log("╔════════════════════════════════════════════════════════════╗");
  console.log("║  Helixor — Day 14 Devnet Validation: STAGE                 ║");
  console.log("║  5 agents · 48h continuous · machine-checkable verdict     ║");
  console.log("╚════════════════════════════════════════════════════════════╝");
  console.log("");

  const env = loadEnv();
  const durationHours = Number(process.env.HELIXOR_VALIDATION_DURATION_HOURS ?? DEFAULT_DURATION_HOURS);
  const snapshotIntervalMin = Number(
    process.env.HELIXOR_VALIDATION_SNAPSHOT_INTERVAL_MIN ?? DEFAULT_SNAPSHOT_INTERVAL_MIN,
  );
  console.log(`  api:     ${env.apiUrl}`);
  console.log(`  rpc:     ${env.solanaRpcUrl}`);
  console.log(`  program: ${env.programId.toBase58()}`);
  console.log(`  duration:${durationHours}h`);
  console.log("");

  // 1. Connectivity
  process.stdout.write("  • verifying connectivity ........... ");
  await verifyConnectivity(env);
  console.log("\x1b[32m✓\x1b[0m");

  // 2. Optional: clear prior validation data if requested
  const db = await openDb(env);
  if (process.env.HELIXOR_VALIDATION_FRESH_START === "1") {
    process.stdout.write("  • clearing prior validation data ... ");
    const removed = await teardownAllValidationData(db);
    console.log(`\x1b[32m✓\x1b[0m  (${removed} agents)`);
  }

  // 3. Generate fresh agents — one per profile
  process.stdout.write("  • generating 5 fresh agents ........ ");
  const agents = ALL_PROFILES.map(p => ({ profile: p, agent: generateAgent(p) }));
  console.log("\x1b[32m✓\x1b[0m");

  const owner = loadKeypairFromFile(env.ownerKeypairPath);
  for (const { agent } of agents) {
    agent.ownerWallet = owner.publicKey.toBase58();
  }

  for (const { profile, agent } of agents) {
    console.log(`      ${profile.id.padEnd(11)} ${agent.wallet}`);
  }

  // 4. Register each agent on-chain so epoch submissions have a real
  // AgentRegistration PDA to target.
  console.log("");
  console.log("  • registering agents on-chain:");
  for (const { profile, agent } of agents) {
    process.stdout.write(`      ${profile.id.padEnd(11)} ... `);
    const reg = await registerAgentOnchain(env, owner, agent.agentKp, `validation_${profile.id}`);
    agent.registrationPda = reg.registrationPda;
    agent.onchainSignature = reg.signature;
    console.log(`\x1b[32m✓\x1b[0m  (${reg.signature.slice(0, 12)}...)`);
  }

  // 5. Seed pre-history per agent
  console.log("");
  console.log("  • seeding pre-history per profile:");
  for (const { profile, agent } of agents) {
    const expectedTxs = profile.txsPerDay * profile.preHistoryDays;
    process.stdout.write(`      ${profile.id.padEnd(11)} → ${expectedTxs} txs ... `);
    await seedPreHistory(db, agent, profile);
    console.log("\x1b[32m✓\x1b[0m");
  }

  // 6. Initial baseline + score per agent (so t=0 state is meaningful)
  console.log("");
  console.log("  • initial baseline + score per agent:");
  for (const { profile, agent } of agents) {
    process.stdout.write(`      ${profile.id.padEnd(11)} ... `);
    const r = await recomputeForAgent(env, agent.wallet);
    if (r.exitCode !== 0) {
      console.log(`\x1b[31m✗\x1b[0m\n${r.stderr.slice(-300)}`);
      await db.close();
      return 1;
    }
    console.log(`\x1b[32m✓\x1b[0m  (${r.durationMs}ms)`);
  }

  await db.close();

  // 7. Persist state
  const runId = crypto.randomUUID().slice(0, 8);
  const state: ValidationState = newState({
    runId,
    durationHours,
    snapshotIntervalMinutes: snapshotIntervalMin,
  });

  state.agents = agents.map(({ profile, agent }): AgentRecord => ({
    profileId:    profile.id,
    agentWallet:  agent.wallet,
    ownerWallet:  agent.ownerWallet,
    registeredAt: new Date(Date.now() - profile.preHistoryDays * 86400_000).toISOString(),
  }));

  await saveState(env.stateDir, state);

  console.log("");
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log(`║  Staged — runId=${runId}                                  ║`);
  console.log("║                                                              ║");
  console.log("║  Next step:                                                  ║");
  console.log("║    npm run monitor &                                         ║");
  console.log("║                                                              ║");
  console.log("║  In ~48h:                                                    ║");
  console.log("║    npm run verify                                            ║");
  console.log("║    npm run report                                            ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");
  console.log("");

  return 0;
}


main().then((code) => process.exit(code))
      .catch((err) => { console.error(err); process.exit(1); });
