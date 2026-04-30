#!/usr/bin/env tsx
// =============================================================================
// scripts/monitor_validation.ts — runs for the duration of the validation.
//
// On each interval (default 30min):
//   1. Inject the appropriate number of transactions for each agent
//      based on their profile's success rate at the current age.
//   2. Run the scoring pipeline for each agent.
//   3. Run epoch_runner so scores reach on-chain.
//   4. Take a snapshot of every agent's score → state.snapshots.
//   5. Persist state.
//
// Designed to be resumable: if killed mid-loop, restart and it picks up
// from the last persisted state.
// =============================================================================

import { HelixorClient } from "@helixor/client";

import { loadEnv } from "../helpers/env";
import { injectTransactions, openDb, type DbHandle } from "../helpers/db";
import { recomputeForAgent, runEpochOnce } from "../helpers/pipeline";
import {
  findActiveRun, hourOffsetNow, loadState, saveState,
  type ScoreSnapshot, type ValidationState,
} from "../helpers/state";
import { profileById } from "../profiles/profiles";


function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)); }
function logicalProfileHour(ageHours: number, durationHours: number): number {
  if (durationHours <= 0) return 48;
  return Math.min(48, (ageHours / durationHours) * 48);
}


async function takeSnapshot(
  client: HelixorClient,
  state: ValidationState,
  ageHours: number,
): Promise<ScoreSnapshot[]> {
  const snapshots: ScoreSnapshot[] = [];
  for (const a of state.agents) {
    const taken = new Date().toISOString();
    try {
      const score = await client.getScore(a.agentWallet);
      snapshots.push({
        agentWallet:        a.agentWallet,
        hourOffset:         ageHours,
        score:              score.score,
        alert:              score.alert,
        source:             score.source,
        successRate:        score.successRate,
        anomalyFlag:        score.anomalyFlag,
        isFresh:            score.isFresh,
        scoringAlgoVersion: score.scoringAlgoVersion ?? null,
        takenAt:            taken,
      });
    } catch (err: any) {
      snapshots.push({
        agentWallet:        a.agentWallet,
        hourOffset:         ageHours,
        score:              null, alert: null, source: null,
        successRate:        null, anomalyFlag: null,
        isFresh:            null, scoringAlgoVersion: null,
        takenAt:            taken,
        error:              err?.message ?? String(err),
      });
    }
  }
  return snapshots;
}


async function tickInjection(
  db:    DbHandle,
  state: ValidationState,
  ageHours: number,
  profileDeltaHours: number,
): Promise<void> {
  for (const a of state.agents) {
    const profile = profileById(a.profileId);
    const validationTxsPerDay = profile.validationTxsPerDay ?? profile.txsPerDay;
    const targetCount = Math.max(1, Math.round(validationTxsPerDay * (profileDeltaHours / 24)));

    const result = await injectTransactions(db, {
      agent: { profileId: a.profileId, wallet: a.agentWallet,
               ownerWallet: a.ownerWallet, agentKp: undefined as any },
      profile,
      ageHours,
      count: targetCount,
    });

    state.injections.push({
      hourOffset: ageHours,
      agentWallet: a.agentWallet,
      count: result.injected,
      successRate: result.successRate,
      takenAt: new Date().toISOString(),
    });
  }
}


async function tickScoring(env: ReturnType<typeof loadEnv>, state: ValidationState, ageHours: number): Promise<void> {
  // Recompute baseline + score for each agent
  for (const a of state.agents) {
    const r = await recomputeForAgent(env, a.agentWallet);
    if (r.exitCode !== 0) {
      console.warn(`  ! recompute failed for ${a.profileId}: ${r.stderr.slice(-200)}`);
    }
  }

  // Run the on-chain epoch
  const epochStart = new Date().toISOString();
  const epoch = await runEpochOnce(env);
  const epochFinish = new Date().toISOString();

  state.epochs.push({
    hourOffset:      ageHours,
    startedAt:       epochStart,
    finishedAt:      epochFinish,
    exitCode:        epoch.exitCode,
    durationMs:      epoch.durationMs,
    scoresSubmitted: countSubmittedFromStdout(epoch.stdout),
  });
  if (epoch.exitCode !== 0) {
    console.warn(`  ! epoch_runner exited ${epoch.exitCode}: ${epoch.stderr.slice(-200)}`);
  }
}

async function runTick(
  env: ReturnType<typeof loadEnv>,
  db: DbHandle,
  client: HelixorClient,
  state: ValidationState,
  profileHour: number,
  profileDeltaHours: number,
): Promise<void> {
  console.log(`  • injecting txs across ${state.agents.length} agents...`);
  await tickInjection(db, state, profileHour, profileDeltaHours);

  console.log(`  • recomputing scores + running epoch_runner...`);
  await tickScoring(env, state, profileHour);

  console.log(`  • taking snapshot of all 5 agents...`);
  const snaps = await takeSnapshot(client, state, profileHour);
  state.snapshots.push(...snaps);
  for (const s of snaps) {
    const profile = state.agents.find(a => a.agentWallet === s.agentWallet)!.profileId;
    const tag = s.error ? `\x1b[31merror: ${s.error.slice(0, 40)}\x1b[0m`
      : `score=${s.score} alert=${s.alert} ${s.anomalyFlag ? "[anomaly]" : ""}`;
    console.log(`    ${profile.padEnd(11)} ${tag}`);
  }
}

function countSubmittedFromStdout(stdout: string): number {
  const matches = stdout.match(/score_submitted/g);
  return matches?.length ?? 0;
}


// =============================================================================
// Main loop
// =============================================================================

async function main(): Promise<number> {
  const env = loadEnv();

  let runId = process.env.HELIXOR_VALIDATION_RUN_ID;
  if (!runId) {
    const found = await findActiveRun(env.stateDir);
    if (!found) {
      console.error("No staged validation run found. Run `npm run stage` first.");
      return 1;
    }
    runId = found;
  }

  const intervalMs = Number(process.env.HELIXOR_VALIDATION_INTERVAL_MS ?? 1_800_000); // 30min default

  console.log("");
  console.log(`Helixor — Day 14 Validation Monitor (runId=${runId}, interval=${intervalMs/60000}min)`);
  console.log("");

  const client = new HelixorClient({ apiBase: env.apiUrl, cacheTtlMs: 0 });
  const db     = await openDb(env);

  const state = await loadState(env.stateDir, runId);
  let lastProfileHour = state.injections.length > 0
    ? Math.max(...state.injections.map(i => i.hourOffset))
    : 0;

  try {
    // Take an initial snapshot at t=0 (if not already present)
    if (state.snapshots.filter(s => s.hourOffset < 0.01).length === 0) {
      console.log(`  ▼ initial snapshot at t=0`);
      const snaps = await takeSnapshot(client, state, 0);
      state.snapshots.push(...snaps);
      await saveState(env.stateDir, state);
    }

    // Loop until duration elapses
    for (;;) {
      const ageHours = hourOffsetNow(state);
      if (ageHours >= state.durationHours) {
        if (lastProfileHour < 48) {
          const finalProfileHour = 48;
          const finalDeltaHours = Math.max(0.01, finalProfileHour - lastProfileHour);
          console.log(`\n[ final catch-up → ${finalProfileHour.toFixed(2)}h profile ] tick`);
          await runTick(env, db, client, state, finalProfileHour, finalDeltaHours);
          await saveState(env.stateDir, state);
          lastProfileHour = finalProfileHour;
        }
        console.log(`  ✓ duration reached (${state.durationHours}h) — exiting monitor`);
        state.finishedAt = new Date().toISOString();
        await saveState(env.stateDir, state);
        break;
      }
      const profileHour = logicalProfileHour(ageHours, state.durationHours);
      const profileDeltaHours = Math.max(0.01, profileHour - lastProfileHour);

      console.log(`\n[ t=${ageHours.toFixed(2)}h real / ${profileHour.toFixed(2)}h profile ] tick`);
      await runTick(env, db, client, state, profileHour, profileDeltaHours);

      // 4. Persist
      await saveState(env.stateDir, state);
      lastProfileHour = profileHour;

      // 5. Sleep until next interval
      await sleep(intervalMs);
    }

  } finally {
    await db.close();
  }

  console.log("");
  console.log(`✓ Monitor finished. Run \`npm run verify\` to compute PASS/FAIL.`);
  return 0;
}


main().then(c => process.exit(c)).catch((err) => { console.error(err); process.exit(1); });
