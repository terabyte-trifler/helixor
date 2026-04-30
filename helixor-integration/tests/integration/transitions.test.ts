// =============================================================================
// tests/integration/transitions.test.ts — state machine transitions.
//
// Bugs hide in transitions, not steady states. Day 10 tested steady states.
// Day 13 tests: provisional → live, live → stale, score guard rail enforcement,
// algo version mismatch behavior, deactivation flow.
// =============================================================================

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { HelixorClient, HelixorError } from "@helixor/client";

import { loadEnv } from "../../helpers/env";
import {
  freshAgent, injectScore, openDb, seedRegisteredAgent,
  seedTransactions, teardownAgent, type DbHandle,
} from "../../helpers/fixtures";
import { recomputeForAgent } from "../../helpers/pipeline";


const env = loadEnv();
let db: DbHandle;
let client: HelixorClient;
const cleanups: string[] = [];

async function fetchFreshScore(wallet: string) {
  const res = await fetch(`${env.apiUrl}/score/${wallet}?force_refresh=true`);
  expect(res.ok).toBe(true);
  const body = await res.json();
  return {
    ...body,
    isFresh: body.is_fresh,
    anomalyFlag: body.anomaly_flag,
  };
}


beforeAll(async () => {
  db = await openDb(env);
  client = new HelixorClient({ apiBase: env.apiUrl, cacheTtlMs: 0 });
}, 60_000);


afterAll(async () => {
  for (const w of cleanups) await teardownAgent(db, w);
  await db.close();
});


describe("Transition: provisional → live", () => {

  it("agent goes from provisional to live after first score lands", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });

    // Provisional: registered, no agent_scores row
    const before = await client.getScore(a.wallet);
    expect(before.source).toBe("provisional");
    expect(before.score).toBe(500);

    // Add transactions and score
    await seedTransactions(db, {
      agent: a, txCount: 100, activeDays: 25, successRate: 0.92,
    });
    const r = await recomputeForAgent(env, a.wallet);
    expect(r.exitCode, `compute: ${r.stderr}`).toBe(0);

    // Inject the on-chain timestamp so isFresh works
    await db.pool.query(
      "UPDATE agent_scores SET written_onchain_at = NOW() WHERE agent_wallet = $1",
      [a.wallet],
    );

    // Now should be live
    const after = await client.getScore(a.wallet);
    expect(after.source).toBe("live");
    expect(after.isFresh).toBe(true);
    expect(after.updatedAt).toBeGreaterThan(0);
    expect(after.breakdown).not.toBeNull();
  }, 180_000);

});


describe("Transition: live → stale", () => {

  it("isFresh flips false when written_onchain_at crosses 48h", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });

    // Just under 48h — should be fresh
    const recent = new Date(Date.now() - 47 * 3600_000);
    await injectScore(db, {
      agent: a, score: 800, computedAt: recent, writtenOnchainAt: recent,
    });
    const fresh = await client.getScore(a.wallet);
    expect(fresh.isFresh).toBe(true);
    expect(fresh.source).toBe("live");

    // Push timestamp to 49h ago
    await db.pool.query(
      `UPDATE agent_scores SET
         written_onchain_at = NOW() - INTERVAL '49 hours',
         computed_at        = NOW() - INTERVAL '49 hours'
       WHERE agent_wallet = $1`,
      [a.wallet],
    );

    const stale = await fetchFreshScore(a.wallet);
    expect(stale.isFresh).toBe(false);
    expect(stale.source).toBe("stale");
    expect(stale.score).toBe(800);  // value preserved, just not fresh
  });

});


describe("Transition: requireMinScore policy boundaries", () => {

  it("score = minimum exactly: passes", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });
    await injectScore(db, { agent: a, score: 600 });

    const result = await client.requireMinScore(a.wallet, 600);
    expect(result.score).toBe(600);
  });

  it("score = minimum - 1: fails", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });
    await injectScore(db, { agent: a, score: 599 });

    await expect(client.requireMinScore(a.wallet, 600)).rejects.toThrow(HelixorError);
  });

  it("score 1000, min 1000: passes", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });
    await injectScore(db, { agent: a, score: 1000 });
    const result = await client.requireMinScore(a.wallet, 1000);
    expect(result.score).toBe(1000);
  });

  it("score 0, min 0: passes (edge of valid range)", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });
    await injectScore(db, { agent: a, score: 0 });
    const result = await client.requireMinScore(a.wallet, 0);
    expect(result.score).toBe(0);
  });

});


describe("Transition: deactivation", () => {

  it("agent marked inactive returns deactivated source", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30, active: true });
    await injectScore(db, { agent: a, score: 800 });

    // Confirm it's live
    const live = await client.getScore(a.wallet);
    expect(live.source).toBe("live");

    // Mark inactive (simulates owner calling deactivate)
    await db.pool.query(
      "UPDATE registered_agents SET active = FALSE WHERE agent_wallet = $1",
      [a.wallet],
    );

    const deact = await fetchFreshScore(a.wallet);
    expect(deact.source).toBe("deactivated");
  });

  it("deactivated agent unbypassable by requireMinScore options", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30, active: false });
    await injectScore(db, { agent: a, score: 1000 });

    await expect(
      client.requireMinScore(a.wallet, 0, {
        allowStale: true, allowAnomaly: true, allowProvisional: true,
      }),
    ).rejects.toMatchObject({ code: "AGENT_DEACTIVATED" });
  });

});


describe("Transition: anomaly flag", () => {

  it("anomaly flag persists across reads until next score", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });
    await injectScore(db, { agent: a, score: 250, anomalyFlag: true });

    // Multiple reads, all should show anomaly
    for (let i = 0; i < 3; i++) {
      const score = await client.getScore(a.wallet);
      expect(score.anomalyFlag).toBe(true);
      client.invalidate(a.wallet);
    }
  });

  it("anomaly clears when next score has no anomaly", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });
    await injectScore(db, { agent: a, score: 250, anomalyFlag: true });
    expect((await client.getScore(a.wallet)).anomalyFlag).toBe(true);

    // Replace with clean score
    await injectScore(db, { agent: a, score: 800, anomalyFlag: false });
    client.invalidate(a.wallet);
    expect((await fetchFreshScore(a.wallet)).anomalyFlag).toBe(false);
  });

});
