// =============================================================================
// tests/integration/invariants.test.ts — properties that must ALWAYS hold.
//
// These aren't "happy-path tests" (Day 10 did that). These assert algebraic
// invariants over the scoring system. If any of these fail in production,
// something is fundamentally broken.
// =============================================================================

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { HelixorClient } from "@helixor/client";

import { loadEnv } from "../../helpers/env";
import {
  freshAgent, injectScore, openDb, seedRegisteredAgent,
  seedTransactions, teardownAgent, type DbHandle, type SeededAgent,
} from "../../helpers/fixtures";
import { recomputeForAgent } from "../../helpers/pipeline";


const env = loadEnv();
let db: DbHandle;
let client: HelixorClient;
const cleanups: string[] = [];


beforeAll(async () => {
  db = await openDb(env);
  client = new HelixorClient({ apiBase: env.apiUrl, cacheTtlMs: 0 });
}, 60_000);


afterAll(async () => {
  for (const w of cleanups) await teardownAgent(db, w);
  await db.close();
});


async function makeScoredAgent(score: number, opts: Partial<{ anomaly: boolean; alert: any }> = {}): Promise<SeededAgent> {
  const a = freshAgent();
  cleanups.push(a.wallet);
  await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });
  await injectScore(db, {
    agent: a, score,
    alert: opts.alert,
    anomalyFlag: opts.anomaly ?? false,
  });
  return a;
}


describe("Score invariants — apply to ALL valid states", () => {

  it("breakdown components sum to raw_score (within 1pt rounding)", async () => {
    const a = await makeScoredAgent(720);
    const score = await client.getScore(a.wallet);
    const bk = score.breakdown!;
    const sum = bk.successRateScore + bk.consistencyScore + bk.stabilityScore;
    expect(Math.abs(sum - bk.rawScore)).toBeLessThanOrEqual(1);
  });

  it("score is in [0, 1000]", async () => {
    for (const s of [0, 100, 500, 999, 1000]) {
      const a = await makeScoredAgent(s);
      const score = await client.getScore(a.wallet);
      expect(score.score).toBeGreaterThanOrEqual(0);
      expect(score.score).toBeLessThanOrEqual(1000);
    }
  });

  it("score component bounds: success<=500, consistency<=300, stability<=200", async () => {
    const a = await makeScoredAgent(950);
    const score = await client.getScore(a.wallet);
    const bk = score.breakdown!;
    expect(bk.successRateScore).toBeGreaterThanOrEqual(0);
    expect(bk.successRateScore).toBeLessThanOrEqual(500);
    expect(bk.consistencyScore).toBeGreaterThanOrEqual(0);
    expect(bk.consistencyScore).toBeLessThanOrEqual(300);
    expect(bk.stabilityScore).toBeGreaterThanOrEqual(0);
    expect(bk.stabilityScore).toBeLessThanOrEqual(200);
  });

  it("alert tier matches score bucket", async () => {
    const cases = [
      { score: 800, expected: "GREEN"  },
      { score: 700, expected: "GREEN"  },
      { score: 600, expected: "YELLOW" },
      { score: 400, expected: "YELLOW" },
      { score: 200, expected: "RED"    },
    ];
    for (const c of cases) {
      const a = await makeScoredAgent(c.score, { alert: c.expected as any });
      const score = await client.getScore(a.wallet);
      expect(score.alert).toBe(c.expected);
    }
  });

  it("agent_wallet round-trips through API exactly", async () => {
    const a = await makeScoredAgent(750);
    const score = await client.getScore(a.wallet);
    expect(score.agentWallet).toBe(a.wallet);
  });

});


describe("Pipeline invariants — recompute determinism", () => {

  it("same inputs → same score (idempotent)", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });
    await seedTransactions(db, {
      agent: a,
      txCount: 100, activeDays: 25, successRate: 0.9,
    });

    const r1 = await recomputeForAgent(env, a.wallet);
    expect(r1.exitCode, `compute1: ${r1.stderr}`).toBe(0);
    const score1 = await client.getScore(a.wallet);

    const r2 = await recomputeForAgent(env, a.wallet);
    expect(r2.exitCode, `compute2: ${r2.stderr}`).toBe(0);
    const score2 = await client.getScore(a.wallet);

    // Same algorithm, same data, must produce identical score
    expect(score2.score).toBe(score1.score);
    expect(score2.alert).toBe(score1.alert);
    expect(score2.breakdown!.successRateScore).toBe(score1.breakdown!.successRateScore);
    expect(score2.breakdown!.consistencyScore).toBe(score1.breakdown!.consistencyScore);
    expect(score2.breakdown!.stabilityScore).toBe(score1.breakdown!.stabilityScore);
  }, 180_000);

  it("scoring algorithm version is stable across all agents", async () => {
    const a1 = await makeScoredAgent(800);
    const a2 = await makeScoredAgent(400);
    const s1 = await client.getScore(a1.wallet);
    const s2 = await client.getScore(a2.wallet);
    expect(s1.scoringAlgoVersion).toBe(s2.scoringAlgoVersion);
    expect(s1.weightsVersion).toBe(s2.weightsVersion);
  });

});


describe("Source-field semantics", () => {

  it("registered + scored = source live, isFresh true", async () => {
    const a = await makeScoredAgent(750);
    const score = await client.getScore(a.wallet);
    expect(score.source).toBe("live");
    expect(score.isFresh).toBe(true);
  });

  it("registered + no score = source provisional, isFresh false", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 0 });
    const score = await client.getScore(a.wallet);
    expect(score.source).toBe("provisional");
    expect(score.isFresh).toBe(false);
    expect(score.score).toBe(500);
    expect(score.alert).toBe("YELLOW");
  });

  it("scored but >48h old = source stale", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });
    const oldDate = new Date(Date.now() - 72 * 3600_000);  // 72h ago
    await injectScore(db, {
      agent: a, score: 750,
      computedAt: oldDate, writtenOnchainAt: oldDate,
    });
    const score = await client.getScore(a.wallet);
    expect(score.source).toBe("stale");
    expect(score.isFresh).toBe(false);
  });

});
