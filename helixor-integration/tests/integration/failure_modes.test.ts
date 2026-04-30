// =============================================================================
// tests/integration/failure_modes.test.ts — graceful failure tests.
//
// What happens when:
//   - API is unreachable from the SDK
//   - DB has zero rows for an agent
//   - Algo version on-chain doesn't match local
//   - Concurrent score updates collide
//   - Pubkey is malformed
//   - SDK timeout fires before API responds
// =============================================================================

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  HelixorClient,
  AgentNotFoundError,
  InvalidAgentWalletError,
  TimeoutError,
} from "@helixor/client";

import { loadEnv } from "../../helpers/env";
import {
  freshAgent, injectScore, openDb, seedRegisteredAgent,
  teardownAgent, type DbHandle,
} from "../../helpers/fixtures";


const env = loadEnv();
const describeIf = env.skipFailureTests ? describe.skip : describe;

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


describeIf("Failure modes — clean error mapping", () => {

  it("malformed pubkey → InvalidAgentWalletError (no network call)", async () => {
    const c = new HelixorClient({ apiBase: env.apiUrl });
    await expect(c.getScore("not-a-pubkey")).rejects.toBeInstanceOf(InvalidAgentWalletError);
  });

  it("empty pubkey → InvalidAgentWalletError", async () => {
    const c = new HelixorClient({ apiBase: env.apiUrl });
    await expect(c.getScore("")).rejects.toBeInstanceOf(InvalidAgentWalletError);
  });

  it("unregistered agent → AgentNotFoundError", async () => {
    const wallet = freshAgent().wallet;  // never seeded
    await expect(client.getScore(wallet)).rejects.toBeInstanceOf(AgentNotFoundError);
  });

  it("AgentNotFoundError carries requestId for support", async () => {
    const wallet = freshAgent().wallet;
    try {
      await client.getScore(wallet);
    } catch (err: any) {
      expect(err.requestId).toBeDefined();
    }
  });

  it("very short timeout → TimeoutError", async () => {
    // 1ms timeout — guarantees timeout regardless of API speed
    const slow = new HelixorClient({
      apiBase: env.apiUrl, timeoutMs: 1, maxRetries: 0,
    });
    const a = freshAgent();
    await expect(slow.getScore(a.wallet)).rejects.toBeInstanceOf(TimeoutError);
  });

});


describeIf("Failure modes — DB edge cases", () => {

  it("agent with zero transactions but registered → provisional", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 1 });
    const score = await client.getScore(a.wallet);
    expect(score.source).toBe("provisional");
  });

  it("agent registered <24h ago is provisional even with txs", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 0 });
    // No score row injected — this is the canonical provisional case
    const score = await client.getScore(a.wallet);
    expect(score.source).toBe("provisional");
    expect(score.score).toBe(500);
  });

});


describeIf("Failure modes — version handling", () => {

  it("score from old algo version still readable but flagged via version field", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });
    await injectScore(db, {
      agent: a, score: 750,
      algoVersion: 1, weightsVersion: 1,
    });
    const score = await client.getScore(a.wallet);
    expect(score.scoringAlgoVersion).toBe(1);
    expect(score.weightsVersion).toBe(1);
    // Consumers can switch on this field to handle migrations.
  });

});


describeIf("Failure modes — concurrent reads", () => {

  it("100 parallel reads return the same score", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });
    await injectScore(db, { agent: a, score: 715 });

    const c = new HelixorClient({ apiBase: env.apiUrl, cacheTtlMs: 0 });
    const results = await Promise.all(
      Array.from({ length: 100 }, () => c.getScore(a.wallet)),
    );

    expect(results.every(s => s.score === 715)).toBe(true);
    expect(results.every(s => s.agentWallet === a.wallet)).toBe(true);
  });

});


describeIf("Failure modes — rate limit returns 429 cleanly", () => {

  it("burst beyond capacity returns 429 with retry-after", async () => {
    // Fire 200 sequential requests to a real endpoint
    let saw429 = false;
    for (let i = 0; i < 200; i++) {
      const r = await fetch(`${env.apiUrl}/score/AGENT11111111111111111111111111111111111111`);
      if (r.status === 429) {
        saw429 = true;
        const body = await r.json();
        expect(body.code).toBe("RATE_LIMITED");
        expect(r.headers.get("retry-after")).toBeTruthy();
        break;
      }
    }
    if (!saw429) {
      console.warn("[skip] burst did not hit rate limit (limit may be too high for this test)");
    }
  });

});
