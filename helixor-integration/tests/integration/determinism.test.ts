// =============================================================================
// tests/integration/determinism.test.ts — reproducibility properties.
//
// Critical: scores must be deterministic. If two oracle nodes disagree on
// the same baseline + window, we have a fork. These tests catch that.
// =============================================================================

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { HelixorClient } from "@helixor/client";

import { loadEnv } from "../../helpers/env";
import {
  freshAgent, openDb, seedRegisteredAgent, seedTransactions,
  teardownAgent, type DbHandle,
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


describe("Determinism — scoring", () => {

  it("recomputing same agent twice produces identical breakdown", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });
    await seedTransactions(db, {
      agent: a, txCount: 80, activeDays: 20, successRate: 0.85,
    });

    const r1 = await recomputeForAgent(env, a.wallet);
    expect(r1.exitCode).toBe(0);
    const score1 = await client.getScore(a.wallet);

    // Run AGAIN with no input changes
    const r2 = await recomputeForAgent(env, a.wallet);
    expect(r2.exitCode).toBe(0);
    const score2 = await client.getScore(a.wallet);

    expect(score2.score).toBe(score1.score);
    expect(score2.successRate).toBe(score1.successRate);
    expect(score2.breakdown!.successRateScore).toBe(score1.breakdown!.successRateScore);
    expect(score2.breakdown!.consistencyScore).toBe(score1.breakdown!.consistencyScore);
    expect(score2.breakdown!.stabilityScore).toBe(score1.breakdown!.stabilityScore);
    expect(score2.breakdown!.rawScore).toBe(score1.breakdown!.rawScore);
  }, 240_000);

  it("baseline_hash from same data is identical across runs", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });
    await seedTransactions(db, {
      agent: a, txCount: 60, activeDays: 20, successRate: 0.9,
    });

    await recomputeForAgent(env, a.wallet);
    const r1 = await db.pool.query(
      "SELECT baseline_hash FROM agent_baselines WHERE agent_wallet = $1",
      [a.wallet],
    );
    const hash1 = r1.rows[0]?.baseline_hash;

    await recomputeForAgent(env, a.wallet);
    const r2 = await db.pool.query(
      "SELECT baseline_hash FROM agent_baselines WHERE agent_wallet = $1",
      [a.wallet],
    );
    const hash2 = r2.rows[0]?.baseline_hash;

    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^[0-9a-f]{64}$/);   // SHA-256 hex
  }, 240_000);

  it("two agents with same data shape produce same score", async () => {
    // Identical TX patterns → identical scores. Demonstrates we don't
    // accidentally factor agent_wallet into scoring.
    const a1 = freshAgent();
    const a2 = freshAgent();
    cleanups.push(a1.wallet, a2.wallet);
    const seedDate = new Date(Date.now() - 7 * 86400_000);
    await seedRegisteredAgent(db, { agent: a1, registeredDaysAgo: 30 });
    await seedRegisteredAgent(db, { agent: a2, registeredDaysAgo: 30 });

    // Manually inject IDENTICAL transactions to both
    const txs = Array.from({ length: 50 }, (_, i) => ({
      blockTime: new Date(seedDate.getTime() + i * 3600_000),
      success:   i % 4 !== 0,   // 75% success
      solChange: 1000 * (i % 7 - 3),
    }));

    for (const a of [a1, a2]) {
      const c = await db.pool.connect();
      try {
        await c.query("BEGIN");
        for (let i = 0; i < txs.length; i++) {
          const tx = txs[i]!;
          await c.query(
            `INSERT INTO agent_transactions
              (agent_wallet, tx_signature, slot, block_time, success,
               program_ids, sol_change, fee, raw_meta, source)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 5000, '{}'::jsonb, 'e2e_seed')
             ON CONFLICT (tx_signature) DO NOTHING`,
            [
              a.wallet,
              `DET_${a.wallet.slice(0, 8)}_${i.toString().padStart(6, "0")}`.padEnd(88, "x"),
              200_000_000 + i,
              tx.blockTime, tx.success,
              ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
              tx.solChange,
            ],
          );
        }
        await c.query("COMMIT");
      } catch (e) {
        await c.query("ROLLBACK");
        throw e;
      } finally {
        c.release();
      }
    }

    const r1 = await recomputeForAgent(env, a1.wallet);
    const r2 = await recomputeForAgent(env, a2.wallet);
    expect(r1.exitCode).toBe(0);
    expect(r2.exitCode).toBe(0);

    const s1 = await client.getScore(a1.wallet);
    const s2 = await client.getScore(a2.wallet);

    expect(s2.score).toBe(s1.score);
    expect(s2.alert).toBe(s1.alert);
    expect(s2.successRate).toBe(s1.successRate);
    expect(s2.breakdown!.rawScore).toBe(s1.breakdown!.rawScore);
  }, 360_000);

});


describe("Determinism — API responses are stable", () => {

  it("five sequential reads return identical JSON (sans served_at, request id)", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });
    // Inject score directly
    await db.pool.query(
      `INSERT INTO agent_scores (
         agent_wallet, score, alert,
         success_rate_score, consistency_score, stability_score,
         raw_score, guard_rail_applied,
         window_success_rate, window_tx_count, window_sol_volatility,
         baseline_hash, baseline_algo_version,
         anomaly_flag, scoring_algo_version, weights_version,
         computed_at, written_onchain_at
       ) VALUES (
         $1, 720, 'GREEN', 400, 220, 100, 720, FALSE,
         0.92, 60, 1500000,
         'cafe' || repeat('0', 60), 1,
         FALSE, 1, 1, NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 hour'
       )
       ON CONFLICT (agent_wallet) DO UPDATE SET
         score = EXCLUDED.score, alert = EXCLUDED.alert,
         computed_at = EXCLUDED.computed_at,
         written_onchain_at = EXCLUDED.written_onchain_at`,
      [a.wallet],
    );

    // Use a dedicated forwarded IP so this test does not inherit the suite's
    // shared rate-limit bucket while still exercising the live API path.
    const forwardedFor = `198.51.100.${Math.floor(Math.random() * 200) + 1}`;
    const responses = [];
    for (let i = 0; i < 5; i++) {
      const res = await fetch(
        `${env.apiUrl}/score/${a.wallet}?force_refresh=true`,
        { headers: { "x-forwarded-for": forwardedFor } },
      );
      expect(res.ok).toBe(true);
      const r = await res.json();
      // Strip volatile fields
      const { served_at, request_id, cached, ...stable } = r;
      void served_at;
      void request_id;
      void cached;
      responses.push(JSON.stringify(stable));
    }
    expect(new Set(responses).size).toBe(1);
  });

});
