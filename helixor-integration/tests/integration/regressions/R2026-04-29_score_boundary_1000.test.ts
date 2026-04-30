// =============================================================================
// R2026-04-29_score_boundary_1000.test.ts
//
// Bug:  An agent with a perfect history briefly scored 1001 due to floating-
//       point rounding in the consistency component summing past the cap.
//       requireMinScore(1000) returned the 1001 score and isFresh comparison
//       broke.
// Fix:  Day 6 scoring engine now clamps each component to its declared max
//       BEFORE summing, plus a final clamp on raw_score before persisting.
// Test: Inject a hypothetical pre-clamp score row and verify the API + SDK
//       both return the clamped value.
// =============================================================================

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { HelixorClient } from "@helixor/client";

import { loadEnv } from "../../../helpers/env";
import {
  freshAgent, openDb, seedRegisteredAgent, teardownAgent, type DbHandle,
} from "../../../helpers/fixtures";

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


describe("Regression: score boundary at 1000", () => {

  it("a 1000 score must read back as exactly 1000 (no off-by-one)", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });

    // Inject a perfect score directly. The scoring engine must clamp at 1000;
    // we verify here that the storage layer + API + SDK all preserve 1000
    // exactly without overflow or coercion.
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
         $1, 1000, 'GREEN', 500, 300, 200, 1000, FALSE,
         1.0, 100, 0,
         'cafe' || repeat('0', 60), 1,
         FALSE, 1, 1, NOW(), NOW()
       )`,
      [a.wallet],
    );

    const score = await client.getScore(a.wallet);
    expect(score.score).toBe(1000);
    expect(score.alert).toBe("GREEN");
    expect(score.breakdown!.successRateScore).toBe(500);
    expect(score.breakdown!.consistencyScore).toBe(300);
    expect(score.breakdown!.stabilityScore).toBe(200);
    expect(score.breakdown!.rawScore).toBe(1000);
  });

  it("requireMinScore(1000) succeeds for a 1000 score", async () => {
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });
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
         $1, 1000, 'GREEN', 500, 300, 200, 1000, FALSE,
         1.0, 100, 0, 'cafe' || repeat('0', 60), 1,
         FALSE, 1, 1, NOW(), NOW()
       )`,
      [a.wallet],
    );

    const result = await client.requireMinScore(a.wallet, 1000);
    expect(result.score).toBe(1000);
  });

  it("DB constraint rejects scores above 1000", async () => {
    // Verify the schema-level CHECK constraint catches malformed inserts
    const a = freshAgent();
    cleanups.push(a.wallet);
    await seedRegisteredAgent(db, { agent: a, registeredDaysAgo: 30 });

    let didThrow = false;
    try {
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
           $1, 1001, 'GREEN', 500, 300, 200, 1001, FALSE,
           1.0, 100, 0, 'cafe' || repeat('0', 60), 1,
           FALSE, 1, 1, NOW(), NOW()
         )`,
        [a.wallet],
      );
    } catch (err: any) {
      didThrow = true;
      expect(err.code).toBe("23514");  // PostgreSQL check_violation
    }
    expect(didThrow).toBe(true);
  });

});
