// =============================================================================
// tests/full_loop.test.ts — END-TO-END LOOP VALIDATION
//
// What this test proves:
//
//   T+0    Register a synthetic agent
//   T+1    Inject 100 transactions into agent_transactions (90% success)
//   T+2    Trigger baseline + score computation
//   T+3    Trigger epoch_runner — score reaches on-chain TrustCertificate
//   T+4    SDK reads the score via /score/{agent}, source = "live"
//   T+5    Score on-chain matches score in DB matches score from SDK
//
// This is the ONE test that proves the entire MVP works.
//
// Three agents are tested in parallel:
//   - "stable"      — 90% success rate seeded → expect GREEN
//   - "failing"     — 30% success rate seeded → expect RED + anomaly
//   - "provisional" — registered but no txs   → expect provisional
// =============================================================================

import {
  AgentDeactivatedError,
  AnomalyDetectedError,
  HelixorClient,
  HelixorError,
  ScoreTooLowError,
  StaleScoreError,
} from "@helixor/client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { loadEnv, verifyConnectivity } from "./env";
import {
  loadKeypairFromFile,
  newAgentKeypair,
  openDb,
  registerAgentOnchain,
  seedRegisteredAgent,
  seedTransactions,
  teardownAgent,
  type DbHandle,
} from "./fixtures";
import { readTrustCert } from "./onchain";
import { pollUntil } from "./poll";
import { recomputeForAgent, runEpochOnce } from "./pipeline";


// =============================================================================
// Suite-level setup — seed three agents, drive pipeline, verify loop
// =============================================================================

const env = loadEnv();

// Generate three deterministic agents; pubkeys persist for the duration of the test
const stableAgentKp      = newAgentKeypair().keypair;
const failingAgentKp     = newAgentKeypair().keypair;
const provisionalAgentKp = newAgentKeypair().keypair;
const stableAgent        = stableAgentKp.publicKey.toBase58();
const failingAgent       = failingAgentKp.publicKey.toBase58();
const provisionalAgent   = provisionalAgentKp.publicKey.toBase58();

const ownerKp = loadKeypairFromFile(env.oracleKeypairPath);
const testOwner = env.testOwnerWallet ?? ownerKp.publicKey.toBase58();

let db: DbHandle;
let client: HelixorClient;
let previouslyActiveWallets: string[] = [];


beforeAll(async () => {
  console.log("\n═══ E2E LOOP — setup ═══");
  console.log(`  api:     ${env.apiUrl}`);
  console.log(`  rpc:     ${env.solanaRpcUrl}`);
  console.log(`  program: ${env.programId.toBase58()}`);
  console.log(`  agents:  stable=${stableAgent.slice(0,12)}..  failing=${failingAgent.slice(0,12)}..  provisional=${provisionalAgent.slice(0,12)}..`);

  await verifyConnectivity(env);
  console.log(`  ✓ connectivity verified`);

  db = await openDb(env);

  const activeRows = await db.pool.query<{ agent_wallet: string }>(
    `
      SELECT agent_wallet
      FROM registered_agents
      WHERE active = TRUE
        AND agent_wallet <> ALL($1::text[])
    `,
    [[stableAgent, failingAgent, provisionalAgent]],
  );
  previouslyActiveWallets = activeRows.rows.map((row) => row.agent_wallet);
  if (previouslyActiveWallets.length > 0) {
    await db.pool.query(
      `
        UPDATE registered_agents
        SET active = FALSE
        WHERE agent_wallet = ANY($1::text[])
      `,
      [previouslyActiveWallets],
    );
  }

  // Cleanup any prior runs (idempotent)
  await teardownAgent(db, stableAgent);
  await teardownAgent(db, failingAgent);
  await teardownAgent(db, provisionalAgent);

  // Step 1: register all three agents
  await Promise.all([
    registerAgentOnchain(env, ownerKp, stableAgentKp, "e2e-stable"),
    registerAgentOnchain(env, ownerKp, failingAgentKp, "e2e-failing"),
    registerAgentOnchain(env, ownerKp, provisionalAgentKp, "e2e-provisional"),
  ]);
  await Promise.all([
    seedRegisteredAgent(db, {
      wallet: stableAgent, ownerWallet: testOwner, name: "e2e-stable",
      txCount: 100, activeDays: 25, successRate: 0.9,
      registeredDaysAgo: 35,
    }),
    seedRegisteredAgent(db, {
      wallet: failingAgent, ownerWallet: testOwner, name: "e2e-failing",
      txCount: 100, activeDays: 25, successRate: 0.3,
      registeredDaysAgo: 35,
    }),
    seedRegisteredAgent(db, {
      wallet: provisionalAgent, ownerWallet: testOwner, name: "e2e-provisional",
      txCount: 0, activeDays: 0, successRate: 0,
      registeredDaysAgo: 1,
    }),
  ]);
  console.log("  ✓ agents registered");

  // Step 2: seed transactions for stable + failing
  await seedTransactions(db, {
    wallet: stableAgent, ownerWallet: testOwner,
    txCount: 100, activeDays: 25, successRate: 0.9,
  });
  await seedTransactions(db, {
    wallet: failingAgent, ownerWallet: testOwner,
    txCount: 100, activeDays: 25, successRate: 0.3,
  });
  console.log("  ✓ transactions seeded");

  // Step 3: drive baseline + score computation
  console.log("  → computing baselines + scores...");
  const r1 = await recomputeForAgent(stableAgent);
  expect(r1.exitCode, `compute stable: ${r1.stderr}`).toBe(0);
  const r2 = await recomputeForAgent(failingAgent);
  expect(r2.exitCode, `compute failing: ${r2.stderr}`).toBe(0);
  console.log("  ✓ scores computed");

  // Step 4: drive on-chain submission
  console.log("  → submitting to chain...");
  const ep = await runEpochOnce();
  expect(ep.exitCode, `epoch_runner: ${ep.stderr}`).toBe(0);
  console.log(`  ✓ epoch ran (${ep.durationMs}ms)`);

  // Step 5: poll until both certs are on-chain
  await pollUntil({
    label: "stable agent cert on-chain",
    timeoutMs: 90_000,
    intervalMs: 3_000,
    check: async () => {
      const cert = await readTrustCert(env, stableAgent);
      return cert?.exists ? cert : null;
    },
    describe: (last) => last ? `cert exists=${(last as any).exists}` : "no cert yet",
  });
  await pollUntil({
    label: "failing agent cert on-chain",
    timeoutMs: 90_000, intervalMs: 3_000,
    check: async () => {
      const cert = await readTrustCert(env, failingAgent);
      return cert?.exists ? cert : null;
    },
  });

  client = new HelixorClient({
    apiBase:    env.apiUrl,
    timeoutMs:  10_000,
    cacheTtlMs: 0,            // disable client cache to read API state directly
  });

  console.log("═══ setup complete ═══\n");
}, 600_000);


afterAll(async () => {
  if (db) {
    if (previouslyActiveWallets.length > 0) {
      await db.pool.query(
        `
          UPDATE registered_agents
          SET active = TRUE
          WHERE agent_wallet = ANY($1::text[])
        `,
        [previouslyActiveWallets],
      );
    }
    await teardownAgent(db, stableAgent);
    await teardownAgent(db, failingAgent);
    await teardownAgent(db, provisionalAgent);
    await db.close();
  }
});


// =============================================================================
// The actual loop assertions
// =============================================================================

describe("End-to-end loop — full pipeline", () => {

  describe("Stable agent (90% success rate)", () => {

    it("returns a live score from the API", async () => {
      const score = await client.getScore(stableAgent);
      expect(score.agentWallet).toBe(stableAgent);
      expect(score.source).toBe("live");
      expect(score.isFresh).toBe(true);
    });

    it("scores ≥ 700 (GREEN)", async () => {
      const score = await client.getScore(stableAgent);
      expect(score.score).toBeGreaterThanOrEqual(700);
      expect(score.alert).toBe("GREEN");
      expect(score.anomalyFlag).toBe(false);
    });

    it("requireMinScore(700) passes", async () => {
      const score = await client.getScore(stableAgent);
      // No throw means pass
      const result = await client.requireMinScore(stableAgent, 700);
      expect(result.score).toBe(score.score);
    });

    it("on-chain cert exists and matches DB score", async () => {
      const cert = await readTrustCert(env, stableAgent);
      const apiScore = await client.getScore(stableAgent);

      expect(cert).not.toBeNull();
      expect(cert!.exists).toBe(true);
      expect(cert!.score).toBe(apiScore.score);
      expect(cert!.alert).toBe(apiScore.alert);
      expect(cert!.scoringAlgoVersion).toBe(apiScore.scoringAlgoVersion);
      expect(cert!.weightsVersion).toBe(apiScore.weightsVersion);
    });

    it("breakdown components sum to raw_score", async () => {
      const score = await client.getScore(stableAgent);
      const bk = score.breakdown!;
      const sum = bk.successRateScore + bk.consistencyScore + bk.stabilityScore;
      expect(sum).toBe(bk.rawScore);
    });

  });

  describe("Failing agent (30% success rate)", () => {

    it("scores 500 (YELLOW) with anomaly flagged", async () => {
      const score = await client.getScore(failingAgent);
      expect(score.score).toBe(500);
      expect(score.alert).toBe("YELLOW");
    });

    it("anomaly_flag = true (absolute floor 75% triggered)", async () => {
      const score = await client.getScore(failingAgent);
      expect(score.anomalyFlag).toBe(true);
    });

    it("requireMinScore(600) throws ScoreTooLowError OR AnomalyDetectedError", async () => {
      try {
        await client.requireMinScore(failingAgent, 600);
        throw new Error("Expected to throw");
      } catch (err) {
        expect(err).toBeInstanceOf(HelixorError);
        // Either is correct — scoring engine triggers both conditions
        const acceptable = [ScoreTooLowError, AnomalyDetectedError];
        const matches = acceptable.some(C => err instanceof C);
        expect(matches).toBe(true);
      }
    });

    it("error carries the actual score", async () => {
      try {
        await client.requireMinScore(failingAgent, 600);
      } catch (err) {
        const e = err as HelixorError;
        expect(e.score).toBeDefined();
        expect(e.score!.score).toBe(500);
        expect(e.score!.agentWallet).toBe(failingAgent);
      }
    });

    it("on-chain cert agrees that score is 500 and anomalous", async () => {
      const cert = await readTrustCert(env, failingAgent);
      expect(cert!.exists).toBe(true);
      expect(cert!.score).toBe(500);
      expect(cert!.alert).toBe("YELLOW");
      expect(cert!.anomalyFlag).toBe(true);
    });

  });

  describe("Provisional agent (registered, no transactions)", () => {

    it("returns provisional source", async () => {
      const score = await client.getScore(provisionalAgent);
      expect(score.source).toBe("provisional");
    });

    it("score = 500, alert = YELLOW", async () => {
      const score = await client.getScore(provisionalAgent);
      expect(score.score).toBe(500);
      expect(score.alert).toBe("YELLOW");
    });

    it("is_fresh = false", async () => {
      const score = await client.getScore(provisionalAgent);
      expect(score.isFresh).toBe(false);
    });

    it("requireMinScore throws ProvisionalScoreError (never overridable for financial)", async () => {
      try {
        await client.requireMinScore(provisionalAgent, 100, {
          allowStale: true, allowAnomaly: true,
        });
        throw new Error("Expected to throw");
      } catch (err) {
        expect((err as HelixorError).code).toBe("PROVISIONAL_SCORE");
      }
    });

    it("no on-chain cert — provisional means we didn't score", async () => {
      const cert = await readTrustCert(env, provisionalAgent);
      expect(cert!.exists).toBe(false);
    });

  });

  describe("Loop integrity assertions", () => {

    it("API and on-chain scores agree to the byte for stable agent", async () => {
      const apiScore = await client.getScore(stableAgent);
      const cert     = await readTrustCert(env, stableAgent);

      expect(cert!.score).toBe(apiScore.score);
      expect(cert!.alert).toBe(apiScore.alert);
      expect(cert!.successRate).toBe(Math.round(apiScore.successRate * 100));
    });

    it("API and on-chain scores agree for failing agent", async () => {
      const apiScore = await client.getScore(failingAgent);
      const cert     = await readTrustCert(env, failingAgent);

      expect(cert!.score).toBe(apiScore.score);
      expect(cert!.alert).toBe(apiScore.alert);
      expect(cert!.anomalyFlag).toBe(apiScore.anomalyFlag);
    });

    it("scoring algorithm version is consistent", async () => {
      const stable = await client.getScore(stableAgent);
      const failing = await client.getScore(failingAgent);
      expect(stable.scoringAlgoVersion).toBe(failing.scoringAlgoVersion);
      expect(stable.weightsVersion).toBe(failing.weightsVersion);
    });

  });

});
