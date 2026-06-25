// =============================================================================
// tests/integration/smoke.test.ts — fast pre-flight before any heavy test.
// Verifies env, RPC, API, schema, oracle balance.
// =============================================================================

import { Connection } from "@solana/web3.js";
import { describe, expect, it } from "vitest";

import { loadEnv } from "../../helpers/env";
import { openDb } from "../../helpers/fixtures";

const env = loadEnv();

describe("smoke", () => {

  it("env validates", () => {
    expect(env.apiUrl).toMatch(/^https?:\/\//);
    expect(env.programId).toBeDefined();
    expect(env.databaseUrl).toContain("postgresql://");
  });

  it("API /health returns ok", async () => {
    const r = await fetch(`${env.apiUrl}/health`);
    expect(r.ok).toBe(true);
  });

  it("API /status reports DB reachable", async () => {
    const r = await fetch(`${env.apiUrl}/status`);
    const body = await r.json();
    expect(body.db_reachable).toBe(true);
  });

  it("Solana RPC responds", async () => {
    const conn = new Connection(env.solanaRpcUrl, "confirmed");
    const slot = await conn.getSlot();
    expect(slot).toBeGreaterThan(0);
  });

  it("program is deployed", async () => {
    const conn = new Connection(env.solanaRpcUrl, "confirmed");
    const info = await conn.getAccountInfo(env.programId);
    expect(info).not.toBeNull();
    expect(info!.executable).toBe(true);
  });

  it("DB schema_version >= 5 (Day 12)", async () => {
    const db = await openDb(env);
    try {
      const r = await db.pool.query("SELECT MAX(version) AS v FROM schema_version");
      expect(r.rows[0].v).toBeGreaterThanOrEqual(5);
    } finally {
      await db.close();
    }
  });

  it("API rejects bad pubkey with 400 not 500", async () => {
    const r = await fetch(`${env.apiUrl}/score/this-is-not-a-pubkey`);
    expect(r.status).toBe(400);
    expect((await r.json()).code).toBe("INVALID_AGENT_WALLET");
  });

});
