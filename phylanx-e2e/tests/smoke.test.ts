// =============================================================================
// tests/smoke.test.ts — fast smoke tests.
//
// Run before full_loop to verify the environment is sane. If smoke fails,
// don't bother with the slow loop test.
// =============================================================================

import { Connection } from "@solana/web3.js";
import { describe, expect, it } from "vitest";

import { loadEnv } from "./env";

const env = loadEnv();

describe("smoke", () => {

  it("env validates without throwing", () => {
    expect(env.apiUrl).toMatch(/^https?:\/\//);
    expect(env.programId).toBeDefined();
    expect(env.databaseUrl).toContain("postgresql://");
  });

  it("API /health returns ok", async () => {
    const r = await fetch(`${env.apiUrl}/health`);
    expect(r.ok).toBe(true);
    const body = await r.json();
    expect(body.status).toBe("ok");
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

  it("health-oracle program is deployed", async () => {
    const conn = new Connection(env.solanaRpcUrl, "confirmed");
    const info = await conn.getAccountInfo(env.programId);
    expect(info).not.toBeNull();
    expect(info!.executable).toBe(true);
  });

  it("API rejects bad pubkey with 400, not 500", async () => {
    const r = await fetch(`${env.apiUrl}/score/this-is-not-a-pubkey`);
    expect(r.status).toBe(400);
    const body = await r.json();
    expect(body.code).toBe("INVALID_AGENT_WALLET");
    expect(body.request_id).toBeDefined();
  });

  it("API returns 404 for unknown agent", async () => {
    const r = await fetch(`${env.apiUrl}/score/AGENT11111111111111111111111111111111111111`);
    expect(r.status).toBe(404);
    const body = await r.json();
    expect(body.code).toBe("AGENT_NOT_FOUND");
  });

  it("OpenAPI docs are served", async () => {
    const r = await fetch(`${env.apiUrl}/docs`);
    expect(r.status).toBe(200);
  });

});
