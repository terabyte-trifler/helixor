// =============================================================================
// tests/config.test.ts — loadConfig validation
// =============================================================================

import { describe, expect, it } from "vitest";

import { HelixorConfigError, loadConfig } from "../src/config";
import { makeRuntime } from "./helpers";

describe("loadConfig", () => {

  it("loads with sane defaults from minimal settings", () => {
    const runtime = makeRuntime();
    const cfg = loadConfig(runtime as any);
    expect(cfg.minScore).toBe(600);
    expect(cfg.allowStale).toBe(false);
    expect(cfg.allowAnomaly).toBe(false);
    expect(cfg.refreshIntervalMs).toBe(60_000);
    expect(cfg.financialActions.length).toBeGreaterThan(0);
  });

  it("rejects missing SOLANA_PUBLIC_KEY", () => {
    const runtime = makeRuntime({ settings: { SOLANA_PUBLIC_KEY: "" } });
    expect(() => loadConfig(runtime as any)).toThrow(HelixorConfigError);
    expect(() => loadConfig(runtime as any)).toThrow(/SOLANA_PUBLIC_KEY is required/);
  });

  it("rejects invalid base58 SOLANA_PUBLIC_KEY", () => {
    const runtime = makeRuntime({ settings: { SOLANA_PUBLIC_KEY: "not-base58!" } });
    expect(() => loadConfig(runtime as any)).toThrow(/not a valid base58/);
  });

  it("rejects missing HELIXOR_API_URL — never silently default to mainnet", () => {
    const runtime = makeRuntime({ settings: { HELIXOR_API_URL: "" } });
    expect(() => loadConfig(runtime as any)).toThrow(/HELIXOR_API_URL is required/);
  });

  it("rejects HELIXOR_API_URL without scheme", () => {
    const runtime = makeRuntime({ settings: { HELIXOR_API_URL: "api.helixor.xyz" } });
    expect(() => loadConfig(runtime as any)).toThrow(/must start with http/);
  });

  it("rejects out-of-range MIN_SCORE", () => {
    const runtime = makeRuntime({ settings: { HELIXOR_MIN_SCORE: "1500" } });
    expect(() => loadConfig(runtime as any)).toThrow(/must be 0-1000/);
  });

  it("rejects refresh interval below 5s", () => {
    const runtime = makeRuntime({ settings: { HELIXOR_REFRESH_MS: "1000" } });
    expect(() => loadConfig(runtime as any)).toThrow(/must be ≥ 5000/);
  });

  it("strips trailing slashes from API URL", () => {
    const runtime = makeRuntime({ settings: { HELIXOR_API_URL: "http://api.test/////" } });
    const cfg = loadConfig(runtime as any);
    expect(cfg.apiUrl).toBe("http://api.test");
  });

  it("falls back to agentWallet when ownerWallet not set", () => {
    const runtime = makeRuntime({ settings: { HELIXOR_OWNER_WALLET: "" } });
    const cfg = loadConfig(runtime as any);
    expect(cfg.ownerWallet).toBe(cfg.agentWallet);
  });

  it("parses custom financial actions list", () => {
    const runtime = makeRuntime({
      settings: { HELIXOR_FINANCIAL_ACTIONS: "swap_x , LEND_y, BORROW_Z" },
    });
    const cfg = loadConfig(runtime as any);
    expect(cfg.financialActions).toEqual(["SWAP_X", "LEND_Y", "BORROW_Z"]);
  });

  it("HELIXOR_TELEMETRY=false disables logs", () => {
    const runtime = makeRuntime({ settings: { HELIXOR_TELEMETRY: "false" } });
    expect(loadConfig(runtime as any).enableTelemetry).toBe(false);
  });

  it("HELIXOR_TELEMETRY default = true", () => {
    const runtime = makeRuntime({ settings: { HELIXOR_TELEMETRY: "" } });
    expect(loadConfig(runtime as any).enableTelemetry).toBe(true);
  });
});
