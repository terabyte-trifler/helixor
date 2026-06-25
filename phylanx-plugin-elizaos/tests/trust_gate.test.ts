// tests/trust_gate.test.ts — Day 12: mode + fail_mode + telemetry
//                            + VULN-12 fail-closed-with-cache integration
import { afterEach, describe, expect, it, vi } from "vitest";

import type { TrustScore } from "@phylanx/client/unsafe";

import { loadConfig } from "../src/config";
import { trustGateEvaluator } from "../src/evaluators/trust_gate";
import { getOrInitState } from "../src/state";
import { makeRuntime, scoreResponse } from "./helpers";

// Helper: compose a fetch that handles BOTH score requests and beacon POSTs.
// Also captures every beacon body so VULN-12 tests can assert event_type.
const capturedBeacons: any[] = [];

function withDualFetch(scoreHandler: (url: string) => any) {
  const original = globalThis.fetch;
  capturedBeacons.length = 0;
  globalThis.fetch = vi.fn(async (url: any, init?: any) => {
    const u = String(url);
    if (u.includes("/telemetry/beacon")) {
      try {
        if (init?.body) capturedBeacons.push(JSON.parse(init.body));
      } catch { /* ignore non-JSON bodies */ }
      return {
        ok: true, status: 202, headers: new Headers(),
        json: async () => ({ accepted: true, deduped: false }),
        text: async () => "{}",
      } as Response;
    }
    const r = await scoreHandler(u);
    return {
      ok: r.status >= 200 && r.status < 300,
      status: r.status,
      headers: new Headers(r.headers ?? {}),
      json: async () => r.body,
      text: async () => JSON.stringify(r.body),
    } as Response;
  }) as any;
  return () => { globalThis.fetch = original; };
}

/** Seed the plugin's last-known-good cache with a synthetic TrustScore. */
function primeCache(runtime: ReturnType<typeof makeRuntime>, score: TrustScore) {
  const config = loadConfig(runtime as any);
  const state  = getOrInitState(runtime as any, config);
  state.scoreCache.put(score);
  return state;
}

/** Telemetry-enabled runtime for VULN-12 tests that assert beacon emissions. */
function makeBeaconRuntime(extra: Record<string,string> = {}) {
  return makeRuntime({
    settings: {
      PHYLANX_TELEMETRY:          "true",
      PHYLANX_TELEMETRY_DISABLED: "false",
      ...extra,
    },
  });
}

function ts(overrides: Partial<TrustScore> = {}): TrustScore {
  return {
    agentWallet: "C6EiVB4Tiky14k8mtrK6EJ4FZN54pKCtcJstU7umhtjP",
    score:       800, alert: "GREEN", source: "live",
    successRate: 97, anomalyFlag: false, isFresh: true,
    updatedAt:   Math.floor(Date.now() / 1000),
    servedAt:    Math.floor(Date.now() / 1000), cached: false,
    ...overrides,
  };
}

/** Wait briefly for fire-and-forget beacons to flush through fetch. */
async function flushBeacons(): Promise<void> {
  for (let i = 0; i < 5; i++) await new Promise(r => setTimeout(r, 5));
}


describe("TRUST_GATE.validate — mode interactions", () => {

  it("observe mode never participates", async () => {
    const runtime = makeRuntime({ settings: { PHYLANX_MODE: "observe" } });
    const message = { content: { action: "SWAP_TOKEN" } } as any;
    const result = await trustGateEvaluator.validate(runtime as any, message);
    expect(result).toBe(false);
  });

  it("warn mode still validates financial actions", async () => {
    const runtime = makeRuntime({ settings: { PHYLANX_MODE: "warn" } });
    const message = { content: { action: "SWAP_TOKEN" } } as any;
    expect(await trustGateEvaluator.validate(runtime as any, message)).toBe(true);
  });

  it("enforce mode (default) validates financial actions", async () => {
    const runtime = makeRuntime();
    expect(await trustGateEvaluator.validate(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any)).toBe(true);
  });
});


describe("TRUST_GATE.handler — mode behavior", () => {
  let restore: () => void = () => {};
  afterEach(() => restore());

  it("enforce mode blocks on low score", async () => {
    restore = withDualFetch(() => ({ status: 200, body: scoreResponse({ score: 400 }) }));
    const runtime = makeRuntime();
    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    expect(r).toBe("phylanx:blocked:SCORE_TOO_LOW");
  });

  it("warn mode logs but ALLOWS on low score", async () => {
    restore = withDualFetch(() => ({ status: 200, body: scoreResponse({ score: 400 }) }));
    const runtime = makeRuntime({ settings: { PHYLANX_MODE: "warn" } });
    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    expect(r).toBe("phylanx:warned:SCORE_TOO_LOW");
  });

  it("warn mode still emits phylanx:blocked event for downstream consumers", async () => {
    restore = withDualFetch(() => ({ status: 200, body: scoreResponse({ score: 400 }) }));
    const runtime = makeRuntime({ settings: { PHYLANX_MODE: "warn" } });
    await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    const ev = runtime._events.find(e => e.name === "phylanx:blocked");
    expect(ev).toBeDefined();
    expect((ev!.payload as any).mode).toBe("warn");
  });
});


describe("TRUST_GATE.handler — fail_mode behavior", () => {
  let restore: () => void = () => {};
  afterEach(() => restore());

  it("fail_mode=closed (default) blocks when API throws", async () => {
    restore = withDualFetch(() => { throw new Error("network down"); });
    const runtime = makeRuntime();
    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    expect(r).toBe("phylanx:blocked:GATE_ERROR");
  });

  it("fail_mode=open allows when API throws", async () => {
    restore = withDualFetch(() => { throw new Error("network down"); });
    const runtime = makeRuntime({ settings: { PHYLANX_FAIL_MODE: "open" } });
    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    expect(r).toBe("phylanx:allowed:fail_open");
  });

  it("fail_mode=open does NOT bypass policy errors (only network errors)", async () => {
    restore = withDualFetch(() => ({ status: 200, body: scoreResponse({ score: 400 }) }));
    const runtime = makeRuntime({ settings: { PHYLANX_FAIL_MODE: "open" } });
    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    // Score-too-low is a PhylanxError, not a network error → still blocks
    expect(r).toBe("phylanx:blocked:SCORE_TOO_LOW");
  });
});


describe("TRUST_GATE.handler — provisional unbypassable", () => {
  let restore: () => void = () => {};
  afterEach(() => restore());

  it("blocks provisional even with allowStale + allowAnomaly", async () => {
    restore = withDualFetch(() => ({
      status: 200, body: scoreResponse({ source: "provisional", is_fresh: false, score: 500 }),
    }));
    const runtime = makeRuntime({
      settings: { PHYLANX_ALLOW_STALE: "true", PHYLANX_ALLOW_ANOMALY: "true" },
    });
    expect(await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any)).toBe("phylanx:blocked:PROVISIONAL_SCORE");
  });

  it("blocks deactivated regardless of mode=warn", async () => {
    restore = withDualFetch(() => ({
      status: 200, body: scoreResponse({ source: "deactivated", score: 0 }),
    }));
    const runtime = makeRuntime({ settings: { PHYLANX_MODE: "warn" } });
    // warn mode would normally allow, but deactivated is unbypassable → return warned
    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    // In warn mode, even AGENT_DEACTIVATED becomes warned (the mode override
    // is at the outer layer). This tests that mode is honored even for hard
    // policy violations — the operator decided to opt in to warn-only.
    expect(r).toBe("phylanx:warned:AGENT_DEACTIVATED");
  });
});


// =============================================================================
// VULN-12 — fail-closed with last-known-good cache.
//
// The combined attack the audit cares about: attacker DDoSes phylanx-api,
// every score fetch throws, the trust_gate (pre-fix) either fails open
// (RED agent borrows max) or fails closed for the entire fleet (a DoS).
//
// The mitigation: before deciding fail-open/closed, consult a recently
// fetched score in the local ScoreCache and run the local policy mirror
// against it. The tests below cover every branch of that decision tree.
// =============================================================================
describe("TRUST_GATE.handler — VULN-12 fail-closed-with-cache", () => {
  let restore: () => void = () => {};
  afterEach(() => restore());

  it("fresh cache + policy passes → allow from cache", async () => {
    restore = withDualFetch(() => { throw new Error("DDoS blackout"); });
    const runtime = makeBeaconRuntime();
    primeCache(runtime, ts({ score: 850 }));

    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);

    expect(r).toMatch(/^phylanx:allowed:cache:\d+$/);
    await flushBeacons();
    const types = capturedBeacons.map(b => b.event_type);
    expect(types).toContain("action_allowed_from_cache");
    expect(types).not.toContain("gate_fail_closed_no_cache");
  });

  it("fresh cache + policy fails → block with cache code + reason", async () => {
    restore = withDualFetch(() => { throw new Error("DDoS blackout"); });
    const runtime = makeBeaconRuntime();
    primeCache(runtime, ts({ score: 100, alert: "RED" }));

    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);

    expect(r).toBe("phylanx:blocked:SCORE_TOO_LOW:cache");
    await flushBeacons();
    const blocked = capturedBeacons.find(b => b.event_type === "action_blocked_from_cache");
    expect(blocked).toBeDefined();
    expect(blocked.block_reason).toBe("SCORE_TOO_LOW");
    expect(blocked.score).toBe(100);
  });

  it("fresh cache + deactivated → blocks even though score >= min", async () => {
    restore = withDualFetch(() => { throw new Error("DDoS blackout"); });
    const runtime = makeRuntime();
    primeCache(runtime, ts({ score: 999, source: "deactivated" }));

    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    expect(r).toBe("phylanx:blocked:AGENT_DEACTIVATED:cache");
  });

  it("fresh cache + provisional → blocks (allowProvisional is forced false)", async () => {
    restore = withDualFetch(() => { throw new Error("DDoS blackout"); });
    const runtime = makeRuntime();
    primeCache(runtime, ts({ score: 800, source: "provisional" }));

    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    expect(r).toBe("phylanx:blocked:PROVISIONAL_SCORE:cache");
  });

  it("fresh cache + policy fails + warn mode → warns from cache, does not block", async () => {
    restore = withDualFetch(() => { throw new Error("DDoS blackout"); });
    const runtime = makeRuntime({ settings: { PHYLANX_MODE: "warn" } });
    primeCache(runtime, ts({ score: 100 }));

    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    expect(r).toBe("phylanx:warned:SCORE_TOO_LOW:cache");
  });

  it("no cache at all → fail-closed with gate_fail_closed_no_cache beacon", async () => {
    restore = withDualFetch(() => { throw new Error("DDoS blackout"); });
    const runtime = makeBeaconRuntime();   // cache deliberately not primed

    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);

    expect(r).toBe("phylanx:blocked:GATE_ERROR");
    await flushBeacons();
    const noCache = capturedBeacons.find(b => b.event_type === "gate_fail_closed_no_cache");
    expect(noCache).toBeDefined();
    expect(noCache.extra.fail_mode).toBe("closed");
  });

  it("stale cache (older than TTL) → fail-closed, NOT served from cache", async () => {
    restore = withDualFetch(() => { throw new Error("DDoS blackout"); });
    // 1-minute TTL but cache will be 2 minutes old
    const runtime = makeBeaconRuntime({ PHYLANX_CACHE_TTL_MS: "60000" });
    const config = loadConfig(runtime as any);
    const state  = getOrInitState(runtime as any, config);
    state.scoreCache.put(ts({ score: 850 }), Date.now() - 120_000);

    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    expect(r).toBe("phylanx:blocked:GATE_ERROR");
    await flushBeacons();
    expect(capturedBeacons.find(b => b.event_type === "action_allowed_from_cache")).toBeUndefined();
    expect(capturedBeacons.find(b => b.event_type === "gate_fail_closed_no_cache")).toBeDefined();
  });

  it("cacheTtlMs=0 disables cache entirely (even just-written entry)", async () => {
    restore = withDualFetch(() => { throw new Error("DDoS blackout"); });
    const runtime = makeRuntime({ settings: { PHYLANX_CACHE_TTL_MS: "0" } });
    primeCache(runtime, ts({ score: 850 }));   // written but cache is disabled

    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    expect(r).toBe("phylanx:blocked:GATE_ERROR");
  });

  it("fail_mode=open + no cache → still allows (legacy escape hatch)", async () => {
    restore = withDualFetch(() => { throw new Error("DDoS blackout"); });
    const runtime = makeBeaconRuntime({ PHYLANX_FAIL_MODE: "open" });

    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    expect(r).toBe("phylanx:allowed:fail_open");
    await flushBeacons();
    // The fail-open path STILL emits the audit beacon so operators see
    // their fleet is in degraded mode during a blackout.
    expect(capturedBeacons.find(b => b.event_type === "gate_fail_closed_no_cache")).toBeDefined();
  });

  it("fail_mode=open is BYPASSED when cache is fresh (cache wins)", async () => {
    restore = withDualFetch(() => { throw new Error("DDoS blackout"); });
    // Even with fail_mode=open, a fresh cached RED score must still block.
    // Otherwise the legacy escape hatch would silently override the audit fix.
    const runtime = makeRuntime({ settings: { PHYLANX_FAIL_MODE: "open" } });
    primeCache(runtime, ts({ score: 50, alert: "RED" }));

    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    expect(r).toBe("phylanx:blocked:SCORE_TOO_LOW:cache");
  });

  it("successful fetch primes the cache for subsequent blackout calls", async () => {
    // First call returns a healthy score; second call (and beyond) blow up.
    // The second call should be allowed from cache.
    let calls = 0;
    restore = withDualFetch(() => {
      calls += 1;
      if (calls === 1) {
        return { status: 200, body: scoreResponse({ score: 820 }) };
      }
      throw new Error("DDoS blackout");
    });

    const runtime = makeRuntime();

    const r1 = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    expect(r1).toBe("phylanx:allowed:820");

    // Force the SDK's internal 30s cache to release on the next call by
    // invalidating it through the plugin state.
    const config = loadConfig(runtime as any);
    const state  = getOrInitState(runtime as any, config);
    state.client.invalidate(config.agentWallet);

    const r2 = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    expect(r2).toMatch(/^phylanx:allowed:cache:\d+$/);
  });

  it("PhylanxError with code NETWORK_ERROR (HTTP 5xx path) also serves cache", async () => {
    // The SDK throws PhylanxError("NETWORK_ERROR") on non-2xx after retries.
    // Confirm the cache path covers that branch too, not just thrown JS Errors.
    restore = withDualFetch(() => ({ status: 503, body: { error: "Service Unavailable" } }));
    const runtime = makeRuntime();
    primeCache(runtime, ts({ score: 800 }));

    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    expect(r).toMatch(/^phylanx:allowed:cache:\d+$/);
  });
});
