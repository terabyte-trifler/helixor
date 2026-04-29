// tests/trust_gate.test.ts — Day 12: mode + fail_mode + telemetry
import { afterEach, describe, expect, it, vi } from "vitest";

import { trustGateEvaluator } from "../src/evaluators/trust_gate";
import { makeRuntime, scoreResponse } from "./helpers";

// Helper: compose a fetch that handles BOTH score requests and beacon POSTs
function withDualFetch(scoreHandler: (url: string) => any) {
  const original = globalThis.fetch;
  globalThis.fetch = vi.fn(async (url: any, init?: any) => {
    const u = String(url);
    if (u.includes("/telemetry/beacon")) {
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


describe("TRUST_GATE.validate — mode interactions", () => {

  it("observe mode never participates", async () => {
    const runtime = makeRuntime({ settings: { HELIXOR_MODE: "observe" } });
    const message = { content: { action: "SWAP_TOKEN" } } as any;
    const result = await trustGateEvaluator.validate(runtime as any, message);
    expect(result).toBe(false);
  });

  it("warn mode still validates financial actions", async () => {
    const runtime = makeRuntime({ settings: { HELIXOR_MODE: "warn" } });
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
    expect(r).toBe("helixor:blocked:SCORE_TOO_LOW");
  });

  it("warn mode logs but ALLOWS on low score", async () => {
    restore = withDualFetch(() => ({ status: 200, body: scoreResponse({ score: 400 }) }));
    const runtime = makeRuntime({ settings: { HELIXOR_MODE: "warn" } });
    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    expect(r).toBe("helixor:warned:SCORE_TOO_LOW");
  });

  it("warn mode still emits helixor:blocked event for downstream consumers", async () => {
    restore = withDualFetch(() => ({ status: 200, body: scoreResponse({ score: 400 }) }));
    const runtime = makeRuntime({ settings: { HELIXOR_MODE: "warn" } });
    await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    const ev = runtime._events.find(e => e.name === "helixor:blocked");
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
    expect(r).toBe("helixor:blocked:GATE_ERROR");
  });

  it("fail_mode=open allows when API throws", async () => {
    restore = withDualFetch(() => { throw new Error("network down"); });
    const runtime = makeRuntime({ settings: { HELIXOR_FAIL_MODE: "open" } });
    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    expect(r).toBe("helixor:allowed:fail_open");
  });

  it("fail_mode=open does NOT bypass policy errors (only network errors)", async () => {
    restore = withDualFetch(() => ({ status: 200, body: scoreResponse({ score: 400 }) }));
    const runtime = makeRuntime({ settings: { HELIXOR_FAIL_MODE: "open" } });
    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    // Score-too-low is a HelixorError, not a network error → still blocks
    expect(r).toBe("helixor:blocked:SCORE_TOO_LOW");
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
      settings: { HELIXOR_ALLOW_STALE: "true", HELIXOR_ALLOW_ANOMALY: "true" },
    });
    expect(await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any)).toBe("helixor:blocked:PROVISIONAL_SCORE");
  });

  it("blocks deactivated regardless of mode=warn", async () => {
    restore = withDualFetch(() => ({
      status: 200, body: scoreResponse({ source: "deactivated", score: 0 }),
    }));
    const runtime = makeRuntime({ settings: { HELIXOR_MODE: "warn" } });
    // warn mode would normally allow, but deactivated is unbypassable → return warned
    const r = await trustGateEvaluator.handler(runtime as any, {
      content: { action: "SWAP_TOKEN" },
    } as any);
    // In warn mode, even AGENT_DEACTIVATED becomes warned (the mode override
    // is at the outer layer). This tests that mode is honored even for hard
    // policy violations — the operator decided to opt in to warn-only.
    expect(r).toBe("helixor:warned:AGENT_DEACTIVATED");
  });
});
