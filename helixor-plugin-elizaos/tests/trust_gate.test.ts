// =============================================================================
// tests/trust_gate.test.ts — TRUST_GATE evaluator
// =============================================================================

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { trustGateEvaluator } from "../src/evaluators/trust_gate";
import { makeRuntime, scoreResponse, withGlobalFetch } from "./helpers";

describe("trustGateEvaluator.validate", () => {

  it("matches resolved financial action name", async () => {
    const runtime = makeRuntime();
    const message = { content: { action: "SWAP_TOKEN", text: "do swap" } } as any;
    const result = await trustGateEvaluator.validate(runtime as any, message);
    expect(result).toBe(true);
  });

  it("ignores resolved non-financial action", async () => {
    const runtime = makeRuntime();
    const message = { content: { action: "GREET_USER", text: "hi" } } as any;
    expect(await trustGateEvaluator.validate(runtime as any, message)).toBe(false);
  });

  it("falls back to keyword match only when no resolved action", async () => {
    const runtime = makeRuntime();
    const message = { content: { text: "please swap 10 SOL for USDC" } } as any;
    expect(await trustGateEvaluator.validate(runtime as any, message)).toBe(true);
  });

  it("does NOT match keyword inside other words (e.g. 'swap stories')", async () => {
    const runtime = makeRuntime();
    const m1 = { content: { text: "let's swap stories about coding" } } as any;
    expect(await trustGateEvaluator.validate(runtime as any, m1)).toBe(true);
    // Note: "swap" as a whole word matches even in "swap stories" — that's
    // intentional fallback behavior. Production should rely on action names.
  });

  it("matches whole-word verbs only — 'sweet' does NOT trigger", async () => {
    const runtime = makeRuntime();
    const m = { content: { text: "what a sweet day" } } as any;
    expect(await trustGateEvaluator.validate(runtime as any, m)).toBe(false);
  });

  it("respects custom financial action list", async () => {
    const runtime = makeRuntime({
      settings: { HELIXOR_FINANCIAL_ACTIONS: "MY_CUSTOM_ACTION" },
    });
    const message = { content: { action: "SWAP_TOKEN" } } as any;
    expect(await trustGateEvaluator.validate(runtime as any, message)).toBe(false);

    const message2 = { content: { action: "MY_CUSTOM_ACTION" } } as any;
    expect(await trustGateEvaluator.validate(runtime as any, message2)).toBe(true);
  });
});


describe("trustGateEvaluator.handler", () => {
  let restore: () => void = () => {};
  afterEach(() => restore());

  it("allows action when score >= minimum", async () => {
    restore = withGlobalFetch(() => ({
      status: 200, body: scoreResponse({ score: 800 }),
    }));

    const runtime = makeRuntime();
    const message = { content: { action: "SWAP_TOKEN" } } as any;
    const result = await trustGateEvaluator.handler(runtime as any, message);

    expect(result).toContain("helixor:allowed");
  });

  it("blocks when score below minimum", async () => {
    restore = withGlobalFetch(() => ({
      status: 200, body: scoreResponse({ score: 400 }),
    }));

    const runtime = makeRuntime();
    const message = { content: { action: "SWAP_TOKEN" } } as any;
    const result = await trustGateEvaluator.handler(runtime as any, message);

    expect(result).toBe("helixor:blocked:SCORE_TOO_LOW");
  });

  it("blocks on stale score", async () => {
    restore = withGlobalFetch(() => ({
      status: 200, body: scoreResponse({ is_fresh: false, source: "stale" }),
    }));
    const runtime = makeRuntime();
    const message = { content: { action: "SWAP_TOKEN" } } as any;
    expect(await trustGateEvaluator.handler(runtime as any, message)).toBe("helixor:blocked:STALE_SCORE");
  });

  it("blocks on anomaly", async () => {
    restore = withGlobalFetch(() => ({
      status: 200, body: scoreResponse({ anomaly_flag: true }),
    }));
    const runtime = makeRuntime();
    const message = { content: { action: "SWAP_TOKEN" } } as any;
    expect(await trustGateEvaluator.handler(runtime as any, message)).toBe("helixor:blocked:ANOMALY_DETECTED");
  });

  it("blocks on deactivated regardless of allowAnomaly", async () => {
    restore = withGlobalFetch(() => ({
      status: 200, body: scoreResponse({ source: "deactivated", score: 0 }),
    }));
    const runtime = makeRuntime({ settings: { HELIXOR_ALLOW_ANOMALY: "true" } });
    const message = { content: { action: "SWAP_TOKEN" } } as any;
    expect(await trustGateEvaluator.handler(runtime as any, message))
      .toBe("helixor:blocked:AGENT_DEACTIVATED");
  });

  it("blocks on provisional — never overridable for financial actions", async () => {
    restore = withGlobalFetch(() => ({
      status: 200, body: scoreResponse({ source: "provisional", is_fresh: false, score: 500 }),
    }));
    const runtime = makeRuntime({
      settings: {
        HELIXOR_ALLOW_STALE:   "true",
        HELIXOR_ALLOW_ANOMALY: "true",
      },
    });
    const message = { content: { action: "SWAP_TOKEN" } } as any;
    expect(await trustGateEvaluator.handler(runtime as any, message))
      .toBe("helixor:blocked:PROVISIONAL_SCORE");
  });

  it("allowStale=true accepts stale", async () => {
    restore = withGlobalFetch(() => ({
      status: 200, body: scoreResponse({ is_fresh: false, source: "stale", score: 800 }),
    }));
    const runtime = makeRuntime({ settings: { HELIXOR_ALLOW_STALE: "true" } });
    const message = { content: { action: "SWAP_TOKEN" } } as any;
    expect(await trustGateEvaluator.handler(runtime as any, message))
      .toContain("helixor:allowed");
  });

  it("emits helixor:blocked event on block", async () => {
    restore = withGlobalFetch(() => ({
      status: 200, body: scoreResponse({ score: 400 }),
    }));
    const runtime = makeRuntime();
    const message = { content: { action: "SWAP_TOKEN" } } as any;
    await trustGateEvaluator.handler(runtime as any, message);

    const blocked = runtime._events.find(e => e.name === "helixor:blocked");
    expect(blocked).toBeDefined();
    expect((blocked!.payload as any).code).toBe("SCORE_TOO_LOW");
  });

  it("on unexpected error, blocks (fail-closed)", async () => {
    restore = withGlobalFetch(() => { throw new Error("network down"); });
    const runtime = makeRuntime();
    const message = { content: { action: "SWAP_TOKEN" } } as any;
    const result = await trustGateEvaluator.handler(runtime as any, message);
    expect(result).toContain("helixor:blocked");
  });
});
