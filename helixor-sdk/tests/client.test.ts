// =============================================================================
// @helixor/client — Vitest test suite
//
// Run: npm test
//
// Uses a mock fetch passed via options.fetch — no network, no MSW server.
// 30+ assertions across happy path, errors, retries, cache, validation, policy.
// =============================================================================

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  AgentDeactivatedError,
  AgentNotFoundError,
  AnomalyDetectedError,
  HelixorClient,
  HelixorError,
  InvalidAgentWalletError,
  NetworkError,
  ProvisionalScoreError,
  RateLimitedError,
  ScoreTooLowError,
  ServerError,
  StaleScoreError,
  TimeoutError,
  type TrustScore,
} from "../src";

const VALID_PUBKEY = "AGENT11111111111111111111111111111111111111";

// ─────────────────────────────────────────────────────────────────────────────
// Mock helpers
// ─────────────────────────────────────────────────────────────────────────────

function makeApiResponse(overrides: any = {}) {
  return {
    agent_wallet: VALID_PUBKEY,
    score:        850,
    alert:        "GREEN",
    source:       "live",
    success_rate: 97.0,
    anomaly_flag: false,
    updated_at:   Math.floor(Date.now() / 1000),
    is_fresh:     true,
    breakdown: {
      success_rate_score: 500,
      consistency_score:  300,
      stability_score:    50,
      raw_score:          850,
      guard_rail_applied: false,
    },
    scoring_algo_version: 1,
    weights_version:      1,
    baseline_hash_prefix: "abcdef0123456789abcdef0123456789",
    served_at: Math.floor(Date.now() / 1000),
    cached:    false,
    ...overrides,
  };
}

function makeFetch(handler: (url: string) => { status: number; body?: any; headers?: Record<string,string> } | Promise<any>): typeof fetch {
  return vi.fn(async (url: any) => {
    const result = await handler(String(url));
    const headers = new Headers({
      "content-type": "application/json",
      "x-request-id": "test-req-1",
      ...(result.headers ?? {}),
    });
    return {
      ok:      result.status >= 200 && result.status < 300,
      status:  result.status,
      headers,
      json:    async () => result.body,
      text:    async () => JSON.stringify(result.body),
    } as Response;
  }) as unknown as typeof fetch;
}

// =============================================================================
// Group 1: Validation
// =============================================================================
describe("HelixorClient — input validation", () => {

  it("throws InvalidAgentWalletError on empty string", async () => {
    const c = new HelixorClient({ fetch: makeFetch(() => ({ status: 200 })) });
    await expect(c.getScore("")).rejects.toBeInstanceOf(InvalidAgentWalletError);
  });

  it("throws InvalidAgentWalletError on too-short string", async () => {
    const c = new HelixorClient({ fetch: makeFetch(() => ({ status: 200 })) });
    await expect(c.getScore("abc")).rejects.toBeInstanceOf(InvalidAgentWalletError);
  });

  it("throws InvalidAgentWalletError on special chars", async () => {
    const c = new HelixorClient({ fetch: makeFetch(() => ({ status: 200 })) });
    await expect(c.getScore("!!!" + "a".repeat(40))).rejects.toBeInstanceOf(InvalidAgentWalletError);
  });

  it("validates BEFORE making any HTTP call", async () => {
    const f = makeFetch(() => ({ status: 200 }));
    const c = new HelixorClient({ fetch: f });
    try { await c.getScore("badpubkey"); } catch {}
    expect(f).not.toHaveBeenCalled();
  });

});

// =============================================================================
// Group 2: getScore happy path
// =============================================================================
describe("HelixorClient — getScore happy path", () => {

  it("returns a fully-typed TrustScore", async () => {
    const c = new HelixorClient({
      apiBase: "https://api.test",
      fetch: makeFetch(() => ({ status: 200, body: makeApiResponse() })),
    });
    const score = await c.getScore(VALID_PUBKEY);
    expect(score.agentWallet).toBe(VALID_PUBKEY);
    expect(score.score).toBe(850);
    expect(score.alert).toBe("GREEN");
    expect(score.source).toBe("live");
    expect(score.successRate).toBe(97.0);
    expect(score.anomalyFlag).toBe(false);
    expect(score.isFresh).toBe(true);
    expect(score.breakdown?.successRateScore).toBe(500);
    expect(score.breakdown?.consistencyScore).toBe(300);
  });

  it("hits the configured API base", async () => {
    const f = makeFetch((url) => {
      expect(url).toBe(`https://test.example.com/score/${VALID_PUBKEY}`);
      return { status: 200, body: makeApiResponse() };
    });
    const c = new HelixorClient({ apiBase: "https://test.example.com", fetch: f });
    await c.getScore(VALID_PUBKEY);
    expect(f).toHaveBeenCalledOnce();
  });

  it("strips trailing slash from apiBase", async () => {
    const f = makeFetch((url) => {
      expect(url).toBe(`https://test.example.com/score/${VALID_PUBKEY}`);
      return { status: 200, body: makeApiResponse() };
    });
    const c = new HelixorClient({ apiBase: "https://test.example.com/////", fetch: f });
    await c.getScore(VALID_PUBKEY);
  });

  it("sends Authorization header when apiKey provided", async () => {
    const f = vi.fn(async (_, init: any) => {
      expect(init.headers["Authorization"]).toBe("Bearer test-key-123");
      return { ok: true, status: 200, headers: new Headers(), json: async () => makeApiResponse() } as any;
    });
    const c = new HelixorClient({ apiKey: "test-key-123", fetch: f as any });
    await c.getScore(VALID_PUBKEY);
  });

});

// =============================================================================
// Group 3: getScore error mapping
// =============================================================================
describe("HelixorClient — getScore errors", () => {

  it("maps 404 → AgentNotFoundError", async () => {
    const c = new HelixorClient({
      fetch: makeFetch(() => ({ status: 404, body: { error: "not found", code: "AGENT_NOT_FOUND" } })),
    });
    await expect(c.getScore(VALID_PUBKEY)).rejects.toBeInstanceOf(AgentNotFoundError);
  });

  it("AgentNotFoundError carries requestId", async () => {
    const c = new HelixorClient({
      fetch: makeFetch(() => ({ status: 404, body: {}, headers: { "x-request-id": "req-xyz" } })),
    });
    try {
      await c.getScore(VALID_PUBKEY);
    } catch (err: any) {
      expect(err.requestId).toBe("req-xyz");
    }
  });

  it("maps 429 → RateLimitedError", async () => {
    const c = new HelixorClient({
      fetch: makeFetch(() => ({ status: 429, body: {}, headers: { "retry-after": "30" } })),
    });
    await expect(c.getScore(VALID_PUBKEY)).rejects.toBeInstanceOf(RateLimitedError);
  });

  it("maps persistent 5xx → ServerError after retries", async () => {
    let calls = 0;
    const c = new HelixorClient({
      maxRetries: 2,
      fetch: makeFetch(() => { calls++; return { status: 503, body: { error: "down" } }; }),
    });
    await expect(c.getScore(VALID_PUBKEY)).rejects.toBeInstanceOf(ServerError);
    expect(calls).toBe(3);  // initial + 2 retries
  });

  it("does NOT retry 404", async () => {
    let calls = 0;
    const c = new HelixorClient({
      maxRetries: 5,
      fetch: makeFetch(() => { calls++; return { status: 404, body: {} }; }),
    });
    await expect(c.getScore(VALID_PUBKEY)).rejects.toBeInstanceOf(AgentNotFoundError);
    expect(calls).toBe(1);
  });

  it("does NOT retry 429", async () => {
    let calls = 0;
    const c = new HelixorClient({
      maxRetries: 5,
      fetch: makeFetch(() => { calls++; return { status: 429, body: {} }; }),
    });
    await expect(c.getScore(VALID_PUBKEY)).rejects.toBeInstanceOf(RateLimitedError);
    expect(calls).toBe(1);
  });

  it("retries 5xx and succeeds", async () => {
    let calls = 0;
    const c = new HelixorClient({
      maxRetries: 2,
      fetch: makeFetch(() => {
        calls++;
        if (calls === 1) return { status: 503, body: {} };
        return { status: 200, body: makeApiResponse() };
      }),
    });
    const score = await c.getScore(VALID_PUBKEY);
    expect(score.score).toBe(850);
    expect(calls).toBe(2);
  });

  it("maps abort → TimeoutError", async () => {
    const c = new HelixorClient({
      timeoutMs: 50,
      fetch: ((url: any, init: any) =>
        new Promise((_resolve, reject) => {
          init.signal.addEventListener("abort", () => {
            const e: any = new Error("aborted");
            e.name = "AbortError";
            reject(e);
          });
        })) as any,
    });
    await expect(c.getScore(VALID_PUBKEY)).rejects.toBeInstanceOf(TimeoutError);
  });

  it("maps fetch thrown → NetworkError", async () => {
    const c = new HelixorClient({
      maxRetries: 0,
      fetch: (() => { throw new Error("ECONNREFUSED"); }) as any,
    });
    await expect(c.getScore(VALID_PUBKEY)).rejects.toBeInstanceOf(NetworkError);
  });

});

// =============================================================================
// Group 4: Caching
// =============================================================================
describe("HelixorClient — client-side cache", () => {

  it("second call within TTL is cached", async () => {
    let calls = 0;
    const c = new HelixorClient({
      cacheTtlMs: 60_000,
      fetch: makeFetch(() => { calls++; return { status: 200, body: makeApiResponse() }; }),
    });
    await c.getScore(VALID_PUBKEY);
    await c.getScore(VALID_PUBKEY);
    expect(calls).toBe(1);
  });

  it("cacheTtlMs=0 disables cache", async () => {
    let calls = 0;
    const c = new HelixorClient({
      cacheTtlMs: 0,
      fetch: makeFetch(() => { calls++; return { status: 200, body: makeApiResponse() }; }),
    });
    await c.getScore(VALID_PUBKEY);
    await c.getScore(VALID_PUBKEY);
    expect(calls).toBe(2);
  });

  it("invalidate() forces refresh", async () => {
    let calls = 0;
    const c = new HelixorClient({
      cacheTtlMs: 60_000,
      fetch: makeFetch(() => { calls++; return { status: 200, body: makeApiResponse() }; }),
    });
    await c.getScore(VALID_PUBKEY);
    c.invalidate(VALID_PUBKEY);
    await c.getScore(VALID_PUBKEY);
    expect(calls).toBe(2);
  });

  it("clearCache() forces refresh for all", async () => {
    let calls = 0;
    const c = new HelixorClient({
      cacheTtlMs: 60_000,
      fetch: makeFetch(() => { calls++; return { status: 200, body: makeApiResponse() }; }),
    });
    await c.getScore(VALID_PUBKEY);
    c.clearCache();
    await c.getScore(VALID_PUBKEY);
    expect(calls).toBe(2);
  });

});

// =============================================================================
// Group 5: requireMinScore policy
// =============================================================================
describe("HelixorClient — requireMinScore", () => {

  function clientReturning(payload: any) {
    return new HelixorClient({
      fetch: makeFetch(() => ({ status: 200, body: payload })),
    });
  }

  it("passes when score >= minimum and all flags clean", async () => {
    const c = clientReturning(makeApiResponse({ score: 800 }));
    const score = await c.requireMinScore(VALID_PUBKEY, 700);
    expect(score.score).toBe(800);
  });

  it("throws ScoreTooLowError when score < minimum", async () => {
    const c = clientReturning(makeApiResponse({ score: 500 }));
    await expect(c.requireMinScore(VALID_PUBKEY, 700)).rejects.toBeInstanceOf(ScoreTooLowError);
  });

  it("throws StaleScoreError when is_fresh=false", async () => {
    const c = clientReturning(makeApiResponse({ is_fresh: false, source: "stale" }));
    await expect(c.requireMinScore(VALID_PUBKEY, 700)).rejects.toBeInstanceOf(StaleScoreError);
  });

  it("allowStale=true accepts stale scores", async () => {
    const c = clientReturning(makeApiResponse({ is_fresh: false, source: "stale" }));
    const score = await c.requireMinScore(VALID_PUBKEY, 700, { allowStale: true });
    expect(score.isFresh).toBe(false);
  });

  it("throws AnomalyDetectedError when anomaly_flag=true", async () => {
    const c = clientReturning(makeApiResponse({ anomaly_flag: true }));
    await expect(c.requireMinScore(VALID_PUBKEY, 700)).rejects.toBeInstanceOf(AnomalyDetectedError);
  });

  it("allowAnomaly=true accepts anomaly", async () => {
    const c = clientReturning(makeApiResponse({ anomaly_flag: true }));
    const score = await c.requireMinScore(VALID_PUBKEY, 700, { allowAnomaly: true });
    expect(score.anomalyFlag).toBe(true);
  });

  it("throws AgentDeactivatedError on deactivated source", async () => {
    const c = clientReturning(makeApiResponse({ source: "deactivated", score: 0 }));
    await expect(c.requireMinScore(VALID_PUBKEY, 700)).rejects.toBeInstanceOf(AgentDeactivatedError);
  });

  it("AgentDeactivatedError is NOT bypassable", async () => {
    const c = clientReturning(makeApiResponse({ source: "deactivated", score: 0 }));
    await expect(
      c.requireMinScore(VALID_PUBKEY, 0, { allowStale: true, allowAnomaly: true, allowProvisional: true }),
    ).rejects.toBeInstanceOf(AgentDeactivatedError);
  });

  it("throws ProvisionalScoreError on provisional source", async () => {
    const c = clientReturning(makeApiResponse({ source: "provisional", is_fresh: false, score: 500 }));
    await expect(c.requireMinScore(VALID_PUBKEY, 400)).rejects.toBeInstanceOf(ProvisionalScoreError);
  });

  it("allowProvisional=true accepts provisional", async () => {
    const c = clientReturning(makeApiResponse({ source: "provisional", is_fresh: false, score: 500 }));
    const score = await c.requireMinScore(VALID_PUBKEY, 400, {
      allowProvisional: true, allowStale: true,
    });
    expect(score.source).toBe("provisional");
  });

  it("error carries the score it failed against", async () => {
    const c = clientReturning(makeApiResponse({ score: 300 }));
    try {
      await c.requireMinScore(VALID_PUBKEY, 700);
    } catch (err: any) {
      expect(err).toBeInstanceOf(ScoreTooLowError);
      expect(err.score?.score).toBe(300);
    }
  });

});

// =============================================================================
// Group 6: HelixorError catches everything
// =============================================================================
describe("HelixorClient — error hierarchy", () => {

  it("all SDK errors extend HelixorError", async () => {
    const cases: Array<() => Promise<any>> = [
      async () => { const c = new HelixorClient({ fetch: makeFetch(() => ({ status: 404, body: {} })) }); return c.getScore(VALID_PUBKEY); },
      async () => { const c = new HelixorClient({ fetch: makeFetch(() => ({ status: 429, body: {} })) }); return c.getScore(VALID_PUBKEY); },
      async () => { const c = new HelixorClient({ fetch: makeFetch(() => ({ status: 500, body: {} })), maxRetries: 0 }); return c.getScore(VALID_PUBKEY); },
    ];
    for (const fn of cases) {
      try { await fn(); } catch (e) { expect(e).toBeInstanceOf(HelixorError); }
    }
  });

  it("error codes are stable", () => {
    const error = new ScoreTooLowError(makeApiResponse() as any, 700);
    expect(error.code).toBe("SCORE_TOO_LOW");
  });

});
