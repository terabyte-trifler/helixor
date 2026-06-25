// =============================================================================
// tests/score_cache.test.ts — VULN-12 unit tests.
//
// Covers the two primitives the trust_gate's fail-closed-with-cache path
// depends on:
//
//   1. `applyPolicy` — pure mirror of PhylanxClient.requireMinScore.
//      The SDK is the canonical source of truth; this local mirror is what
//      the trust_gate evaluates against the CACHED score when the API is
//      unreachable. Tests assert that the precedence and the bypass flags
//      match the SDK's behaviour line-for-line.
//
//   2. `ScoreCache` — single-slot last-known-good cache with TTL.
//      The trust_gate's NETWORK_ERROR branch reads from it; every
//      successful fetch (background refresh, gate, action) writes to it
//      via PluginState.recordScore. Tests cover put/peek/age/isFresh/clear,
//      the ttlMs == 0 disabled-cache case, and TTL edge cases.
// =============================================================================
import { describe, expect, it } from "vitest";

import type { TrustScore } from "@phylanx/client/unsafe";

import { applyPolicy, ScoreCache } from "../src/score_cache";


function makeScore(overrides: Partial<TrustScore> = {}): TrustScore {
  return {
    agentWallet: "C6EiVB4Tiky14k8mtrK6EJ4FZN54pKCtcJstU7umhtjP",
    score:       800,
    alert:       "GREEN",
    source:      "live",
    successRate: 97,
    anomalyFlag: false,
    isFresh:     true,
    updatedAt:   Math.floor(Date.now() / 1000),
    servedAt:    Math.floor(Date.now() / 1000),
    cached:      false,
    ...overrides,
  };
}


describe("applyPolicy — precedence (mirror of SDK requireMinScore)", () => {
  const baseOpts = {
    minScore:         600,
    allowStale:       false,
    allowAnomaly:     false,
    allowProvisional: false,
  };

  it("allows a healthy score above the minimum", () => {
    expect(applyPolicy(makeScore(), baseOpts)).toEqual({ allowed: true });
  });

  it("AGENT_DEACTIVATED wins over everything", () => {
    const s = makeScore({
      source: "deactivated", isFresh: false, anomalyFlag: true, score: 0,
    });
    expect(applyPolicy(s, { ...baseOpts, allowStale: true, allowAnomaly: true }))
      .toEqual({ allowed: false, code: "AGENT_DEACTIVATED" });
  });

  it("PROVISIONAL_SCORE blocks unless allowProvisional", () => {
    const s = makeScore({ source: "provisional", score: 500 });
    expect(applyPolicy(s, baseOpts))
      .toEqual({ allowed: false, code: "PROVISIONAL_SCORE" });
  });

  it("PROVISIONAL_SCORE bypassed when allowProvisional=true", () => {
    const s = makeScore({ source: "provisional", score: 800 });
    expect(applyPolicy(s, { ...baseOpts, allowProvisional: true }))
      .toEqual({ allowed: true });
  });

  it("STALE_SCORE blocks unless allowStale", () => {
    const s = makeScore({ isFresh: false });
    expect(applyPolicy(s, baseOpts))
      .toEqual({ allowed: false, code: "STALE_SCORE" });
  });

  it("STALE_SCORE bypassed when allowStale=true", () => {
    const s = makeScore({ isFresh: false });
    expect(applyPolicy(s, { ...baseOpts, allowStale: true }))
      .toEqual({ allowed: true });
  });

  it("ANOMALY_DETECTED blocks unless allowAnomaly", () => {
    const s = makeScore({ anomalyFlag: true });
    expect(applyPolicy(s, baseOpts))
      .toEqual({ allowed: false, code: "ANOMALY_DETECTED" });
  });

  it("ANOMALY_DETECTED bypassed when allowAnomaly=true", () => {
    const s = makeScore({ anomalyFlag: true });
    expect(applyPolicy(s, { ...baseOpts, allowAnomaly: true }))
      .toEqual({ allowed: true });
  });

  it("SCORE_TOO_LOW when score < minScore", () => {
    const s = makeScore({ score: 599 });
    expect(applyPolicy(s, baseOpts))
      .toEqual({ allowed: false, code: "SCORE_TOO_LOW" });
  });

  it("score exactly at minScore is allowed (>= boundary)", () => {
    const s = makeScore({ score: 600 });
    expect(applyPolicy(s, baseOpts)).toEqual({ allowed: true });
  });

  it("precedence: stale beats anomaly beats too-low", () => {
    const s = makeScore({ isFresh: false, anomalyFlag: true, score: 100 });
    expect(applyPolicy(s, baseOpts))
      .toEqual({ allowed: false, code: "STALE_SCORE" });
    expect(applyPolicy(s, { ...baseOpts, allowStale: true }))
      .toEqual({ allowed: false, code: "ANOMALY_DETECTED" });
    expect(applyPolicy(s, { ...baseOpts, allowStale: true, allowAnomaly: true }))
      .toEqual({ allowed: false, code: "SCORE_TOO_LOW" });
  });
});


describe("ScoreCache — construction validation", () => {
  it("accepts ttlMs > 0", () => {
    expect(() => new ScoreCache(60_000)).not.toThrow();
  });

  it("accepts ttlMs == 0 (disabled cache)", () => {
    expect(() => new ScoreCache(0)).not.toThrow();
  });

  it("rejects negative ttlMs", () => {
    expect(() => new ScoreCache(-1)).toThrow(/non-negative/);
  });

  it("rejects non-finite ttlMs", () => {
    expect(() => new ScoreCache(Infinity)).toThrow(/finite/);
    expect(() => new ScoreCache(NaN)).toThrow(/finite/);
  });
});


describe("ScoreCache — put/peek/age/isFresh", () => {
  it("is empty by default", () => {
    const c = new ScoreCache(60_000);
    expect(c.peek()).toBeNull();
    expect(c.age()).toBe(Infinity);
    expect(c.isFresh()).toBe(false);
    expect(c.getIfFresh()).toBeNull();
  });

  it("put stores the score and timestamp", () => {
    const c = new ScoreCache(60_000);
    const s = makeScore({ score: 750 });
    c.put(s, 1_000_000);
    const entry = c.peek();
    expect(entry).not.toBeNull();
    expect(entry!.score.score).toBe(750);
    expect(entry!.cachedAt).toBe(1_000_000);
  });

  it("age reports elapsed ms relative to caller-supplied now", () => {
    const c = new ScoreCache(60_000);
    c.put(makeScore(), 1_000_000);
    expect(c.age(1_000_500)).toBe(500);
    expect(c.age(1_060_001)).toBe(60_001);
  });

  it("isFresh respects TTL boundary", () => {
    const c = new ScoreCache(60_000);
    c.put(makeScore(), 1_000_000);
    expect(c.isFresh(1_059_999)).toBe(true);
    expect(c.isFresh(1_060_000)).toBe(false);   // strict <
    expect(c.isFresh(1_060_001)).toBe(false);
  });

  it("ttlMs == 0 means never fresh, even immediately after put", () => {
    const c = new ScoreCache(0);
    c.put(makeScore(), 1_000_000);
    expect(c.isFresh(1_000_000)).toBe(false);
    expect(c.getIfFresh(1_000_000)).toBeNull();
    // peek still returns the entry — the cache stored it; freshness is a
    // separate gate.
    expect(c.peek()).not.toBeNull();
  });

  it("getIfFresh returns the entry inside TTL and null after", () => {
    const c = new ScoreCache(60_000);
    const s = makeScore({ score: 700 });
    c.put(s, 1_000_000);
    expect(c.getIfFresh(1_030_000)?.score.score).toBe(700);
    expect(c.getIfFresh(1_100_000)).toBeNull();
  });

  it("put overwrites previous entry", () => {
    const c = new ScoreCache(60_000);
    c.put(makeScore({ score: 100 }), 1_000_000);
    c.put(makeScore({ score: 900 }), 1_000_500);
    expect(c.peek()!.score.score).toBe(900);
    expect(c.peek()!.cachedAt).toBe(1_000_500);
  });

  it("clear empties the cache", () => {
    const c = new ScoreCache(60_000);
    c.put(makeScore(), 1_000_000);
    c.clear();
    expect(c.peek()).toBeNull();
    expect(c.isFresh()).toBe(false);
  });
});


describe("ScoreCache — semantic guarantees", () => {
  it("caches RED scores too (cache is truthful, not optimistic)", () => {
    // A previous bug shape: caching only "good" scores. The audit-mandated
    // semantics is that the cache reflects the most recent fetched score,
    // regardless of policy outcome. The POLICY decides allow/block at gate
    // time — the cache is just a value store.
    const c = new ScoreCache(60_000);
    const red = makeScore({ score: 100, alert: "RED" });
    c.put(red, 1_000_000);
    expect(c.getIfFresh(1_010_000)?.score.score).toBe(100);
    expect(c.getIfFresh(1_010_000)?.score.alert).toBe("RED");
  });

  it("policy applied to a cached RED score blocks", () => {
    const c = new ScoreCache(60_000);
    c.put(makeScore({ score: 100, alert: "RED" }), 1_000_000);
    const cached = c.getIfFresh(1_010_000)!;
    expect(applyPolicy(cached.score, {
      minScore: 600, allowStale: false, allowAnomaly: false, allowProvisional: false,
    })).toEqual({ allowed: false, code: "SCORE_TOO_LOW" });
  });
});
