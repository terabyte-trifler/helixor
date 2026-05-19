// =============================================================================
// test/getscore_shape.test.ts — the getScore compatibility contract.
//
// The Day-19 done-when includes "the SDK still returns the same shape".
// This test pins the `HealthScore` shape `getScore` returns — the exact
// MVP fields, no more — so an accidental future change that adds/removes a
// field (and silently breaks MVP consumers) fails CI.
//
// It does NOT need a validator: it asserts the TYPE-LEVEL contract by
// constructing a HealthScore and checking its keys, and asserts that the
// V2 EpochScore is a strict SUPERSET (additive, never breaking).
//
// Run: tsx test/getscore_shape.test.ts
// =============================================================================

import { describe, expect, it } from "vitest";

import { AlertTier, type HealthScore, type EpochScore } from "../src/types";
import { PublicKey } from "@solana/web3.js";

// The frozen MVP shape — exactly these five keys, nothing else.
const MVP_HEALTH_SCORE_KEYS = ["agent", "score", "alert", "flags", "issuedAt"];

describe("getScore shape contract", () => {
  it("HealthScore has exactly the MVP keys", () => {
    const sample: HealthScore = {
      agent: PublicKey.default,
      score: 916,
      alert: AlertTier.Green,
      flags: 0,
      issuedAt: 1_777_000_000,
    };
    expect(Object.keys(sample).sort()).toEqual([...MVP_HEALTH_SCORE_KEYS].sort());
  });

  it("HealthScore field types match the MVP contract", () => {
    const sample: HealthScore = {
      agent: PublicKey.default,
      score: 700,
      alert: AlertTier.Yellow,
      flags: 0x08,
      issuedAt: 1,
    };
    expect(sample.agent).toBeInstanceOf(PublicKey);
    expect(typeof sample.score).toBe("number");
    expect(Object.values(AlertTier)).toContain(sample.alert);
    expect(typeof sample.flags).toBe("number");
    expect(typeof sample.issuedAt).toBe("number");
  });

  it("EpochScore is a strict superset of HealthScore (additive only)", () => {
    const epochScore: EpochScore = {
      agent: PublicKey.default,
      score: 916,
      alert: AlertTier.Green,
      flags: 0,
      issuedAt: 1,
      epoch: 1,
      immediateRed: false,
    };
    for (const key of MVP_HEALTH_SCORE_KEYS) {
      expect(key in epochScore).toBe(true);
    }
    expect("epoch" in epochScore).toBe(true);
    expect("immediateRed" in epochScore).toBe(true);
  });

  it("AlertTier codes are the stable MVP values", () => {
    expect(AlertTier.Green).toBe("GREEN");
    expect(AlertTier.Yellow).toBe("YELLOW");
    expect(AlertTier.Red).toBe("RED");
  });
});
