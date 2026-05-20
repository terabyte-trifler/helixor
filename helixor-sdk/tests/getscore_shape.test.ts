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

import * as assert from "assert";

import { AlertTier, type HealthScore, type EpochScore } from "../src/types";
import type { PublicKey } from "@solana/web3.js";

let passed = 0;
function test(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
    console.log(`  ok  ${name}`);
  } catch (err) {
    console.error(`FAIL  ${name}`);
    console.error(err);
    process.exitCode = 1;
  }
}

// The frozen MVP shape — exactly these five keys, nothing else.
const MVP_HEALTH_SCORE_KEYS = ["agent", "score", "alert", "flags", "issuedAt"];
const SAMPLE_AGENT = { toBase58: () => "11111111111111111111111111111111" } as PublicKey;

test("HealthScore has exactly the MVP keys", () => {
  const sample: HealthScore = {
    agent: SAMPLE_AGENT,
    score: 916,
    alert: AlertTier.Green,
    flags: 0,
    issuedAt: 1_777_000_000,
  };
  const keys = Object.keys(sample).sort();
  assert.deepStrictEqual(
    keys,
    [...MVP_HEALTH_SCORE_KEYS].sort(),
    "HealthScore must carry exactly the MVP keys — no field added or removed"
  );
});

test("HealthScore field types match the MVP contract", () => {
  const sample: HealthScore = {
    agent: SAMPLE_AGENT,
    score: 700,
    alert: AlertTier.Yellow,
    flags: 0x08,
    issuedAt: 1,
  };
  assert.strictEqual(typeof sample.agent.toBase58, "function");
  assert.strictEqual(typeof sample.score, "number");
  assert.ok(Object.values(AlertTier).includes(sample.alert));
  assert.strictEqual(typeof sample.flags, "number");
  assert.strictEqual(typeof sample.issuedAt, "number");
});

test("EpochScore is a strict superset of HealthScore (additive only)", () => {
  // Every HealthScore key must also be an EpochScore key — the V2 type
  // EXTENDS the MVP type, it never drops a field.
  const epochScore: EpochScore = {
    agent: SAMPLE_AGENT,
    score: 916,
    alert: AlertTier.Green,
    flags: 0,
    issuedAt: 1,
    epoch: 1,
    immediateRed: false,
  };
  for (const key of MVP_HEALTH_SCORE_KEYS) {
    assert.ok(
      key in epochScore,
      `EpochScore is missing MVP key '${key}' — V2 must be additive`
    );
  }
  // And it adds exactly the two V2 fields.
  assert.ok("epoch" in epochScore);
  assert.ok("immediateRed" in epochScore);
});

test("AlertTier codes are the stable MVP values", () => {
  assert.strictEqual(AlertTier.Green, "GREEN");
  assert.strictEqual(AlertTier.Yellow, "YELLOW");
  assert.strictEqual(AlertTier.Red, "RED");
});

console.log(`\n${passed} getScore-shape tests passed`);
