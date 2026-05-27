// =============================================================================
// test/sec1_advisory_disclaimer.test.ts — SEC-1 ADVISORY_DISCLAIMER pin.
//
// The SDK MUST surface the canonical not-investment-advice disclaimer
// alongside every returned score. The string is mirrored byte-for-byte
// from `helixor-oracle/oracle/securities_compliance.py` (ADVISORY_DISCLAIMER).
// `audit/securities_compliance_check.py` cross-checks the two strings; this
// file pins the SDK side from the SDK's own tests.
//
// Run: tsx test/sec1_advisory_disclaimer.test.ts
// =============================================================================

import * as assert from "assert";

import {
  ADVISORY_DISCLAIMER,
  disclaimerText,
} from "../src/safe_reader";


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


// =============================================================================
// ADVISORY_DISCLAIMER — content + posture
// =============================================================================

test("ADVISORY_DISCLAIMER is non-empty", () => {
  assert.ok(ADVISORY_DISCLAIMER.length > 0);
});

test("ADVISORY_DISCLAIMER carries every required carve-out", () => {
  // The audit-mandated three concrete carve-outs.
  assert.match(ADVISORY_DISCLAIMER, /NOT investment advice/);
  assert.match(ADVISORY_DISCLAIMER, /NOT a security rating/);
  assert.match(ADVISORY_DISCLAIMER, /NOT issued by a registered investment adviser/);
});

test("ADVISORY_DISCLAIMER frames the cluster output as a technical trust signal", () => {
  assert.match(ADVISORY_DISCLAIMER, /technical trust signals/);
});

test("ADVISORY_DISCLAIMER tells the consumer the decision is theirs alone", () => {
  // Critical posture point — the cluster output is NOT a recommendation.
  assert.match(ADVISORY_DISCLAIMER, /the consumer's alone/);
  assert.match(ADVISORY_DISCLAIMER, /MUST NOT treat a Helixor cert score as a recommendation/);
});


// =============================================================================
// disclaimerText() helper
// =============================================================================

test("disclaimerText() returns the constant unchanged", () => {
  assert.strictEqual(disclaimerText(), ADVISORY_DISCLAIMER);
});

test("disclaimerText() is referentially stable", () => {
  // Same call twice in succession returns the same string instance —
  // the helper is a constant getter, not a builder.
  assert.strictEqual(disclaimerText(), disclaimerText());
});


// =============================================================================
// Cross-reference: the example_safe_partner reader imports the constant
// =============================================================================

test("ADVISORY_DISCLAIMER export name matches the audit pin", () => {
  // The audit gate `audit/securities_compliance_check.py` greps the SDK
  // source for the marker `ADVISORY_DISCLAIMER`. A renaming refactor that
  // breaks the marker would also break this assertion.
  assert.ok(
    /Helixor cert scores are technical trust signals/.test(ADVISORY_DISCLAIMER),
    "ADVISORY_DISCLAIMER must lead with the canonical opening clause",
  );
});


console.log(`\n${passed} SEC-1 advisory-disclaimer tests passed`);
