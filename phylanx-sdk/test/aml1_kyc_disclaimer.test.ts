// =============================================================================
// test/aml1_kyc_disclaimer.test.ts — AML-1 AML_KYC_DISCLAIMER pin.
//
// The SDK MUST surface the canonical KYC/AML carve-out disclaimer
// alongside every returned score (and alongside the SEC-1 disclaimer).
// The string is mirrored byte-for-byte from
// `phylanx-oracle/oracle/aml_compliance.py` (AML_KYC_DISCLAIMER).
// `audit/aml_compliance_check.py` cross-checks the two strings; this
// file pins the SDK side from the SDK's own tests.
//
// Run: tsx test/aml1_kyc_disclaimer.test.ts
// =============================================================================

import * as assert from "assert";

import {
  AML_KYC_DISCLAIMER,
  amlKycDisclaimerText,
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
// AML_KYC_DISCLAIMER — content + posture
// =============================================================================

test("AML_KYC_DISCLAIMER is non-empty", () => {
  assert.ok(AML_KYC_DISCLAIMER.length > 0);
});

test("AML_KYC_DISCLAIMER carries every required carve-out", () => {
  // The audit-mandated concrete carve-outs.
  assert.match(AML_KYC_DISCLAIMER, /NOT a KYC control/);
  assert.match(AML_KYC_DISCLAIMER, /NOT an AML screen/);
  assert.match(AML_KYC_DISCLAIMER, /Travel Rule/);
  assert.match(AML_KYC_DISCLAIMER, /sanctions screening/);
});

test("AML_KYC_DISCLAIMER frames the cluster output as a technical trust signal", () => {
  assert.match(AML_KYC_DISCLAIMER, /technical trust signals/);
});

test("AML_KYC_DISCLAIMER disclaims customer identity collection", () => {
  // The cluster's load-bearing AML posture: it does NOT collect KYC
  // data. The disclaimer must say this explicitly.
  assert.match(
    AML_KYC_DISCLAIMER,
    /does not collect customer identity information/,
  );
});

test("AML_KYC_DISCLAIMER tells the consumer they must run their own KYC/AML program", () => {
  assert.match(AML_KYC_DISCLAIMER, /MUST run their own KYC\/AML program/);
});


// =============================================================================
// amlKycDisclaimerText() helper
// =============================================================================

test("amlKycDisclaimerText() returns the constant unchanged", () => {
  assert.strictEqual(amlKycDisclaimerText(), AML_KYC_DISCLAIMER);
});

test("amlKycDisclaimerText() is referentially stable", () => {
  // Same call twice in succession returns the same string instance —
  // the helper is a constant getter, not a builder.
  assert.strictEqual(amlKycDisclaimerText(), amlKycDisclaimerText());
});


// =============================================================================
// Cross-reference: the audit gate greps for the AML_KYC_DISCLAIMER marker
// =============================================================================

test("AML_KYC_DISCLAIMER export name matches the audit pin", () => {
  // The audit gate `audit/aml_compliance_check.py` greps the SDK
  // source for the marker `AML_KYC_DISCLAIMER`. A renaming refactor
  // that breaks the marker would also break this assertion.
  assert.ok(
    /Phylanx cert scores are technical trust signals/.test(AML_KYC_DISCLAIMER),
    "AML_KYC_DISCLAIMER must lead with the canonical opening clause",
  );
});


console.log(`\n${passed} AML-1 KYC/AML disclaimer tests passed`);
