// =============================================================================
// test/unsafe_surface.test.ts — DBP-3 surface partition.
//
// Pins the @phylanx/sdk safe-by-default partition. The default entry point
// MUST NOT export raw cert-reader primitives (PhylanxClient,
// PhylanxChainClient); those live at `@phylanx/sdk/unsafe`.
//
// A regression that flips one of these surfaces back to the default export
// lights the test red BEFORE the rollout reaches partners.
//
// Run: tsx test/unsafe_surface.test.ts
// =============================================================================

import * as assert from "assert";

import * as defaultEntry from "../src/index";
import * as unsafeEntry from "../src/unsafe";

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

// -----------------------------------------------------------------------------
// Safe-default surface MUST hold these structurally-safe surfaces.
// -----------------------------------------------------------------------------

const REQUIRED_SAFE_EXPORTS = [
  "SafeCertReader",
  "RejectReason",
  "verifyAgainstSolanaLedger",
  "verifyInputProvenance",
  "verifyBaselineProvenance",
  "verifyScoreComputation",
  "decodeHealthCertificate",
  "decodeVerifiedConsumer",
  "verifiedConsumerPda",
  "isVerifiedConsumerActive",
  "registrationAttestationDigest",
  "certificatePda",
  "AlertTier",
  "alertTierFromCode",
];

test("default entry exposes every required safe surface", () => {
  for (const name of REQUIRED_SAFE_EXPORTS) {
    assert.ok(
      (defaultEntry as Record<string, unknown>)[name] !== undefined,
      `default @phylanx/sdk no longer exports ${name}`,
    );
  }
});

// -----------------------------------------------------------------------------
// Safe-default surface MUST NOT expose raw cert-reading primitives.
// -----------------------------------------------------------------------------

const FORBIDDEN_FROM_DEFAULT = [
  "PhylanxClient",
  "PhylanxChainClient",
  "CertificateNotFoundError",
  "PhylanxError",
  "AgentNotFoundError",
];

test("default entry does NOT expose raw cert-reader primitives", () => {
  for (const name of FORBIDDEN_FROM_DEFAULT) {
    assert.strictEqual(
      (defaultEntry as Record<string, unknown>)[name],
      undefined,
      `default @phylanx/sdk MUST NOT export ${name} — that lives at @phylanx/sdk/unsafe`,
    );
  }
});

// -----------------------------------------------------------------------------
// /unsafe MUST hold exactly the raw cert-reader primitives.
// -----------------------------------------------------------------------------

const REQUIRED_UNSAFE_EXPORTS = [
  "PhylanxClient",
  "PhylanxChainClient",
  "CertificateNotFoundError",
  "PhylanxError",
  "AgentNotFoundError",
];

test("/unsafe exposes the raw cert-reader primitives", () => {
  for (const name of REQUIRED_UNSAFE_EXPORTS) {
    assert.ok(
      (unsafeEntry as Record<string, unknown>)[name] !== undefined,
      `@phylanx/sdk/unsafe no longer exports ${name}`,
    );
  }
});

console.log(`\n${passed} passed`);
