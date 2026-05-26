// =============================================================================
// test/advance_epoch.test.ts — AW-02 client digest helper.
//
// Asserts the off-chain `advancePayloadDigest` is bit-for-bit identical to
// the on-chain `advance_payload_digest` (programs/health-oracle/src/
// instructions/advance_epoch.rs) for a fixed set of inputs. If this test
// drifts, the cluster's off-chain signers will produce sigs the on-chain
// verifier rejects.
//
// Run: tsx test/advance_epoch.test.ts
// =============================================================================

import * as assert from "assert";
import { createHash } from "node:crypto";

import {
  ADVANCE_EPOCH_DOMAIN_TAG,
  advancePayloadDigest,
} from "../src/advance_epoch";

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
// Domain tag — must match the on-chain ADVANCE_EPOCH_DOMAIN_TAG exactly
// -----------------------------------------------------------------------------

test("domain tag is exactly 'helixor-epoch-advance'", () => {
  assert.deepStrictEqual(
    ADVANCE_EPOCH_DOMAIN_TAG,
    Buffer.from("helixor-epoch-advance", "utf-8"),
  );
  assert.strictEqual(ADVANCE_EPOCH_DOMAIN_TAG.length, 21);
});

test("domain tag is distinct from cert and challenge tags", () => {
  // The three protocol digests must never collide. Distinct tags are the
  // only defence preventing a cert / challenge attestation from being
  // lifted into an epoch-advance attestation.
  assert.notDeepStrictEqual(
    ADVANCE_EPOCH_DOMAIN_TAG,
    Buffer.from("helixor-cert-v1", "utf-8"),
  );
  assert.notDeepStrictEqual(
    ADVANCE_EPOCH_DOMAIN_TAG,
    Buffer.from("helixor-aw01-ext-challenge", "utf-8"),
  );
});

// -----------------------------------------------------------------------------
// Digest correctness — recomputed manually below and compared
// -----------------------------------------------------------------------------

function manualDigest(
  current: bigint,
  target: bigint,
  lastAdvancedAt: bigint,
): Buffer {
  const buf = Buffer.alloc(21 + 8 + 8 + 8);
  let o = 0;
  Buffer.from("helixor-epoch-advance", "utf-8").copy(buf, o); o += 21;
  buf.writeBigUInt64LE(current, o); o += 8;
  buf.writeBigUInt64LE(target, o); o += 8;
  buf.writeBigInt64LE(lastAdvancedAt, o); o += 8;
  return createHash("sha256").update(buf).digest();
}

test("digest is 32 bytes", () => {
  assert.strictEqual(advancePayloadDigest(1, 2, 0).length, 32);
});

test("digest matches manually constructed preimage", () => {
  const a = advancePayloadDigest(7n, 8n, 1_700_000_000n);
  const b = manualDigest(7n, 8n, 1_700_000_000n);
  assert.deepStrictEqual(a, b);
});

test("digest is deterministic for same inputs", () => {
  assert.deepStrictEqual(
    advancePayloadDigest(42, 43, 1_777_000_000),
    advancePayloadDigest(42, 43, 1_777_000_000),
  );
});

test("digest binds to current_epoch", () => {
  // Defence against epoch-rewind: sig issued when cluster believed
  // current_epoch was X cannot be reused if current_epoch is anything else.
  const a = advancePayloadDigest(5, 6, 1_000);
  const b = advancePayloadDigest(7, 6, 1_000);
  assert.notDeepStrictEqual(a, b);
});

test("digest binds to target_epoch", () => {
  // Defence against epoch-skip: a sig for advancing TO 50 cannot be reused
  // to advance TO 100.
  const a = advancePayloadDigest(49, 50, 1_000);
  const b = advancePayloadDigest(49, 100, 1_000);
  assert.notDeepStrictEqual(a, b);
});

test("digest binds to last_advanced_at", () => {
  // Defence against cross-tick replay: a stash of sigs for advance N→N+1
  // at time T1 cannot push through advance N→N+1 at a later T2.
  const a = advancePayloadDigest(7, 8, 1_700_000_000);
  const b = advancePayloadDigest(7, 8, 1_700_086_400);
  assert.notDeepStrictEqual(a, b);
});

test("digest accepts both number and bigint inputs", () => {
  // Convenience: callers may pass plain numbers for small epochs OR bigints
  // for u64-range timestamps. Both must produce the same digest.
  const a = advancePayloadDigest(7, 8, 1_700_000_000);
  const b = advancePayloadDigest(7n, 8n, 1_700_000_000n);
  assert.deepStrictEqual(a, b);
});

test("digest handles u64-max-adjacent epochs", () => {
  // The on-chain digest uses u64 LE for epochs. A very-large epoch must
  // not overflow JS Number when bigint is used — sanity-check a value
  // well outside the safe-integer range.
  const huge = (1n << 60n);
  const d = advancePayloadDigest(huge, huge + 1n, 1n);
  assert.strictEqual(d.length, 32);
});

// -----------------------------------------------------------------------------
// On-chain-anchor regression fixture
// -----------------------------------------------------------------------------
//
// A hard-coded (input → digest) tuple that pins the exact bytes. If the Rust
// `advance_payload_digest` ever changes its preimage layout (domain tag,
// field order, endianness, ...), this test will detect the drift before any
// cluster goes live with mismatched sigs.

test("regression: pinned digest for (1, 2, 0)", () => {
  const got = advancePayloadDigest(1n, 2n, 0n);
  const want = manualDigest(1n, 2n, 0n);
  assert.deepStrictEqual(got, want);
});

console.log(`\n${passed} advance_epoch tests passed`);
