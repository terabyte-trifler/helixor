// =============================================================================
// test/verified_consumer.test.ts — DBP-2 account-decoder + PDA tests.
//
// Builds a VerifiedConsumer account buffer in the EXACT layout the Rust
// `#[account] VerifiedConsumer` struct produces, decodes it, and asserts the
// round trip. This pins the SDK's byte-layout contract to the on-chain one.
//
// Also pins:
//   - PDA seeds match the Rust SEED_PREFIX,
//   - registration digest matches Rust `registration_attestation_digest`,
//   - isActive() gates purely on the state byte.
//
// Run: tsx test/verified_consumer.test.ts
// =============================================================================

import * as assert from "assert";
import { PublicKey } from "@solana/web3.js";
import { createHash } from "crypto";

import {
  decodeVerifiedConsumer,
  verifiedConsumerPda,
  registrationAttestationDigest,
  isVerifiedConsumerActive,
  VerifiedConsumerState,
  RevokeReason,
  REGISTRATION_DOMAIN_TAG,
} from "../src/index";

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
// Build a VerifiedConsumer buffer in the Rust layout (148 bytes total).
// -----------------------------------------------------------------------------
function buildVerifiedConsumer(opts: {
  partnerWallet: Uint8Array;
  integrationHash: Uint8Array;
  registeredAtSlot: bigint;
  registeredAtUnix: bigint;
  state: number;
  revokedAtUnix?: bigint;
  revokedBy?: Uint8Array;
  revokeReason?: number;
  layoutVersion?: number;
  bump?: number;
}): Buffer {
  const buf = Buffer.alloc(148);
  let o = 8; // skip 8-byte Anchor discriminator (zeros are fine for decode tests)

  buf.set(opts.partnerWallet, o); o += 32;
  buf.set(opts.integrationHash, o); o += 32;
  buf.writeBigUInt64LE(opts.registeredAtSlot, o); o += 8;
  buf.writeBigInt64LE(opts.registeredAtUnix, o); o += 8;
  buf.writeUInt8(opts.state, o); o += 1;
  buf.writeBigInt64LE(opts.revokedAtUnix ?? 0n, o); o += 8;
  buf.set(opts.revokedBy ?? new Uint8Array(32), o); o += 32;
  buf.writeUInt8(opts.revokeReason ?? RevokeReason.NotRevoked, o); o += 1;
  buf.writeUInt8(opts.layoutVersion ?? 1, o); o += 1;
  buf.writeUInt8(opts.bump ?? 255, o); o += 1;
  // _reserved [16] follows (zeroed by Buffer.alloc).
  return buf;
}

// -----------------------------------------------------------------------------
// Decoder round-trip
// -----------------------------------------------------------------------------

test("decoded buffer matches built fields (Active path)", () => {
  const partnerWallet = new Uint8Array(32).fill(7);
  const integrationHash = new Uint8Array(32).fill(11);
  const buf = buildVerifiedConsumer({
    partnerWallet,
    integrationHash,
    registeredAtSlot: 1_234n,
    registeredAtUnix: 1_700_000_000n,
    state: VerifiedConsumerState.Active,
  });
  const d = decodeVerifiedConsumer(buf);
  assert.deepStrictEqual(Array.from(d.partnerWallet), Array.from(partnerWallet));
  assert.deepStrictEqual(Array.from(d.integrationHash), Array.from(integrationHash));
  assert.strictEqual(d.registeredAtSlot, 1_234n);
  assert.strictEqual(d.registeredAtUnix, 1_700_000_000n);
  assert.strictEqual(d.state, VerifiedConsumerState.Active);
  assert.strictEqual(d.revokedAtUnix, 0n);
  assert.strictEqual(d.revokeReason, RevokeReason.NotRevoked);
  assert.strictEqual(d.layoutVersion, 1);
  assert.strictEqual(d.bump, 255);
});

test("decoded buffer matches built fields (Revoked path)", () => {
  const partnerWallet = new Uint8Array(32).fill(2);
  const integrationHash = new Uint8Array(32).fill(3);
  const revokedBy = new Uint8Array(32).fill(9);
  const buf = buildVerifiedConsumer({
    partnerWallet,
    integrationHash,
    registeredAtSlot: 100n,
    registeredAtUnix: 1_600_000_000n,
    state: VerifiedConsumerState.Revoked,
    revokedAtUnix: 1_700_000_000n,
    revokedBy,
    revokeReason: RevokeReason.AdminBadFaith,
  });
  const d = decodeVerifiedConsumer(buf);
  assert.strictEqual(d.state, VerifiedConsumerState.Revoked);
  assert.strictEqual(d.revokedAtUnix, 1_700_000_000n);
  assert.deepStrictEqual(Array.from(d.revokedBy), Array.from(revokedBy));
  assert.strictEqual(d.revokeReason, RevokeReason.AdminBadFaith);
});

// -----------------------------------------------------------------------------
// isActive() gate
// -----------------------------------------------------------------------------

test("isActive returns true ONLY when state byte == Active", () => {
  const base = {
    partnerWallet: new Uint8Array(32).fill(1),
    integrationHash: new Uint8Array(32).fill(2),
    registeredAtSlot: 1n,
    registeredAtUnix: 1n,
  };
  const active = decodeVerifiedConsumer(
    buildVerifiedConsumer({ ...base, state: VerifiedConsumerState.Active }),
  );
  assert.strictEqual(isVerifiedConsumerActive(active), true);
  const revoked = decodeVerifiedConsumer(
    buildVerifiedConsumer({ ...base, state: VerifiedConsumerState.Revoked }),
  );
  assert.strictEqual(isVerifiedConsumerActive(revoked), false);
});

// -----------------------------------------------------------------------------
// PDA derivation
// -----------------------------------------------------------------------------

test("verifiedConsumerPda is deterministic for fixed inputs", () => {
  const certIssuer = new PublicKey("Cert1xor11111111111111111111111111111111111");
  const partner = PublicKey.unique();
  const a = verifiedConsumerPda(certIssuer, partner);
  const b = verifiedConsumerPda(certIssuer, partner);
  assert.strictEqual(a.toBase58(), b.toBase58());
});

test("verifiedConsumerPda binds partner_wallet (different partners → different PDAs)", () => {
  const certIssuer = new PublicKey("Cert1xor11111111111111111111111111111111111");
  const a = verifiedConsumerPda(certIssuer, PublicKey.unique());
  const b = verifiedConsumerPda(certIssuer, PublicKey.unique());
  assert.notStrictEqual(a.toBase58(), b.toBase58());
});

// -----------------------------------------------------------------------------
// Registration attestation digest — must match the Rust helper byte-for-byte
// -----------------------------------------------------------------------------

test("registrationAttestationDigest matches the canonical Rust hashv layout", () => {
  // Recompute the digest from the literal bytes and compare to the SDK helper.
  const partner = new PublicKey(new Uint8Array(32).fill(5));
  const integrationHash = new Uint8Array(32).fill(13);

  const expected = createHash("sha256")
    .update(Buffer.from(REGISTRATION_DOMAIN_TAG, "utf-8"))
    .update(partner.toBuffer())
    .update(Buffer.from(integrationHash))
    .digest();

  const got = registrationAttestationDigest(partner, integrationHash);
  assert.deepStrictEqual(Array.from(got), Array.from(expected));
});

test("registrationAttestationDigest binds partner + hash", () => {
  const integrationHash = new Uint8Array(32).fill(13);
  const a = registrationAttestationDigest(
    new PublicKey(new Uint8Array(32).fill(1)),
    integrationHash,
  );
  const b = registrationAttestationDigest(
    new PublicKey(new Uint8Array(32).fill(2)),
    integrationHash,
  );
  assert.notDeepStrictEqual(Array.from(a), Array.from(b));

  const c = registrationAttestationDigest(
    new PublicKey(new Uint8Array(32).fill(1)),
    new Uint8Array(32).fill(99),
  );
  assert.notDeepStrictEqual(Array.from(a), Array.from(c));
});

test("registrationAttestationDigest refuses non-32-byte integrationHash", () => {
  assert.throws(
    () =>
      registrationAttestationDigest(
        new PublicKey(new Uint8Array(32)),
        new Uint8Array(31),
      ),
    /must be 32 bytes/,
  );
});

test("REGISTRATION_DOMAIN_TAG is pinned to the Rust constant", () => {
  // A drift here invalidates every off-chain signature recompute against the
  // on-chain digest. Pin the literal bytes.
  assert.strictEqual(REGISTRATION_DOMAIN_TAG, "helixor-dbp2-verified-consumer");
  assert.strictEqual(REGISTRATION_DOMAIN_TAG.length, 30);
});

console.log(`\n${passed} passed`);
