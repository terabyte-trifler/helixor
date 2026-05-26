// =============================================================================
// test/decode.test.ts — account-decoder tests.
//
// Runs without a validator: it builds account byte buffers in the EXACT
// layout the Rust #[account] structs produce, decodes them, and asserts the
// round trip. This pins the SDK's byte-layout contract to the on-chain one.
//
// Run: tsx test/decode.test.ts
// =============================================================================

import * as assert from "assert";

import {
  decodeHealthCertificate,
  decodeEpochState,
  CHALLENGE_STATE_NONE,
  CHALLENGE_STATE_UPHELD,
  CHALLENGE_STATE_REJECTED,
} from "../src/decode";

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
// Build a HealthCertificate buffer in the Rust layout
// =============================================================================

function buildHealthCertificate(opts: {
  epoch: number;
  score: number;
  alertTier: number;
  flags: number;
  issuedAt: number;
  immediateRed: boolean;
  layoutVersion?: number;
  signerCount?: number;
  inputCommitment?: Uint8Array;
  slotAnchorSlot?: bigint;
  slotAnchorHash?: Uint8Array;
  challengeState?: number;
}): Buffer {
  // 8 discriminator + 210 data = 218 bytes (HealthCertificate::SPACE v4/v5
  // — challenge_state shares a byte with what used to be _reserved, so the
  // total size is unchanged from v4).
  const buf = Buffer.alloc(218);
  let o = 8; // skip discriminator

  buf.fill(0xaa, o, o + 32); o += 32; // agent_wallet
  buf.writeBigUInt64LE(BigInt(opts.epoch), o); o += 8;
  buf.writeUInt16LE(opts.score, o); o += 2;
  buf.writeUInt8(opts.alertTier, o); o += 1;
  buf.writeUInt32LE(opts.flags, o); o += 4;
  buf.writeBigInt64LE(BigInt(opts.issuedAt), o); o += 8;
  buf.fill(0xbb, o, o + 32); o += 32; // issuer
  buf.fill(0xcc, o, o + 32); o += 32; // baseline_hash
  buf.writeUInt8(opts.immediateRed ? 1 : 0, o); o += 1;
  buf.writeUInt8(254, o); o += 1; // bump
  buf.writeUInt8(opts.layoutVersion ?? 5, o); o += 1; // layout_version
  buf.writeUInt8(opts.signerCount ?? 0, o); o += 1; // signer_count
  if (opts.inputCommitment) {
    Buffer.from(opts.inputCommitment).copy(buf, o);
  }
  o += 32;
  buf.writeBigUInt64LE(opts.slotAnchorSlot ?? 0n, o); o += 8;
  if (opts.slotAnchorHash) {
    Buffer.from(opts.slotAnchorHash).copy(buf, o);
  }
  o += 32;
  // v5: challenge_state (1 byte), then _reserved [14] left zero.
  buf.writeUInt8(opts.challengeState ?? 0, o); o += 1;
  return buf;
}

function buildEpochState(opts: {
  currentEpoch: number;
  lastAdvancedAt: number;
  durationSeconds: number;
}): Buffer {
  // 8 discriminator + 89 data = 97 bytes (EpochState::SPACE)
  const buf = Buffer.alloc(97);
  let o = 8;
  buf.writeBigUInt64LE(BigInt(opts.currentEpoch), o); o += 8;
  buf.writeBigInt64LE(BigInt(opts.lastAdvancedAt), o); o += 8;
  buf.writeBigInt64LE(BigInt(opts.durationSeconds), o); o += 8;
  buf.fill(0xdd, o, o + 32); o += 32; // advance_authority
  buf.writeUInt8(253, o); o += 1; // bump
  return buf;
}

// =============================================================================
// HealthCertificate decode
// =============================================================================

test("decodes a HealthCertificate round trip", () => {
  const buf = buildHealthCertificate({
    epoch: 1,
    score: 916,
    alertTier: 0,
    flags: 0,
    issuedAt: 1_777_000_000,
    immediateRed: false,
    layoutVersion: 1,
  });
  const cert = decodeHealthCertificate(buf);
  assert.strictEqual(cert.epoch, 1);
  assert.strictEqual(cert.score, 916);
  assert.strictEqual(cert.alertTier, 0);
  assert.strictEqual(cert.issuedAt, 1_777_000_000);
  assert.strictEqual(cert.immediateRed, false);
  assert.strictEqual(cert.layoutVersion, 1);
});

test("decodes v4 slot-anchor fields", () => {
  const hash = new Uint8Array(32).fill(0x99);
  const buf = buildHealthCertificate({
    epoch: 851,
    score: 916,
    alertTier: 0,
    flags: 0,
    issuedAt: 1_777_000_000,
    immediateRed: false,
    layoutVersion: 4,
    signerCount: 3,
    inputCommitment: new Uint8Array(32).fill(0xab),
    slotAnchorSlot: 250_000_000n,
    slotAnchorHash: hash,
  });
  const cert = decodeHealthCertificate(buf);
  assert.strictEqual(cert.layoutVersion, 4);
  assert.strictEqual(cert.signerCount, 3);
  assert.strictEqual(cert.slotAnchorSlot, 250_000_000n);
  assert.deepStrictEqual(Buffer.from(cert.slotAnchorHash), Buffer.from(hash));
  assert.deepStrictEqual(
    Buffer.from(cert.inputCommitment),
    Buffer.alloc(32, 0xab),
  );
});

test("decodes v5 challenge_state values", () => {
  for (const state of [
    CHALLENGE_STATE_NONE,
    CHALLENGE_STATE_UPHELD,
    CHALLENGE_STATE_REJECTED,
  ]) {
    const buf = buildHealthCertificate({
      epoch: 9,
      score: 100,
      alertTier: 2,
      flags: 0,
      issuedAt: 1_777_000_000,
      immediateRed: true,
      layoutVersion: 5,
      challengeState: state,
    });
    assert.strictEqual(decodeHealthCertificate(buf).challengeState, state);
  }
});

test("v4 buffer (zero reserved byte) decodes challenge_state as None", () => {
  // The byte is reserved padding in v4; reading it as 0 = None is the
  // backwards-compatible behaviour we rely on for legacy cert buffers.
  const buf = buildHealthCertificate({
    epoch: 9,
    score: 700,
    alertTier: 0,
    flags: 0,
    issuedAt: 1_777_000_000,
    immediateRed: false,
    layoutVersion: 4,
    challengeState: 0,
  });
  assert.strictEqual(
    decodeHealthCertificate(buf).challengeState,
    CHALLENGE_STATE_NONE,
  );
});

test("decodes a pre-v4 (short) buffer with zero-sentinel slot anchor", () => {
  // A v3 cert is only 170+8 = 178 bytes; truncate the v4 buffer to match.
  const v4 = buildHealthCertificate({
    epoch: 1,
    score: 700,
    alertTier: 0,
    flags: 0,
    issuedAt: 1,
    immediateRed: false,
    layoutVersion: 3,
    signerCount: 5,
    inputCommitment: new Uint8Array(32).fill(0xcd),
  });
  const v3 = v4.subarray(0, 178);
  const cert = decodeHealthCertificate(v3);
  assert.strictEqual(cert.layoutVersion, 3);
  assert.strictEqual(cert.slotAnchorSlot, 0n);
  assert.deepStrictEqual(
    Buffer.from(cert.slotAnchorHash),
    Buffer.alloc(32, 0x00),
  );
});

test("decodes immediate_red true", () => {
  const buf = buildHealthCertificate({
    epoch: 5,
    score: 120,
    alertTier: 2,
    flags: 0x08,
    issuedAt: 1_777_100_000,
    immediateRed: true,
  });
  const cert = decodeHealthCertificate(buf);
  assert.strictEqual(cert.immediateRed, true);
  assert.strictEqual(cert.alertTier, 2);
  assert.strictEqual(cert.flags, 0x08);
});

test("decodes the maximum score", () => {
  const buf = buildHealthCertificate({
    epoch: 2,
    score: 1000,
    alertTier: 0,
    flags: 0,
    issuedAt: 1_777_200_000,
    immediateRed: false,
  });
  assert.strictEqual(decodeHealthCertificate(buf).score, 1000);
});

test("decodes 32-byte agent / issuer / baseline_hash slices", () => {
  const buf = buildHealthCertificate({
    epoch: 1, score: 700, alertTier: 0, flags: 0,
    issuedAt: 1, immediateRed: false,
  });
  const cert = decodeHealthCertificate(buf);
  assert.strictEqual(cert.agentWallet.length, 32);
  assert.strictEqual(cert.issuer.length, 32);
  assert.strictEqual(cert.baselineHash.length, 32);
});

// =============================================================================
// EpochState decode
// =============================================================================

test("decodes an EpochState round trip", () => {
  const buf = buildEpochState({
    currentEpoch: 7,
    lastAdvancedAt: 1_777_000_000,
    durationSeconds: 86_400,
  });
  const state = decodeEpochState(buf);
  assert.strictEqual(state.currentEpoch, 7);
  assert.strictEqual(state.lastAdvancedAt, 1_777_000_000);
  assert.strictEqual(state.epochDurationSeconds, 86_400);
  assert.strictEqual(state.advanceAuthority.length, 32);
});

test("decodes epoch 1 (the first epoch)", () => {
  const buf = buildEpochState({
    currentEpoch: 1,
    lastAdvancedAt: 0,
    durationSeconds: 86_400,
  });
  assert.strictEqual(decodeEpochState(buf).currentEpoch, 1);
});

console.log(`\n${passed} decode tests passed`);
