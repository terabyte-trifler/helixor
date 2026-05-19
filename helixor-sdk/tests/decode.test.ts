// =============================================================================
// test/decode.test.ts — account-decoder tests.
//
// Runs without a validator: it builds account byte buffers in the EXACT
// layout the Rust #[account] structs produce, decodes them, and asserts the
// round trip. This pins the SDK's byte-layout contract to the on-chain one.
//
// Run: tsx test/decode.test.ts
// =============================================================================

import { describe, expect, it } from "vitest";

import {
  decodeHealthCertificate,
  decodeEpochState,
} from "../src/decode";

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
}): Buffer {
  // 8 discriminator + 170 data = 178 bytes (HealthCertificate::SPACE)
  const buf = Buffer.alloc(178);
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
  buf.writeUInt8(1, o); o += 1; // layout_version
  // _reserved [48] left zero
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

describe("account decoders", () => {
  it("decodes a HealthCertificate round trip", () => {
    const buf = buildHealthCertificate({
      epoch: 1,
      score: 916,
      alertTier: 0,
      flags: 0,
      issuedAt: 1_777_000_000,
      immediateRed: false,
    });
    const cert = decodeHealthCertificate(buf);
    expect(cert.epoch).toBe(1);
    expect(cert.score).toBe(916);
    expect(cert.alertTier).toBe(0);
    expect(cert.issuedAt).toBe(1_777_000_000);
    expect(cert.immediateRed).toBe(false);
    expect(cert.layoutVersion).toBe(1);
  });

  it("decodes immediate_red true", () => {
    const buf = buildHealthCertificate({
      epoch: 5,
      score: 120,
      alertTier: 2,
      flags: 0x08,
      issuedAt: 1_777_100_000,
      immediateRed: true,
    });
    const cert = decodeHealthCertificate(buf);
    expect(cert.immediateRed).toBe(true);
    expect(cert.alertTier).toBe(2);
    expect(cert.flags).toBe(0x08);
  });

  it("decodes the maximum score", () => {
    const buf = buildHealthCertificate({
      epoch: 2,
      score: 1000,
      alertTier: 0,
      flags: 0,
      issuedAt: 1_777_200_000,
      immediateRed: false,
    });
    expect(decodeHealthCertificate(buf).score).toBe(1000);
  });

  it("decodes 32-byte agent / issuer / baseline_hash slices", () => {
    const buf = buildHealthCertificate({
      epoch: 1, score: 700, alertTier: 0, flags: 0,
      issuedAt: 1, immediateRed: false,
    });
    const cert = decodeHealthCertificate(buf);
    expect(cert.agentWallet.length).toBe(32);
    expect(cert.issuer.length).toBe(32);
    expect(cert.baselineHash.length).toBe(32);
  });

  it("decodes an EpochState round trip", () => {
    const buf = buildEpochState({
      currentEpoch: 7,
      lastAdvancedAt: 1_777_000_000,
      durationSeconds: 86_400,
    });
    const state = decodeEpochState(buf);
    expect(state.currentEpoch).toBe(7);
    expect(state.lastAdvancedAt).toBe(1_777_000_000);
    expect(state.epochDurationSeconds).toBe(86_400);
    expect(state.advanceAuthority.length).toBe(32);
  });

  it("decodes epoch 1 (the first epoch)", () => {
    const buf = buildEpochState({
      currentEpoch: 1,
      lastAdvancedAt: 0,
      durationSeconds: 86_400,
    });
    expect(decodeEpochState(buf).currentEpoch).toBe(1);
  });
});
