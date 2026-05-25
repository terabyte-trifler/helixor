// =============================================================================
// test/safe_reader.test.ts — VULN-23 SafeCertReader contract tests.
//
// Tests use a hand-rolled mock ChainReader so they run without a validator.
// Every guard rail branch (ok / stale / velocity / insufficient / no-current)
// has an explicit pin so a future regression that loosens the wrapper
// fails CI.
//
// Run: tsx test/safe_reader.test.ts
// =============================================================================

import * as assert from "assert";
import { PublicKey } from "@solana/web3.js";

import { AlertTier, type EpochScore } from "../src/types";
import {
  SafeCertReader,
  RejectReason,
  CERT_MAX_AGE_SECONDS,
  MAX_SCORE_VELOCITY,
  VELOCITY_WINDOW_EPOCHS,
  MIN_HISTORY_REQUIRED,
  type ChainReader,
  type SafeScoreOk,
  type SafeScoreRejected,
} from "../src/safe_reader";

let passed = 0;
function test(name: string, fn: () => void | Promise<void>): void {
  const run = async () => {
    try {
      await fn();
      passed++;
      console.log(`  ok  ${name}`);
    } catch (err) {
      console.error(`FAIL  ${name}`);
      console.error(err);
      process.exitCode = 1;
    }
  };
  // Tests are sequential — we await the chain by chaining promises.
  pending.push(run);
}

const pending: Array<() => Promise<void>> = [];


// =============================================================================
// Mock ChainReader
// =============================================================================

const AGENT = new PublicKey("11111111111111111111111111111112");
const NOW = 1_777_000_000;

function mkCert(epoch: number, score: number, opts: {
  alert?: AlertTier;
  issuedAt?: number;
  immediateRed?: boolean;
} = {}): EpochScore {
  return {
    agent: AGENT,
    epoch,
    score,
    alert: opts.alert ?? AlertTier.Green,
    flags: 0,
    issuedAt: opts.issuedAt ?? (NOW - 3600), // 1h old by default
    immediateRed: opts.immediateRed ?? false,
  };
}

class MockChain implements ChainReader {
  constructor(
    private readonly currentEpoch: number,
    private readonly history: EpochScore[]
  ) {}

  async getCurrentEpoch(): Promise<number> {
    return this.currentEpoch;
  }

  async getScoreHistory(
    _agent: PublicKey,
    fromEpoch: number,
    toEpoch: number
  ): Promise<EpochScore[]> {
    return this.history.filter(
      (c) => c.epoch >= fromEpoch && c.epoch <= toEpoch
    );
  }
}

function reader(chain: ChainReader, nowOverride: number = NOW): SafeCertReader {
  return new SafeCertReader(chain, { nowSeconds: () => nowOverride });
}

function expectOk(r: any): asserts r is SafeScoreOk {
  if (!r.ok) {
    throw new Error(`expected ok, got reject: ${r.reason} — ${r.detail}`);
  }
}

function expectReject(
  r: any,
  reason: RejectReason
): asserts r is SafeScoreRejected {
  if (r.ok) {
    throw new Error(`expected reject ${reason}, got ok: score=${r.score}`);
  }
  if (r.reason !== reason) {
    throw new Error(
      `expected reject ${reason}, got ${r.reason} — ${r.detail}`
    );
  }
}


// =============================================================================
// Constants pin — the audit values must not drift silently
// =============================================================================

test("constants match the audit mandate", () => {
  assert.strictEqual(CERT_MAX_AGE_SECONDS, 48 * 60 * 60,
    "CERT_MAX_AGE_SECONDS must stay at 48h — audit mandate");
  assert.strictEqual(MAX_SCORE_VELOCITY, 200,
    "MAX_SCORE_VELOCITY must match the off-chain per-epoch clamp (200)");
  assert.strictEqual(VELOCITY_WINDOW_EPOCHS, 3,
    "VELOCITY_WINDOW_EPOCHS must stay at 3");
  assert.strictEqual(MIN_HISTORY_REQUIRED, 2,
    "MIN_HISTORY_REQUIRED must stay at 2");
});


// =============================================================================
// Happy path
// =============================================================================

test("ok: fresh cert, flat scores in window", async () => {
  const chain = new MockChain(10, [
    mkCert(8, 700),
    mkCert(9, 720),
    mkCert(10, 730, { issuedAt: NOW - 60 }),
  ]);
  const r = await reader(chain).getSafeScore(AGENT);
  expectOk(r);
  assert.strictEqual(r.score, 730);
  assert.strictEqual(r.epoch, 10);
  assert.strictEqual(r.alert, AlertTier.Green);
  assert.strictEqual(r.velocityWindow.minScore, 700);
  assert.strictEqual(r.velocityWindow.maxScore, 730);
  assert.deepStrictEqual(r.velocityWindow.epochs, [8, 9, 10]);
});

test("ok: velocity exactly at the limit (200) is allowed", async () => {
  const chain = new MockChain(10, [
    mkCert(8, 500),
    mkCert(9, 600),
    mkCert(10, 700, { issuedAt: NOW - 60 }),
  ]);
  const r = await reader(chain).getSafeScore(AGENT);
  expectOk(r);
  assert.strictEqual(r.velocityWindow.maxScore - r.velocityWindow.minScore, 200);
});

test("ok: cert exactly at the freshness limit is allowed", async () => {
  const issuedAt = NOW - CERT_MAX_AGE_SECONDS; // exactly 48h
  const chain = new MockChain(10, [
    mkCert(9, 700),
    mkCert(10, 710, { issuedAt }),
  ]);
  const r = await reader(chain).getSafeScore(AGENT);
  expectOk(r);
  assert.strictEqual(r.issuedAt, issuedAt);
});


// =============================================================================
// STALE_CERT
// =============================================================================

test("reject STALE_CERT: cert one second past the limit", async () => {
  const issuedAt = NOW - CERT_MAX_AGE_SECONDS - 1;
  const chain = new MockChain(10, [
    mkCert(9, 700),
    mkCert(10, 710, { issuedAt }),
  ]);
  const r = await reader(chain).getSafeScore(AGENT);
  expectReject(r, RejectReason.StaleCert);
  assert.ok(r.detail.includes(String(issuedAt)));
});

test("reject STALE_CERT: a week-old cert", async () => {
  const chain = new MockChain(10, [
    mkCert(9, 700),
    mkCert(10, 710, { issuedAt: NOW - 7 * 24 * 3600 }),
  ]);
  const r = await reader(chain).getSafeScore(AGENT);
  expectReject(r, RejectReason.StaleCert);
});


// =============================================================================
// VELOCITY_EXCEEDED
// =============================================================================

test("reject VELOCITY_EXCEEDED: pump from 300 to 700 in 3 epochs", async () => {
  const chain = new MockChain(10, [
    mkCert(8, 300),
    mkCert(9, 500),
    mkCert(10, 700, { issuedAt: NOW - 60 }),
  ]);
  const r = await reader(chain).getSafeScore(AGENT);
  expectReject(r, RejectReason.VelocityExceeded);
  assert.ok(r.detail.includes("400"), `detail should mention swing: ${r.detail}`);
});

test("reject VELOCITY_EXCEEDED: drop from 900 to 600", async () => {
  const chain = new MockChain(10, [
    mkCert(8, 900),
    mkCert(10, 600, { issuedAt: NOW - 60 }),
  ]);
  const r = await reader(chain).getSafeScore(AGENT);
  expectReject(r, RejectReason.VelocityExceeded);
});

test("reject VELOCITY_EXCEEDED: one point over (201) trips", async () => {
  const chain = new MockChain(10, [
    mkCert(9, 500),
    mkCert(10, 701, { issuedAt: NOW - 60 }),
  ]);
  const r = await reader(chain).getSafeScore(AGENT);
  expectReject(r, RejectReason.VelocityExceeded);
});


// =============================================================================
// INSUFFICIENT_HISTORY
// =============================================================================

test("reject INSUFFICIENT_HISTORY: brand-new agent with one cert", async () => {
  const chain = new MockChain(10, [
    mkCert(10, 700, { issuedAt: NOW - 60 }),
  ]);
  const r = await reader(chain).getSafeScore(AGENT);
  expectReject(r, RejectReason.InsufficientHistory);
});

test("reject INSUFFICIENT_HISTORY: empty history", async () => {
  const chain = new MockChain(10, []);
  const r = await reader(chain).getSafeScore(AGENT);
  expectReject(r, RejectReason.InsufficientHistory);
});


// =============================================================================
// NO_CURRENT_CERT
// =============================================================================

test("reject NO_CURRENT_CERT: latest is older epoch", async () => {
  // history present in older epochs but the live epoch (10) has no cert
  const chain = new MockChain(10, [
    mkCert(8, 700),
    mkCert(9, 710),
  ]);
  const r = await reader(chain).getSafeScore(AGENT);
  expectReject(r, RejectReason.NoCurrentCert);
  assert.ok(r.detail.includes("epoch 9"), `detail mentions newest: ${r.detail}`);
});


// =============================================================================
// Ordering robustness — getScoreHistory promises sparse, not sorted
// =============================================================================

test("sorts unsorted history correctly", async () => {
  const chain = new MockChain(10, [
    mkCert(10, 730, { issuedAt: NOW - 60 }),
    mkCert(8, 700),
    mkCert(9, 720),
  ]);
  const r = await reader(chain).getSafeScore(AGENT);
  expectOk(r);
  assert.strictEqual(r.epoch, 10);
  assert.strictEqual(r.score, 730);
});


// =============================================================================
// Option overrides — every constant must be overridable for tests + opt-ins
// =============================================================================

test("opts: stricter maxAgeSeconds enforces tighter freshness", async () => {
  const chain = new MockChain(10, [
    mkCert(9, 700),
    mkCert(10, 710, { issuedAt: NOW - 3700 }), // ~1h old
  ]);
  const strict = new SafeCertReader(chain, {
    nowSeconds: () => NOW,
    maxAgeSeconds: 3600, // 1h ceiling
  });
  const r = await strict.getSafeScore(AGENT);
  expectReject(r, RejectReason.StaleCert);
});

test("opts: stricter maxVelocity enforces tighter swing", async () => {
  const chain = new MockChain(10, [
    mkCert(9, 700),
    mkCert(10, 750, { issuedAt: NOW - 60 }),
  ]);
  const strict = new SafeCertReader(chain, {
    nowSeconds: () => NOW,
    maxVelocity: 25,
  });
  const r = await strict.getSafeScore(AGENT);
  expectReject(r, RejectReason.VelocityExceeded);
});

test("opts: windowEpochs < MIN_HISTORY_REQUIRED is refused at construction", () => {
  const chain = new MockChain(10, []);
  assert.throws(
    () => new SafeCertReader(chain, { windowEpochs: 1 }),
    /windowEpochs/
  );
});

test("opts: maxAgeSeconds must be positive", () => {
  const chain = new MockChain(10, []);
  assert.throws(
    () => new SafeCertReader(chain, { maxAgeSeconds: 0 }),
    /maxAgeSeconds/
  );
});


// =============================================================================
// Early-epoch boundary — window must not go negative
// =============================================================================

test("early-epoch boundary: currentEpoch=1 doesn't crash", async () => {
  // window would be -1..1, but we clamp fromEpoch to 0
  const chain = new MockChain(1, [
    mkCert(0, 700),
    mkCert(1, 720, { issuedAt: NOW - 60 }),
  ]);
  const r = await reader(chain).getSafeScore(AGENT);
  expectOk(r);
});


// =============================================================================
// Run sequentially
// =============================================================================

(async () => {
  for (const t of pending) await t();
  console.log(`\n${passed} SafeCertReader tests passed`);
})();
