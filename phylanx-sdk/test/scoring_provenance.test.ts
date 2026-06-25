// =============================================================================
// test/scoring_provenance.test.ts — AW-04 SDK-side verifier tests.
//
// Runs without a validator: constructs the EXACT byte layouts of a v7
// HealthCertificate + a ScoreComponentsAccount, stubs a `Connection`
// that returns the fake account, and asserts the verifier accepts the OK
// path and refuses every defined failure mode.
//
// Run: tsx test/scoring_provenance.test.ts
// =============================================================================

import * as assert from "assert";
import { createHash } from "crypto";
import { PublicKey } from "@solana/web3.js";

import {
  decodeHealthCertificate,
  decodeScoreComponentsAccount,
} from "../src/decode";
import {
  verifyScoreComputation,
  verifyScoringCodeHash,
  replayScoreFromComponents,
  parseScoreComponentsPayload,
  sha256ComponentsPayload,
  ScoringProvenanceRejection,
  CodeHashCheckResult,
  MAX_SCORE_DELTA,
  SCORE_COMPONENTS_SCHEMA_VERSION,
  type ParsedScoreComponents,
} from "../src/scoring_provenance";
import { scoreComponentsPda } from "../src/pdas";

let passed = 0;
function test(name: string, fn: () => Promise<void> | void): void {
  const p = (async () => fn())();
  p.then(
    () => {
      passed++;
      console.log(`  ok  ${name}`);
    },
    (err) => {
      console.error(`FAIL  ${name}`);
      console.error(err);
      process.exitCode = 1;
    }
  );
}

// =============================================================================
// Byte layouts — v7 HealthCertificate + ScoreComponentsAccount
// =============================================================================

function buildHealthCertificateV7Buf(opts: {
  agentWallet: Uint8Array;
  epoch: bigint;
  score: number;
  scoringCodeHash: Uint8Array;
}): Buffer {
  // v7 = 8 discriminator + 242 data = 250 bytes total.
  const buf = Buffer.alloc(250);
  let o = 8;
  Buffer.from(opts.agentWallet).copy(buf, o); o += 32;
  buf.writeBigUInt64LE(opts.epoch, o); o += 8;
  buf.writeUInt16LE(opts.score, o); o += 2;
  buf.writeUInt8(0, o); o += 1;                              // alert_tier
  buf.writeUInt32LE(0, o); o += 4;                           // flags
  buf.writeBigInt64LE(1_777_000_000n, o); o += 8;            // issued_at
  buf.fill(0xbb, o, o + 32); o += 32;                        // issuer
  buf.fill(0xcc, o, o + 32); o += 32;                        // baseline_hash
  buf.writeUInt8(0, o); o += 1;                              // immediate_red
  buf.writeUInt8(254, o); o += 1;                            // bump
  buf.writeUInt8(7, o); o += 1;                              // layout_version (v7)
  buf.writeUInt8(3, o); o += 1;                              // signer_count
  buf.fill(0xdd, o, o + 32); o += 32;                        // input_commitment
  buf.writeBigUInt64LE(123n, o); o += 8;                     // slot_anchor_slot
  buf.fill(0xee, o, o + 32); o += 32;                        // slot_anchor_hash
  buf.writeUInt8(0, o); o += 1;                              // challenge_state
  buf.writeBigUInt64LE(7n, o); o += 8;                       // baseline_commit_nonce
  Buffer.from(opts.scoringCodeHash).copy(buf, o); o += 32;   // scoring_code_hash (v7)
  // _reserved [6] follows — zeros from Buffer.alloc.
  return buf;
}

function buildScoreComponentsAccountBuf(opts: {
  agentWallet: Uint8Array;
  epoch: bigint;
  payload: Buffer | Uint8Array;
  /** If undefined, the on-chain hash is computed from `payload` (OK path).
   *  Pass a different value to simulate tampering. */
  componentsHash?: Uint8Array;
}): Buffer {
  const fixedLen = 32 + 8 + 32 + 8 + 4 + 1 + 1 + 16; // = 102
  const buf = Buffer.alloc(8 + fixedLen + opts.payload.length);
  let o = 8;
  Buffer.from(opts.agentWallet).copy(buf, o); o += 32;
  buf.writeBigUInt64LE(opts.epoch, o); o += 8;
  const hash =
    opts.componentsHash ??
    new Uint8Array(createHash("sha256").update(opts.payload).digest());
  Buffer.from(hash).copy(buf, o); o += 32;
  buf.writeBigInt64LE(1_777_000_000n, o); o += 8;            // computed_at
  buf.writeUInt32LE(opts.payload.length, o); o += 4;
  Buffer.from(opts.payload).copy(buf, o); o += opts.payload.length;
  buf.writeUInt8(254, o); o += 1;                            // bump
  buf.writeUInt8(1, o); o += 1;                              // layout_version
  // _reserved [16] follows — zeros from Buffer.alloc.
  return buf;
}

function makeCanonicalPayload(opts: {
  contribs: number[]; // five dims in order: drift, anomaly, performance, consistency, security
  score: number;
  previousScore: number | null;
  deltaClamped?: boolean;
}): Buffer {
  const dimIds = ["drift", "anomaly", "performance", "consistency", "security"];
  const rawScore = opts.contribs.reduce((a, b) => a + b, 0);
  const dims = dimIds.map((id, i) => ({
    algo_v: 1,
    contrib: opts.contribs[i],
    flags: 0,
    id,
    norm: "0.000000000",
  }));
  const payload = {
    agg_flags: 0,
    algo_v: 2,
    alert: "GREEN",
    confidence: 800,
    delta_clamped: !!opts.deltaClamped,
    dims,
    gaming: false,
    gaming_drop: "0.000000000",
    immediate_red: false,
    previous_score: opts.previousScore,
    raw_score: rawScore,
    score: opts.score,
    v: SCORE_COMPONENTS_SCHEMA_VERSION,
    weights_v: 1,
  };
  // Byte-canonical form (sorted keys, no whitespace) isn't required for
  // the SDK contract — the parser uses JSON.parse — but exercising the
  // shape the Python serializer emits keeps the tests honest.
  return Buffer.from(JSON.stringify(payload), "utf-8");
}

// =============================================================================
// Stub connection
// =============================================================================

function makeStubConnection(
  accounts: Map<string, Buffer>
): {
  conn: { getAccountInfo: (pda: PublicKey) => Promise<{ data: Buffer } | null> };
} {
  return {
    conn: {
      async getAccountInfo(pda: PublicKey) {
        const b = accounts.get(pda.toBase58());
        if (b === undefined) return null;
        return { data: b };
      },
    },
  };
}

// =============================================================================
// Pure helpers
// =============================================================================

test("sha256ComponentsPayload matches Node createHash", () => {
  const payload = Buffer.from("hello world", "utf-8");
  const expected = createHash("sha256").update(payload).digest();
  assert.deepStrictEqual(
    Buffer.from(sha256ComponentsPayload(payload)),
    expected
  );
});

test("parseScoreComponentsPayload extracts all required fields", () => {
  const payload = makeCanonicalPayload({
    contribs: [200, 150, 150, 100, 100],
    score: 700,
    previousScore: 650,
  });
  const parsed = parseScoreComponentsPayload(payload);
  assert.strictEqual(parsed.v, 1);
  assert.strictEqual(parsed.score, 700);
  assert.strictEqual(parsed.rawScore, 700);
  assert.strictEqual(parsed.previousScore, 650);
  assert.strictEqual(parsed.dims.length, 5);
  assert.strictEqual(parsed.dims[0].id, "drift");
  assert.strictEqual(parsed.dims[0].contrib, 200);
});

test("parseScoreComponentsPayload rejects missing field", () => {
  const broken = Buffer.from('{"v":1}', "utf-8");
  assert.throws(() => parseScoreComponentsPayload(broken), /missing field/);
});

test("parseScoreComponentsPayload accepts previous_score=null", () => {
  const payload = makeCanonicalPayload({
    contribs: [100, 100, 100, 100, 100],
    score: 500,
    previousScore: null,
  });
  const parsed = parseScoreComponentsPayload(payload);
  assert.strictEqual(parsed.previousScore, null);
});

// =============================================================================
// replayScoreFromComponents — the formula tests
// =============================================================================

function parsedFor(opts: {
  contribs: number[];
  score: number;
  previousScore: number | null;
  deltaClamped?: boolean;
}): ParsedScoreComponents {
  return parseScoreComponentsPayload(makeCanonicalPayload(opts));
}

test("replay: no previous score, sum within range, no clamp", () => {
  const parsed = parsedFor({
    contribs: [200, 150, 150, 100, 100],
    score: 700,
    previousScore: null,
  });
  const replay = replayScoreFromComponents(parsed);
  assert.strictEqual(replay.rawScore, 700);
  assert.strictEqual(replay.scoreAfterClamp, 700);
  assert.strictEqual(replay.deltaClamped, false);
  assert.strictEqual(replay.finalScore, 700);
});

test("replay: sum > 1000 clamps to 1000", () => {
  const parsed = parsedFor({
    contribs: [500, 500, 500, 500, 500], // 2500
    score: 1000,
    previousScore: null,
  });
  const replay = replayScoreFromComponents(parsed);
  assert.strictEqual(replay.rawScore, 2500);
  assert.strictEqual(replay.scoreAfterClamp, 1000);
  assert.strictEqual(replay.finalScore, 1000);
});

test("replay: sum < 0 clamps to 0", () => {
  const parsed = parsedFor({
    contribs: [-100, -50, -50, 0, 0],
    score: 0,
    previousScore: null,
  });
  const replay = replayScoreFromComponents(parsed);
  assert.strictEqual(replay.rawScore, -200);
  assert.strictEqual(replay.scoreAfterClamp, 0);
  assert.strictEqual(replay.finalScore, 0);
});

test("replay: positive delta beyond 200 is guard-clamped", () => {
  // sum -> 900; previous = 500; raw delta = +400; guard clamps to prev+200 = 700.
  const parsed = parsedFor({
    contribs: [200, 200, 200, 200, 100],
    score: 700,
    previousScore: 500,
    deltaClamped: true,
  });
  const replay = replayScoreFromComponents(parsed);
  assert.strictEqual(replay.scoreAfterClamp, 900);
  assert.strictEqual(replay.deltaClamped, true);
  assert.strictEqual(replay.finalScore, 700);
});

test("replay: negative delta beyond -200 is guard-clamped", () => {
  // sum -> 200; previous = 800; raw delta = -600; guard clamps to prev-200 = 600.
  const parsed = parsedFor({
    contribs: [50, 50, 50, 25, 25],
    score: 600,
    previousScore: 800,
    deltaClamped: true,
  });
  const replay = replayScoreFromComponents(parsed);
  assert.strictEqual(replay.scoreAfterClamp, 200);
  assert.strictEqual(replay.deltaClamped, true);
  assert.strictEqual(replay.finalScore, 600);
});

test("replay: delta exactly +MAX_SCORE_DELTA is NOT clamped", () => {
  // sum -> 700; previous = 500; raw delta = +200 (not strictly > 200).
  const parsed = parsedFor({
    contribs: [200, 150, 150, 100, 100],
    score: 700,
    previousScore: 500,
  });
  const replay = replayScoreFromComponents(parsed);
  assert.strictEqual(replay.scoreAfterClamp, 700);
  assert.strictEqual(replay.deltaClamped, false);
  assert.strictEqual(replay.finalScore, 700);
  assert.strictEqual(MAX_SCORE_DELTA, 200);
});

// =============================================================================
// verifyScoreComputation — the AW-04 contract
// =============================================================================

const CERT_ISSUER = new PublicKey("11111111111111111111111111111112");
const AGENT_BYTES = new Uint8Array(32).fill(0xa1);
const AGENT = new PublicKey(AGENT_BYTES);
const SCORING_CODE_HASH = new Uint8Array(32).fill(0xbb);
const EPOCH = 42n;

function setupHappyPath(opts?: {
  contribs?: number[];
  score?: number;
  previousScore?: number | null;
}) {
  const contribs = opts?.contribs ?? [200, 150, 150, 100, 100];
  const score = opts?.score ?? 700;
  const previousScore = opts?.previousScore ?? null;

  const payload = makeCanonicalPayload({ contribs, score, previousScore });
  const certBuf = buildHealthCertificateV7Buf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    score,
    scoringCodeHash: SCORING_CODE_HASH,
  });
  const cert = decodeHealthCertificate(certBuf);

  const pda = scoreComponentsPda(CERT_ISSUER, AGENT, EPOCH);
  const accountBuf = buildScoreComponentsAccountBuf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    payload,
  });
  return { cert, pda, accountBuf, payload };
}

test("OK path: matching components account verifies", async () => {
  const { cert, pda, accountBuf } = setupHappyPath();
  const accounts = new Map<string, Buffer>([[pda.toBase58(), accountBuf]]);
  const { conn } = makeStubConnection(accounts);

  const result = await verifyScoreComputation(conn as any, CERT_ISSUER, cert);
  assert.strictEqual(result.ok, true);
  if (result.ok) {
    assert.strictEqual(result.replay.finalScore, 700);
    assert.strictEqual(result.parsed.score, 700);
  }
});

test("refuses pre-AW-04 cert (scoringCodeHash all zero)", async () => {
  const certBuf = buildHealthCertificateV7Buf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    score: 700,
    scoringCodeHash: new Uint8Array(32),
  });
  const cert = decodeHealthCertificate(certBuf);
  const { conn } = makeStubConnection(new Map());

  const result = await verifyScoreComputation(conn as any, CERT_ISSUER, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(
      result.reason,
      ScoringProvenanceRejection.NoComponentsAccount
    );
  }
});

test("refuses pre-v7 cert (layoutVersion < 7)", async () => {
  // Build the v7 buffer but flip layout_version back to 6 — the verifier
  // must trust the layout marker even when bytes are present.
  const certBuf = buildHealthCertificateV7Buf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    score: 700,
    scoringCodeHash: SCORING_CODE_HASH,
  });
  // layout_version sits at offset 8 + 32+8+2+1+4+8+32+32+1+1 = 129.
  certBuf.writeUInt8(6, 129);
  const cert = decodeHealthCertificate(certBuf);
  const { conn } = makeStubConnection(new Map());

  const result = await verifyScoreComputation(conn as any, CERT_ISSUER, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(
      result.reason,
      ScoringProvenanceRejection.NoComponentsAccount
    );
  }
});

test("refuses when components account is missing on chain", async () => {
  const { cert } = setupHappyPath();
  const { conn } = makeStubConnection(new Map());

  const result = await verifyScoreComputation(conn as any, CERT_ISSUER, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(
      result.reason,
      ScoringProvenanceRejection.AccountNotFound
    );
  }
});

test("refuses when account decoder rejects buffer", async () => {
  const { cert, pda } = setupHappyPath();
  const accounts = new Map<string, Buffer>([
    [pda.toBase58(), Buffer.alloc(20)],
  ]);
  const { conn } = makeStubConnection(accounts);

  const result = await verifyScoreComputation(conn as any, CERT_ISSUER, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(
      result.reason,
      ScoringProvenanceRejection.AccountUnreadable
    );
  }
});

test("refuses when sha256(payload) does not match componentsHash", async () => {
  const { cert, pda, payload } = setupHappyPath();
  // Same PDA but declare a tampered components_hash.
  const tampered = buildScoreComponentsAccountBuf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    payload,
    componentsHash: new Uint8Array(32).fill(0x77),
  });
  const accounts = new Map<string, Buffer>([[pda.toBase58(), tampered]]);
  const { conn } = makeStubConnection(accounts);

  const result = await verifyScoreComputation(conn as any, CERT_ISSUER, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(
      result.reason,
      ScoringProvenanceRejection.HashMismatch
    );
  }
});

test("refuses when components account is for a different agent", async () => {
  const { cert, pda, payload } = setupHappyPath();
  const wrongAgent = new Uint8Array(32).fill(0xff);
  const wrongBuf = buildScoreComponentsAccountBuf({
    agentWallet: wrongAgent,
    epoch: EPOCH,
    payload,
  });
  const accounts = new Map<string, Buffer>([[pda.toBase58(), wrongBuf]]);
  const { conn } = makeStubConnection(accounts);

  const result = await verifyScoreComputation(conn as any, CERT_ISSUER, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(
      result.reason,
      ScoringProvenanceRejection.AgentMismatch
    );
  }
});

test("refuses when components account epoch disagrees with cert", async () => {
  const { cert, pda, payload } = setupHappyPath();
  const wrongBuf = buildScoreComponentsAccountBuf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH + 1n,
    payload,
  });
  const accounts = new Map<string, Buffer>([[pda.toBase58(), wrongBuf]]);
  const { conn } = makeStubConnection(accounts);

  const result = await verifyScoreComputation(conn as any, CERT_ISSUER, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(
      result.reason,
      ScoringProvenanceRejection.EpochMismatch
    );
  }
});

test("refuses when canonical-JSON payload is malformed", async () => {
  const { cert, pda } = setupHappyPath();
  const garbage = Buffer.from('{"v":1,"oops":"no required fields"}', "utf-8");
  const buf = buildScoreComponentsAccountBuf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    payload: garbage,
  });
  const accounts = new Map<string, Buffer>([[pda.toBase58(), buf]]);
  const { conn } = makeStubConnection(accounts);

  const result = await verifyScoreComputation(conn as any, CERT_ISSUER, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(
      result.reason,
      ScoringProvenanceRejection.PayloadMalformed
    );
  }
});

test("refuses unsupported schema version", async () => {
  const { cert, pda } = setupHappyPath();
  // A full payload but with v=99 — the schema sentinel check must catch it.
  const futurePayload = makeCanonicalPayload({
    contribs: [200, 150, 150, 100, 100],
    score: 700,
    previousScore: null,
  });
  const obj = JSON.parse(futurePayload.toString("utf-8")) as Record<string, unknown>;
  obj["v"] = 99;
  const futureBytes = Buffer.from(JSON.stringify(obj), "utf-8");
  const buf = buildScoreComponentsAccountBuf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    payload: futureBytes,
  });
  const accounts = new Map<string, Buffer>([[pda.toBase58(), buf]]);
  const { conn } = makeStubConnection(accounts);

  const result = await verifyScoreComputation(conn as any, CERT_ISSUER, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(
      result.reason,
      ScoringProvenanceRejection.PayloadMalformed
    );
  }
});

test("refuses when replay disagrees with cert.score (the AW-04 catch)", async () => {
  // The cluster publishes score=999 on the cert but only 700 in the
  // payload. Replay arrives at 700 — refuse.
  const payload = makeCanonicalPayload({
    contribs: [200, 150, 150, 100, 100],
    score: 700,
    previousScore: null,
  });
  const certBuf = buildHealthCertificateV7Buf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    score: 999, // <-- the lie
    scoringCodeHash: SCORING_CODE_HASH,
  });
  const cert = decodeHealthCertificate(certBuf);
  const pda = scoreComponentsPda(CERT_ISSUER, AGENT, EPOCH);
  const buf = buildScoreComponentsAccountBuf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    payload,
  });
  const accounts = new Map<string, Buffer>([[pda.toBase58(), buf]]);
  const { conn } = makeStubConnection(accounts);

  const result = await verifyScoreComputation(conn as any, CERT_ISSUER, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(
      result.reason,
      ScoringProvenanceRejection.ScoreReplayMismatch
    );
  }
});

test("refuses when payload.delta_clamped disagrees with replay", async () => {
  // Build a payload that DOES NOT need the guard rail, but flips
  // delta_clamped=true. The replay's deltaClamped=false will catch it.
  const goodPayload = makeCanonicalPayload({
    contribs: [200, 150, 150, 100, 100],
    score: 700,
    previousScore: 650,
    deltaClamped: true,
  });
  const certBuf = buildHealthCertificateV7Buf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    score: 700,
    scoringCodeHash: SCORING_CODE_HASH,
  });
  const cert = decodeHealthCertificate(certBuf);
  const pda = scoreComponentsPda(CERT_ISSUER, AGENT, EPOCH);
  const buf = buildScoreComponentsAccountBuf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    payload: goodPayload,
  });
  const accounts = new Map<string, Buffer>([[pda.toBase58(), buf]]);
  const { conn } = makeStubConnection(accounts);

  const result = await verifyScoreComputation(conn as any, CERT_ISSUER, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(
      result.reason,
      ScoringProvenanceRejection.ScoreReplayMismatch
    );
  }
});

// =============================================================================
// verifyScoringCodeHash — the second-leg check
// =============================================================================

test("verifyScoringCodeHash OK when expectedHash matches cert", () => {
  const certBuf = buildHealthCertificateV7Buf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    score: 700,
    scoringCodeHash: SCORING_CODE_HASH,
  });
  const cert = decodeHealthCertificate(certBuf);
  const r = verifyScoringCodeHash(cert, SCORING_CODE_HASH);
  assert.strictEqual(r.result, CodeHashCheckResult.Ok);
});

test("verifyScoringCodeHash reports Mismatch on different hash", () => {
  const certBuf = buildHealthCertificateV7Buf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    score: 700,
    scoringCodeHash: SCORING_CODE_HASH,
  });
  const cert = decodeHealthCertificate(certBuf);
  const r = verifyScoringCodeHash(cert, new Uint8Array(32).fill(0x44));
  assert.strictEqual(r.result, CodeHashCheckResult.Mismatch);
});

test("verifyScoringCodeHash reports PreV7Cert on zero hash", () => {
  const certBuf = buildHealthCertificateV7Buf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    score: 700,
    scoringCodeHash: new Uint8Array(32),
  });
  const cert = decodeHealthCertificate(certBuf);
  const r = verifyScoringCodeHash(cert, new Uint8Array(32).fill(0xbb));
  assert.strictEqual(r.result, CodeHashCheckResult.PreV7Cert);
});

test("verifyScoringCodeHash throws on wrong-length expectedHash", () => {
  const certBuf = buildHealthCertificateV7Buf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    score: 700,
    scoringCodeHash: SCORING_CODE_HASH,
  });
  const cert = decodeHealthCertificate(certBuf);
  assert.throws(
    () => verifyScoringCodeHash(cert, new Uint8Array(16)),
    /must be exactly 32 bytes/
  );
});

// =============================================================================
// decode/PDA sanity
// =============================================================================

test("decodeScoreComponentsAccount round-trips an account buffer", () => {
  const payload = makeCanonicalPayload({
    contribs: [200, 150, 150, 100, 100],
    score: 700,
    previousScore: null,
  });
  const buf = buildScoreComponentsAccountBuf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    payload,
  });
  const decoded = decodeScoreComponentsAccount(buf);
  assert.strictEqual(decoded.epoch, EPOCH);
  assert.strictEqual(decoded.bump, 254);
  assert.strictEqual(decoded.layoutVersion, 1);
  assert.deepStrictEqual(Buffer.from(decoded.payload), Buffer.from(payload));
});

test("decodeHealthCertificate v7 surfaces scoringCodeHash", () => {
  const certBuf = buildHealthCertificateV7Buf({
    agentWallet: AGENT_BYTES,
    epoch: EPOCH,
    score: 700,
    scoringCodeHash: SCORING_CODE_HASH,
  });
  const cert = decodeHealthCertificate(certBuf);
  assert.strictEqual(cert.layoutVersion, 7);
  assert.deepStrictEqual(
    Buffer.from(cert.scoringCodeHash),
    Buffer.from(SCORING_CODE_HASH)
  );
});

process.on("beforeExit", () => {
  console.log(`\n${passed} scoring_provenance tests ran`);
});
