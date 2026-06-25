// =============================================================================
// test/baseline_provenance.test.ts — AW-03 SDK-side verifier tests.
//
// Runs without a validator: it constructs the EXACT byte layouts of a
// HealthCertificate + a BaselineDataAccount, stubs a `Connection` that
// returns the fake account, and asserts the verifier accepts the OK path
// and refuses every defined failure mode.
//
// Run: tsx test/baseline_provenance.test.ts
// =============================================================================

import * as assert from "assert";
import { createHash } from "crypto";
import { PublicKey } from "@solana/web3.js";

import {
  decodeHealthCertificate,
  decodeBaselineDataAccount,
} from "../src/decode";
import {
  verifyBaselineProvenance,
  sha256Payload,
  decodeBaselinePayload,
  BaselineProvenanceRejection,
} from "../src/baseline_provenance";
import { baselineDataPda } from "../src/pdas";

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
// Byte layouts (mirror the Rust #[account] structs)
// =============================================================================

function buildHealthCertificateBuf(opts: {
  agentWallet: Uint8Array;
  baselineHash: Uint8Array;
  baselineCommitNonce: bigint;
}): Buffer {
  const buf = Buffer.alloc(218); // discriminator + 210 data
  let o = 8;
  Buffer.from(opts.agentWallet).copy(buf, o); o += 32;
  buf.writeBigUInt64LE(1n, o); o += 8;                      // epoch
  buf.writeUInt16LE(700, o); o += 2;                         // score
  buf.writeUInt8(0, o); o += 1;                              // alert_tier
  buf.writeUInt32LE(0, o); o += 4;                           // flags
  buf.writeBigInt64LE(1_777_000_000n, o); o += 8;            // issued_at
  buf.fill(0xbb, o, o + 32); o += 32;                        // issuer
  Buffer.from(opts.baselineHash).copy(buf, o); o += 32;      // baseline_hash
  buf.writeUInt8(0, o); o += 1;                              // immediate_red
  buf.writeUInt8(254, o); o += 1;                            // bump
  buf.writeUInt8(6, o); o += 1;                              // layout_version (v6)
  buf.writeUInt8(3, o); o += 1;                              // signer_count
  o += 32;                                                   // input_commitment
  buf.writeBigUInt64LE(0n, o); o += 8;                       // slot_anchor_slot
  o += 32;                                                   // slot_anchor_hash
  buf.writeUInt8(0, o); o += 1;                              // challenge_state
  buf.writeBigUInt64LE(opts.baselineCommitNonce, o); o += 8; // baseline_commit_nonce (v6)
  return buf;
}

function buildBaselineDataAccountBuf(opts: {
  agentWallet: Uint8Array;
  commitNonce: bigint;
  baselineHash: Uint8Array;
  payload: Buffer | Uint8Array;
}): Buffer {
  const fixedLen = 32 + 8 + 32 + 1 + 8 + 32 + 4 + 1 + 1 + 16;
  const buf = Buffer.alloc(8 + fixedLen + opts.payload.length);
  let o = 8;
  Buffer.from(opts.agentWallet).copy(buf, o); o += 32;
  buf.writeBigUInt64LE(opts.commitNonce, o); o += 8;
  Buffer.from(opts.baselineHash).copy(buf, o); o += 32;
  buf.writeUInt8(3, o); o += 1;                              // baseline_algo_version
  buf.writeBigInt64LE(1_777_000_000n, o); o += 8;            // committed_at
  buf.fill(0xee, o, o + 32); o += 32;                        // committer
  buf.writeUInt32LE(opts.payload.length, o); o += 4;
  Buffer.from(opts.payload).copy(buf, o); o += opts.payload.length;
  buf.writeUInt8(254, o); o += 1;                            // bump
  buf.writeUInt8(1, o); o += 1;                              // layout_version
  return buf;
}

// =============================================================================
// Stub connection — implements the slice of Connection the verifier uses
// =============================================================================

function makeStubConnection(
  accounts: Map<string, Buffer>
): {
  conn: { getAccountInfo: (pda: PublicKey) => Promise<{ data: Buffer } | null> };
} {
  const conn = {
    async getAccountInfo(pda: PublicKey) {
      const b = accounts.get(pda.toBase58());
      if (b === undefined) return null;
      return { data: b };
    },
  };
  return { conn };
}

// =============================================================================
// Pure-helper tests
// =============================================================================

test("sha256Payload matches Node createHash", () => {
  const payload = Buffer.from("hello world", "utf-8");
  const expected = createHash("sha256").update(payload).digest();
  assert.deepStrictEqual(Buffer.from(sha256Payload(payload)), expected);
});

test("decodeBaselinePayload parses canonical JSON", () => {
  const json = JSON.stringify({
    v: 3,
    schema_fp: "abc",
    means: ["0.100000000", "0.200000000"],
    stds: ["0.010000000"],
    txtype_dist: ["0.500000000", "0.500000000"],
    action_entropy: "0.950000000",
    success_rate_30d: "0.880000000",
    daily_success_rate_series: ["0.950000000"],
  });
  const parsed = decodeBaselinePayload(Buffer.from(json, "utf-8"));
  assert.strictEqual(parsed.v, 3);
  assert.strictEqual(parsed.means.length, 2);
  assert.strictEqual(parsed.means[0], "0.100000000");
});

// =============================================================================
// verifyBaselineProvenance — the AW-03 contract
// =============================================================================

const HEALTH_ORACLE = new PublicKey("11111111111111111111111111111112");

function setupHappyPath(opts?: { payload?: string; nonce?: bigint }) {
  const payload = Buffer.from(
    opts?.payload ?? '{"v":3,"schema_fp":"deadbeef","means":["0.100000000"]}',
    "utf-8"
  );
  const baselineHash = createHash("sha256").update(payload).digest();

  // Deterministic agent pubkey — must round-trip through PublicKey.
  const agentSeed = new Uint8Array(32).fill(0xa1);
  const agent = new PublicKey(agentSeed);
  const nonce = opts?.nonce ?? 7n;

  const certBuf = buildHealthCertificateBuf({
    agentWallet: agent.toBytes(),
    baselineHash,
    baselineCommitNonce: nonce,
  });
  const cert = decodeHealthCertificate(certBuf);

  const daPda = baselineDataPda(HEALTH_ORACLE, agent, nonce);
  const daBuf = buildBaselineDataAccountBuf({
    agentWallet: agent.toBytes(),
    commitNonce: nonce,
    baselineHash: new Uint8Array(baselineHash),
    payload,
  });
  return { cert, daPda, daBuf, payload, baselineHash };
}

test("OK path: matching DA account verifies", async () => {
  const { cert, daPda, daBuf, payload } = setupHappyPath();
  const accounts = new Map<string, Buffer>([[daPda.toBase58(), daBuf]]);
  const { conn } = makeStubConnection(accounts);

  const result = await verifyBaselineProvenance(conn as any, HEALTH_ORACLE, cert);
  assert.strictEqual(result.ok, true);
  if (result.ok) {
    assert.strictEqual(result.dataAccount.commitNonce, 7n);
    assert.deepStrictEqual(
      Buffer.from(result.dataAccount.payload),
      Buffer.from(payload)
    );
  }
});

test("refuses pre-AW-03 cert (nonce == 0)", async () => {
  const { cert } = setupHappyPath({ nonce: 0n });
  const { conn } = makeStubConnection(new Map());

  const result = await verifyBaselineProvenance(conn as any, HEALTH_ORACLE, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(result.reason, BaselineProvenanceRejection.NoDataAccount);
  }
});

test("refuses when DA account is missing on chain", async () => {
  const { cert } = setupHappyPath();
  const { conn } = makeStubConnection(new Map());

  const result = await verifyBaselineProvenance(conn as any, HEALTH_ORACLE, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(result.reason, BaselineProvenanceRejection.AccountNotFound);
  }
});

test("refuses when account decoder rejects buffer", async () => {
  const { cert, daPda } = setupHappyPath();
  // 20 bytes — well under the fixed-field minimum.
  const accounts = new Map<string, Buffer>([[daPda.toBase58(), Buffer.alloc(20)]]);
  const { conn } = makeStubConnection(accounts);

  const result = await verifyBaselineProvenance(conn as any, HEALTH_ORACLE, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(result.reason, BaselineProvenanceRejection.AccountUnreadable);
  }
});

test("refuses when sha256(payload) does not match cert.baselineHash", async () => {
  const { cert, daPda } = setupHappyPath();
  // Build a DA account with the SAME nonce/agent but a DIFFERENT payload —
  // so its sha256 will not match the cert's baselineHash.
  const evilPayload = Buffer.from("evil-substituted-payload", "utf-8");
  const evilBuf = buildBaselineDataAccountBuf({
    agentWallet: cert.agentWallet,
    commitNonce: cert.baselineCommitNonce,
    baselineHash: cert.baselineHash, // declare the cert's hash on the account...
    payload: evilPayload,             // ...but ship a different payload
  });
  const accounts = new Map<string, Buffer>([[daPda.toBase58(), evilBuf]]);
  const { conn } = makeStubConnection(accounts);

  const result = await verifyBaselineProvenance(conn as any, HEALTH_ORACLE, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(result.reason, BaselineProvenanceRejection.HashMismatch);
  }
});

test("refuses when DA account is for a different agent", async () => {
  const { cert, daPda, payload, baselineHash } = setupHappyPath();
  // Same PDA address, but the bytes claim a different agent_wallet.
  const wrongAgent = new Uint8Array(32).fill(0xff);
  const wrongBuf = buildBaselineDataAccountBuf({
    agentWallet: wrongAgent,
    commitNonce: cert.baselineCommitNonce,
    baselineHash: new Uint8Array(baselineHash),
    payload,
  });
  const accounts = new Map<string, Buffer>([[daPda.toBase58(), wrongBuf]]);
  const { conn } = makeStubConnection(accounts);

  const result = await verifyBaselineProvenance(conn as any, HEALTH_ORACLE, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(result.reason, BaselineProvenanceRejection.AgentMismatch);
  }
});

test("refuses when DA account commit_nonce disagrees with cert", async () => {
  const { cert, daPda, payload, baselineHash } = setupHappyPath();
  const wrongBuf = buildBaselineDataAccountBuf({
    agentWallet: cert.agentWallet,
    commitNonce: cert.baselineCommitNonce + 1n, // off-by-one
    baselineHash: new Uint8Array(baselineHash),
    payload,
  });
  const accounts = new Map<string, Buffer>([[daPda.toBase58(), wrongBuf]]);
  const { conn } = makeStubConnection(accounts);

  const result = await verifyBaselineProvenance(conn as any, HEALTH_ORACLE, cert);
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(result.reason, BaselineProvenanceRejection.NonceMismatch);
  }
});

// Wait for the async tests to settle before printing the summary.
process.on("beforeExit", () => {
  console.log(`\n${passed} baseline_provenance tests ran`);
});
