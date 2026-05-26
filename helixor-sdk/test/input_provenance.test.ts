// =============================================================================
// test/input_provenance.test.ts — AW-01 SDK cross-impl verification.
//
// Pins the SDK's `computeInputCommitment` to byte-identical output with the
// Python `oracle.cluster.input_commitment.compute_input_commitment`. The
// fixed-hex digest below was produced by the Python implementation; if the
// two ever diverge, this test fails and the SDK's verifier would silently
// reject every honest cert.
//
// Run: tsx test/input_provenance.test.ts
// =============================================================================

import * as assert from "assert";

import {
  computeInputCommitment,
  verifyInputProvenance,
  verifyAgainstSolanaLedger,
  ProvenanceRejection,
  LedgerRejection,
  COMMITMENT_BYTES,
  type ObservableTransaction,
  type InputCommitmentInputs,
  type SlotHashesProvider,
} from "../src/input_provenance";
import type { DecodedHealthCertificate } from "../src/decode";

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
// Fixture builders mirroring the Python script that generated EXPECTED_HEX
// =============================================================================

function mkTx(
  slot: bigint,
  signature: string,
  opts: { success?: boolean; counterparty?: string | null } = {}
): ObservableTransaction {
  return {
    signature,
    slot,
    blockTime: new Date(Date.UTC(2026, 4, 1, 12, 0, 0)), // 2026-05-01 12:00 UTC
    success: opts.success ?? true,
    programIds: ["Jupiter"],
    solChange: -1234n,
    fee: 5000n,
    priorityFee: 1000n,
    computeUnits: 200000n,
    counterparty: opts.counterparty ?? null,
  };
}

function fixtureInputs(): InputCommitmentInputs {
  return {
    agentWallet: "AGENTwallet000000000000000",
    baselineWindow: {
      start: new Date(Date.UTC(2026, 3, 1, 0, 0, 0)), // 2026-04-01
      end: new Date(Date.UTC(2026, 4, 1, 0, 0, 0)),   // 2026-05-01
    },
    currentWindow: {
      start: new Date(Date.UTC(2026, 4, 1, 0, 0, 0)),
      end: new Date(Date.UTC(2026, 4, 2, 0, 0, 0)),
    },
    baselineTransactions: [
      mkTx(100n, "sigA"),
      mkTx(101n, "sigB", { counterparty: "cp1" }),
    ],
    currentTransactions: [mkTx(200n, "sigC", { success: false })],
    baselineHash: new Uint8Array(32).fill(0xab),
    // AW-01-EXT: matches the SlotAnchor in /tmp/gen_aw01ext_pin.py
    slotAnchor: {
      slot: 250_000_000n,
      blockHash: new Uint8Array(32).fill(0x99),
    },
  };
}

// =============================================================================
// CROSS-IMPL PIN — SDK output must equal the Python reference
// =============================================================================

// AW-01-EXT (v2) pin. Regenerated via /tmp/gen_aw01ext_pin.py against the
// Python `oracle.cluster.input_commitment.compute_input_commitment` with the
// same fixture (incl. SlotAnchor(slot=250_000_000, hash=0x99...0x99)).
// If this drifts, the SDK and the cluster have diverged and consumer
// verification will reject every honest cert.
const EXPECTED_HEX =
  "6ec6ada2cf7921c98989f3e1ebef8f3a5b6b95c4b75c0586dfe41e3110b2a813";

test("computeInputCommitment matches the Python implementation byte-for-byte", () => {
  const out = computeInputCommitment(fixtureInputs());
  assert.strictEqual(out.length, COMMITMENT_BYTES);
  assert.strictEqual(out.toString("hex"), EXPECTED_HEX);
});

test("transaction order does not change the commitment", () => {
  const inputs = fixtureInputs();
  const reordered: InputCommitmentInputs = {
    ...inputs,
    baselineTransactions: [...inputs.baselineTransactions].reverse(),
  };
  assert.strictEqual(
    computeInputCommitment(reordered).toString("hex"),
    EXPECTED_HEX
  );
});

test("changing the agent wallet changes the commitment", () => {
  const inputs = fixtureInputs();
  const a = computeInputCommitment(inputs);
  const b = computeInputCommitment({ ...inputs, agentWallet: "DIFFERENT" });
  assert.notStrictEqual(a.toString("hex"), b.toString("hex"));
});

test("changing the baseline hash changes the commitment", () => {
  const inputs = fixtureInputs();
  const b = computeInputCommitment({
    ...inputs,
    baselineHash: new Uint8Array(32).fill(0xcd),
  });
  assert.notStrictEqual(b.toString("hex"), EXPECTED_HEX);
});

test("rejects baseline hash of wrong length", () => {
  const inputs = fixtureInputs();
  assert.throws(
    () => computeInputCommitment({ ...inputs, baselineHash: new Uint8Array(7) }),
    /baselineHash must be 32 bytes/
  );
});

test("rejects empty agent wallet", () => {
  const inputs = fixtureInputs();
  assert.throws(
    () => computeInputCommitment({ ...inputs, agentWallet: "" }),
    /agentWallet must be non-empty/
  );
});

// =============================================================================
// verifyInputProvenance — three-way outcome
// =============================================================================

function fakeCert(opts: {
  layoutVersion: number;
  inputCommitment: Uint8Array;
  slotAnchorSlot?: bigint;
  slotAnchorHash?: Uint8Array;
}): DecodedHealthCertificate {
  return {
    agentWallet: new Uint8Array(32),
    epoch: 1,
    score: 916,
    alertTier: 0,
    flags: 0,
    issuedAt: 1_777_000_000,
    issuer: new Uint8Array(32),
    baselineHash: new Uint8Array(32),
    immediateRed: false,
    bump: 255,
    layoutVersion: opts.layoutVersion,
    signerCount: 5,
    inputCommitment: opts.inputCommitment,
    slotAnchorSlot: opts.slotAnchorSlot ?? 0n,
    slotAnchorHash: opts.slotAnchorHash ?? new Uint8Array(32),
  };
}

test("verify succeeds when the recomputed commitment matches the cert", () => {
  const inputs = fixtureInputs();
  const expected = computeInputCommitment(inputs);
  const cert = fakeCert({
    layoutVersion: 4,
    inputCommitment: expected,
    slotAnchorSlot: inputs.slotAnchor.slot,
    slotAnchorHash: inputs.slotAnchor.blockHash,
  });
  const r = verifyInputProvenance(cert, inputs);
  assert.strictEqual(r.ok, true);
});

test("verify rejects a mismatched commitment", () => {
  const inputs = fixtureInputs();
  const cert = fakeCert({
    layoutVersion: 4,
    inputCommitment: new Uint8Array(32).fill(0xff),
    slotAnchorSlot: inputs.slotAnchor.slot,
    slotAnchorHash: inputs.slotAnchor.blockHash,
  });
  const r = verifyInputProvenance(cert, inputs);
  assert.strictEqual(r.ok, false);
  if (!r.ok) assert.strictEqual(r.reason, ProvenanceRejection.Mismatch);
});

test("verify reports PreV3Cert for a pre-AW-01 layout", () => {
  const inputs = fixtureInputs();
  const cert = fakeCert({
    layoutVersion: 2,
    inputCommitment: new Uint8Array(32),
  });
  const r = verifyInputProvenance(cert, inputs);
  assert.strictEqual(r.ok, false);
  if (!r.ok) assert.strictEqual(r.reason, ProvenanceRejection.PreV3Cert);
});

test("verify reports PreV4Cert for a v3 (pre-anchor) cert", () => {
  const inputs = fixtureInputs();
  const cert = fakeCert({
    layoutVersion: 3,
    inputCommitment: new Uint8Array(32).fill(0xab),
  });
  const r = verifyInputProvenance(cert, inputs);
  assert.strictEqual(r.ok, false);
  if (!r.ok) assert.strictEqual(r.reason, ProvenanceRejection.PreV4Cert);
});

test("verify reports MissingCommitment when v4 cert carries zero commitment", () => {
  const inputs = fixtureInputs();
  const cert = fakeCert({
    layoutVersion: 4,
    inputCommitment: new Uint8Array(32),
    slotAnchorSlot: inputs.slotAnchor.slot,
    slotAnchorHash: inputs.slotAnchor.blockHash,
  });
  const r = verifyInputProvenance(cert, inputs);
  assert.strictEqual(r.ok, false);
  if (!r.ok) assert.strictEqual(r.reason, ProvenanceRejection.MissingCommitment);
});

test("verify reports MissingSlotAnchor when v4 cert carries zero anchor", () => {
  const inputs = fixtureInputs();
  const expected = computeInputCommitment(inputs);
  const cert = fakeCert({
    layoutVersion: 4,
    inputCommitment: expected,
    // anchor fields default to zero
  });
  const r = verifyInputProvenance(cert, inputs);
  assert.strictEqual(r.ok, false);
  if (!r.ok) assert.strictEqual(r.reason, ProvenanceRejection.MissingSlotAnchor);
});

// =============================================================================
// verifyAgainstSolanaLedger — AW-01-EXT close-the-loop check
// =============================================================================

const BASE58 =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function encodeBase58(bytes: Uint8Array): string {
  // Tiny encoder for fixtures — mirrors decodeBase58Hash in src/.
  let acc = 0n;
  for (const b of bytes) acc = acc * 256n + BigInt(b);
  let out = "";
  while (acc > 0n) {
    out = BASE58[Number(acc % 58n)] + out;
    acc /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out || "1";
}

function mkProvider(
  entries: Array<{ slot: bigint; hash: Uint8Array }>,
): SlotHashesProvider {
  return {
    async getSlotHashes() {
      return entries.map(e => ({ slot: e.slot, hash: encodeBase58(e.hash) }));
    },
  };
}

(async () => {
  await (async function ledger_ok() {
    const hash = new Uint8Array(32).fill(0x99);
    const cert = fakeCert({
      layoutVersion: 4,
      inputCommitment: new Uint8Array(32).fill(0xab),
      slotAnchorSlot: 250_000_000n,
      slotAnchorHash: hash,
    });
    const provider = mkProvider([
      { slot: 250_000_001n, hash: new Uint8Array(32).fill(0x42) },
      { slot: 250_000_000n, hash },
    ]);
    const r = await verifyAgainstSolanaLedger(cert, provider);
    if (!r.ok) throw new Error(`expected ok, got ${JSON.stringify(r)}`);
    passed++;
    console.log("  ok  verifyAgainstSolanaLedger accepts matching anchor");
  })();

  await (async function ledger_hash_mismatch() {
    const cert = fakeCert({
      layoutVersion: 4,
      inputCommitment: new Uint8Array(32).fill(0xab),
      slotAnchorSlot: 250_000_000n,
      slotAnchorHash: new Uint8Array(32).fill(0x99),
    });
    const provider = mkProvider([
      { slot: 250_000_000n, hash: new Uint8Array(32).fill(0x88) },
    ]);
    const r = await verifyAgainstSolanaLedger(cert, provider);
    if (r.ok || r.reason !== LedgerRejection.AnchorHashMismatch) {
      throw new Error(`expected AnchorHashMismatch, got ${JSON.stringify(r)}`);
    }
    passed++;
    console.log("  ok  verifyAgainstSolanaLedger flags hash mismatch");
  })();

  await (async function ledger_too_old() {
    const cert = fakeCert({
      layoutVersion: 4,
      inputCommitment: new Uint8Array(32).fill(0xab),
      slotAnchorSlot: 250_000_000n,
      slotAnchorHash: new Uint8Array(32).fill(0x99),
    });
    const provider = mkProvider([
      { slot: 250_001_000n, hash: new Uint8Array(32).fill(0x12) },
    ]);
    const r = await verifyAgainstSolanaLedger(cert, provider);
    if (r.ok || r.reason !== LedgerRejection.AnchorTooOld) {
      throw new Error(`expected AnchorTooOld, got ${JSON.stringify(r)}`);
    }
    passed++;
    console.log("  ok  verifyAgainstSolanaLedger flags missing slot as too-old");
  })();

  await (async function ledger_missing_anchor() {
    const cert = fakeCert({
      layoutVersion: 4,
      inputCommitment: new Uint8Array(32).fill(0xab),
    });
    const r = await verifyAgainstSolanaLedger(cert, mkProvider([]));
    if (r.ok || r.reason !== LedgerRejection.MissingSlotAnchor) {
      throw new Error(`expected MissingSlotAnchor, got ${JSON.stringify(r)}`);
    }
    passed++;
    console.log("  ok  verifyAgainstSolanaLedger flags zero anchor as missing");
  })();

  await (async function ledger_pre_v4() {
    const cert = fakeCert({
      layoutVersion: 3,
      inputCommitment: new Uint8Array(32).fill(0xab),
    });
    const r = await verifyAgainstSolanaLedger(cert, mkProvider([]));
    if (r.ok || r.reason !== LedgerRejection.PreV4Cert) {
      throw new Error(`expected PreV4Cert, got ${JSON.stringify(r)}`);
    }
    passed++;
    console.log("  ok  verifyAgainstSolanaLedger short-circuits on pre-v4 cert");
  })();

  console.log(`\n${passed} input_provenance tests passed`);
})();
