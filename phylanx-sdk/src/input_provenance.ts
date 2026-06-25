// =============================================================================
// phylanx-sdk/src/input_provenance.ts — AW-01 client-side verification.
//
// The architectural fix for AW-01 (Trust Transitivity) extends the on-chain
// HealthCertificate with an `input_commitment`: a 32-byte SHA-256 over the
// canonical scoring inputs the cluster agreed on (transactions, windows,
// baseline_hash, agent_wallet). This module lets a DeFi consumer close the
// loop:
//
//     observed transactions (from an independent indexer)
//        |
//        v
//     computeInputCommitment(...)         <-- this module
//        |
//        v
//     compare to cert.inputCommitment     <-- verifyInputProvenance(...)
//
// If they match, the consumer has cryptographic proof that the score it sees
// was computed over the same inputs the consumer is willing to attest to. If
// they DIFFER, the cluster scored a different set of inputs than what the
// consumer can observe on chain — refuse the score.
//
// BYTE-COMPATIBILITY CONTRACT
// ---------------------------
// The canonical encoding here MUST be byte-identical to:
//   oracle/cluster/input_commitment.py :: compute_input_commitment
//   (the Python primitive every oracle node uses)
//
// Any divergence makes the SDK's recomputed commitment differ from what the
// oracle baked into the cert, and verification will always fail. The
// `test/input_provenance.test.ts` cross-impl test pins the wire format.
// =============================================================================

import { createHash } from "crypto";
import type { DecodedHealthCertificate } from "./decode";

// 32-byte SHA-256 digest output.
export const COMMITMENT_BYTES = 32;

// Schema-version tag — folded into the digest, bumped if the canonical form
// ever changes. Mirrors INPUT_COMMITMENT_VERSION on the Python side.
//
// v1 → v2 (AW-01-EXT): appended a SlotAnchor (8-byte BE slot + 32-byte
// block hash) so the commitment is now bound to a SPECIFIC point in
// Solana's own ledger. An attacker would have to forge Solana's history
// to coax the cluster into committing over inputs from a slot that does
// not exist.
export const INPUT_COMMITMENT_VERSION = 2;

// Canonical-anchor payload contribution: u64 BE slot (8) + 32-byte hash.
export const SLOT_ANCHOR_BYTES = 40;

// =============================================================================
// Public types
// =============================================================================

/**
 * A normalised transaction the consumer can observe. The shape mirrors the
 * Python `features.Transaction` dataclass that the oracle hashes.
 *
 * Times are JS `Date` (ms resolution; the encoder normalises to UTC
 * microseconds), `slot` is a JS `bigint` (Solana slots overflow u32), and
 * all SOL/fee amounts are `bigint` so a consumer never loses precision.
 */
export interface ObservableTransaction {
  signature: string;
  slot: bigint;
  blockTime: Date;
  success: boolean;
  programIds: string[];
  /** Net SOL delta on the agent wallet in lamports (signed). */
  solChange: bigint;
  /** Base fee paid in lamports. */
  fee: bigint;
  /** Priority fee paid in lamports. */
  priorityFee: bigint;
  /** Compute units consumed. */
  computeUnits: bigint;
  /** The single counterparty wallet, if exactly one was observed. */
  counterparty: string | null;
}

/**
 * An extraction window. `start` is inclusive; `end` is exclusive on the
 * oracle side. The consumer just needs to mirror what the oracle was given.
 */
export interface ExtractionWindow {
  start: Date;
  end: Date;
}

/**
 * AW-01-EXT — the Solana `(slot, block_hash)` pair the cluster pinned at
 * scoring time. Folded into the input commitment AND verified by the
 * on-chain handler against the `SlotHashes` sysvar. A consumer can
 * independently re-verify it via `verifyAgainstSolanaLedger`.
 */
export interface SlotAnchor {
  /** The absolute Solana slot number (u64). */
  slot: bigint;
  /** The 32-byte block hash for that slot. */
  blockHash: Uint8Array;
}

/** Inputs to `computeInputCommitment` — the same per-agent input the oracle saw. */
export interface InputCommitmentInputs {
  agentWallet: string;
  baselineWindow: ExtractionWindow;
  currentWindow: ExtractionWindow;
  baselineTransactions: ObservableTransaction[];
  currentTransactions: ObservableTransaction[];
  /** The 32-byte baseline hash bound on chain; the consumer reads it from the cert. */
  baselineHash: Uint8Array;
  /**
   * AW-01-EXT slot anchor (v2+). Required: the cluster always pins a
   * fresh anchor at scoring time; the on-chain handler rejects a
   * zero anchor. Consumers reading from a decoded cert should pass
   * `{ slot: cert.slotAnchorSlot, blockHash: cert.slotAnchorHash }`.
   */
  slotAnchor: SlotAnchor;
}

/** The outcome of `verifyInputProvenance`. */
export type ProvenanceResult =
  | { ok: true; expected: Buffer; recomputed: Buffer }
  | { ok: false; reason: ProvenanceRejection; expected: Buffer | null; recomputed: Buffer };

export enum ProvenanceRejection {
  /** The cert is pre-AW-01 (layout < 3) — no inputCommitment was stored. */
  PreV3Cert = "PRE_V3_CERT",
  /** The cert advertises layout >= 3 but its inputCommitment is the zero sentinel. */
  MissingCommitment = "MISSING_COMMITMENT",
  /** Recomputed commitment != cert.inputCommitment — the inputs do not match. */
  Mismatch = "MISMATCH",
  /** The cert is pre-AW-01-EXT (layout < 4) — no slot anchor stored. */
  PreV4Cert = "PRE_V4_CERT",
  /** The cert's slot anchor is the zero sentinel (slot=0, hash=zeros). */
  MissingSlotAnchor = "MISSING_SLOT_ANCHOR",
}

/** Outcome of `verifyAgainstSolanaLedger`. */
export type SolanaLedgerVerification =
  | { ok: true }
  | { ok: false; reason: LedgerRejection };

export enum LedgerRejection {
  /** The cert is pre-AW-01-EXT (layout < 4) — there is nothing to verify. */
  PreV4Cert = "PRE_V4_CERT",
  /** Cert carries the zero anchor sentinel — never verifiable. */
  MissingSlotAnchor = "MISSING_SLOT_ANCHOR",
  /**
   * The anchor slot is older than the sysvar's ~512-slot window. The cert
   * may still be honest — but the consumer's RPC can no longer prove that
   * Solana ever recorded that slot/hash pair. The consumer must decide its
   * own policy (e.g. accept aged certs that passed at issuance, or refuse).
   */
  AnchorTooOld = "ANCHOR_TOO_OLD",
  /**
   * The slot was found but its hash differs from what the cluster pinned.
   * This is the strong-evidence-of-poisoning case: Solana itself disagrees
   * with the cluster's view of the slot.
   */
  AnchorHashMismatch = "ANCHOR_HASH_MISMATCH",
}

/** Minimal shape of `Connection.getSlotHashes` we depend on — keeps the
 * SDK free of a hard `@solana/web3.js` dependency at the type level. */
export interface SlotHashesProvider {
  getSlotHashes(): Promise<Array<{ slot: number | bigint; hash: string }>>;
}

// =============================================================================
// Canonical encoding — byte-identical to the Python module
// =============================================================================

function encodeStr(value: string): Buffer {
  const encoded = Buffer.from(value, "utf-8");
  if (encoded.length > 0xffff) {
    throw new Error(
      `string field too long for u16 length prefix: ${encoded.length}`
    );
  }
  const prefix = Buffer.alloc(2);
  prefix.writeUInt16BE(encoded.length, 0);
  return Buffer.concat([prefix, encoded]);
}

function encodeOptionalStr(value: string | null): Buffer {
  if (value === null) return Buffer.from([0x00]);
  return Buffer.concat([Buffer.from([0x01]), encodeStr(value)]);
}

function encodeBlockTimeMicros(when: Date): Buffer {
  // i64 big-endian, microseconds since unix epoch. Python uses
  // int(when.timestamp() * 1_000_000). JS Date has ms resolution, so the
  // µs are always a clean multiple of 1000 — but we still emit i64 µs to
  // match the wire format byte-for-byte.
  const micros = BigInt(when.getTime()) * 1000n;
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(micros, 0);
  return buf;
}

function encodeWindow(window: ExtractionWindow): Buffer {
  return Buffer.concat([
    encodeBlockTimeMicros(window.start),
    encodeBlockTimeMicros(window.end),
  ]);
}

function encodeTransaction(tx: ObservableTransaction): Buffer {
  const slot = Buffer.alloc(8);
  slot.writeBigUInt64BE(tx.slot, 0);
  const sol = Buffer.alloc(8);
  sol.writeBigInt64BE(tx.solChange, 0);
  const fee = Buffer.alloc(8);
  fee.writeBigUInt64BE(tx.fee, 0);
  const prio = Buffer.alloc(8);
  prio.writeBigUInt64BE(tx.priorityFee, 0);
  const cu = Buffer.alloc(8);
  cu.writeBigUInt64BE(tx.computeUnits, 0);
  const progCount = Buffer.alloc(2);
  progCount.writeUInt16BE(tx.programIds.length, 0);

  const parts: Buffer[] = [
    encodeStr(tx.signature),
    slot,
    encodeBlockTimeMicros(tx.blockTime),
    Buffer.from([tx.success ? 0x01 : 0x00]),
    progCount,
  ];
  for (const pid of tx.programIds) parts.push(encodeStr(pid));
  parts.push(sol, fee, prio, cu, encodeOptionalStr(tx.counterparty));
  return Buffer.concat(parts);
}

function canonicalTransactions(txs: ObservableTransaction[]): Buffer {
  const ordered = [...txs].sort((a, b) => {
    if (a.slot < b.slot) return -1;
    if (a.slot > b.slot) return 1;
    if (a.signature < b.signature) return -1;
    if (a.signature > b.signature) return 1;
    return 0;
  });
  const count = Buffer.alloc(4);
  count.writeUInt32BE(ordered.length, 0);
  const parts: Buffer[] = [count];
  for (const tx of ordered) {
    const encoded = encodeTransaction(tx);
    const len = Buffer.alloc(4);
    len.writeUInt32BE(encoded.length, 0);
    parts.push(len, encoded);
  }
  return Buffer.concat(parts);
}

// =============================================================================
// Public API
// =============================================================================

function encodeSlotAnchor(anchor: SlotAnchor): Buffer {
  if (anchor.blockHash.length !== 32) {
    throw new Error(
      `slotAnchor.blockHash must be 32 bytes, got ${anchor.blockHash.length}`
    );
  }
  if (anchor.slot < 0n || anchor.slot > 0xffffffffffffffffn) {
    throw new Error(`slotAnchor.slot out of u64 range: ${anchor.slot}`);
  }
  const slot = Buffer.alloc(8);
  slot.writeBigUInt64BE(anchor.slot, 0);
  return Buffer.concat([slot, Buffer.from(anchor.blockHash)]);
}

/**
 * Compute the 32-byte AW-01 input-provenance commitment for one agent's
 * scoring input. Byte-identical to the Python `compute_input_commitment`.
 *
 * v2 (AW-01-EXT) appends a 40-byte slot anchor (8B BE slot + 32B block
 * hash) after the baseline hash. The Python primitive does the same; the
 * cross-impl pin in `test/input_provenance.test.ts` keeps them locked.
 */
export function computeInputCommitment(inputs: InputCommitmentInputs): Buffer {
  if (!inputs.agentWallet) {
    throw new Error("agentWallet must be non-empty");
  }
  if (inputs.baselineHash.length !== 32) {
    throw new Error(
      `baselineHash must be 32 bytes, got ${inputs.baselineHash.length}`
    );
  }
  if (!inputs.slotAnchor) {
    throw new Error("slotAnchor is required (AW-01-EXT)");
  }

  const version = Buffer.alloc(2);
  version.writeUInt16BE(INPUT_COMMITMENT_VERSION, 0);

  const payload = Buffer.concat([
    version,
    encodeStr(inputs.agentWallet),
    encodeWindow(inputs.baselineWindow),
    encodeWindow(inputs.currentWindow),
    canonicalTransactions(inputs.baselineTransactions),
    canonicalTransactions(inputs.currentTransactions),
    Buffer.from(inputs.baselineHash),
    encodeSlotAnchor(inputs.slotAnchor),     // AW-01-EXT (40 bytes)
  ]);
  return createHash("sha256").update(payload).digest();
}

/**
 * Verify that a decoded HealthCertificate's `inputCommitment` matches the
 * commitment the consumer recomputes from its observable inputs. THE AW-01
 * close-the-loop check: if it fails, the cluster scored a different set of
 * inputs than what the consumer sees, and the score must not be trusted.
 *
 * Pre-v3 certs (layoutVersion < 3) carry zeros where the commitment used to
 * be reserved bytes. They are reported as `PreV3Cert` so consumers can
 * choose to fall back to the V2 trust model rather than reject outright.
 */
export function verifyInputProvenance(
  cert: DecodedHealthCertificate,
  inputs: InputCommitmentInputs
): ProvenanceResult {
  const recomputed = computeInputCommitment(inputs);
  const expected = Buffer.from(cert.inputCommitment);

  if (cert.layoutVersion < 3) {
    return {
      ok: false,
      reason: ProvenanceRejection.PreV3Cert,
      expected: null,
      recomputed,
    };
  }
  if (cert.layoutVersion < 4) {
    // v3 certs carry an inputCommitment computed with the v1 (pre-anchor)
    // canonical form. A v2 recomputation will never match — report the
    // pre-v4 reason so the consumer can choose its own fallback policy
    // rather than mistake this for a real mismatch.
    return {
      ok: false,
      reason: ProvenanceRejection.PreV4Cert,
      expected,
      recomputed,
    };
  }
  if (isAllZero(expected)) {
    return {
      ok: false,
      reason: ProvenanceRejection.MissingCommitment,
      expected,
      recomputed,
    };
  }
  if (
    cert.slotAnchorSlot === 0n &&
    isAllZero(Buffer.from(cert.slotAnchorHash))
  ) {
    return {
      ok: false,
      reason: ProvenanceRejection.MissingSlotAnchor,
      expected,
      recomputed,
    };
  }
  if (!constantTimeEqual(expected, recomputed)) {
    return {
      ok: false,
      reason: ProvenanceRejection.Mismatch,
      expected,
      recomputed,
    };
  }
  return { ok: true, expected, recomputed };
}

/**
 * AW-01-EXT — verify the cert's slot anchor against Solana's own ledger.
 *
 * The on-chain handler verifies the same anchor against the `SlotHashes`
 * sysvar at cert-issue time. This helper lets a consumer (long after
 * issuance, on a different RPC) re-run that check: Solana itself confirms
 * that the slot the cluster pinned existed and had the hash the cluster
 * claimed.
 *
 * The sysvar window is ~512 slots (~3.4 minutes). For certs older than
 * that, the consumer must either trust the on-chain verification done at
 * issuance OR be passed a `SlotHashesProvider` backed by an archive node.
 *
 * Pure async. Never throws — every rejection is returned as a
 * `LedgerRejection` reason for the consumer to decide.
 */
export async function verifyAgainstSolanaLedger(
  cert: DecodedHealthCertificate,
  provider: SlotHashesProvider,
): Promise<SolanaLedgerVerification> {
  if (cert.layoutVersion < 4) {
    return { ok: false, reason: LedgerRejection.PreV4Cert };
  }
  if (
    cert.slotAnchorSlot === 0n &&
    isAllZero(Buffer.from(cert.slotAnchorHash))
  ) {
    return { ok: false, reason: LedgerRejection.MissingSlotAnchor };
  }

  const entries = await provider.getSlotHashes();
  let oldestSeen: bigint | null = null;
  for (const entry of entries) {
    const entrySlot =
      typeof entry.slot === "bigint" ? entry.slot : BigInt(entry.slot);
    if (oldestSeen === null || entrySlot < oldestSeen) oldestSeen = entrySlot;

    if (entrySlot === cert.slotAnchorSlot) {
      const onChain = decodeBase58Hash(entry.hash);
      if (constantTimeEqual(
        Buffer.from(onChain),
        Buffer.from(cert.slotAnchorHash),
      )) {
        return { ok: true };
      }
      return { ok: false, reason: LedgerRejection.AnchorHashMismatch };
    }
  }

  // Not found. If the anchor is older than the oldest entry the sysvar
  // window has rolled past it; otherwise it is in the future / unknown —
  // both collapse to AnchorTooOld for the consumer-facing reason.
  return { ok: false, reason: LedgerRejection.AnchorTooOld };
}

/**
 * Solana `Hash` is a base58-encoded 32-byte SHA-256. Decode without
 * pulling in `bs58` — small inline implementation. Throws on invalid
 * input; callers above only pass strings from the RPC.
 */
function decodeBase58Hash(value: string): Uint8Array {
  const ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const BASE = 58n;
  let acc = 0n;
  for (const ch of value) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base58 char: ${ch}`);
    acc = acc * BASE + BigInt(idx);
  }
  // Convert to big-endian bytes.
  const out: number[] = [];
  while (acc > 0n) {
    out.unshift(Number(acc & 0xffn));
    acc >>= 8n;
  }
  // Preserve leading-zero bytes from leading '1's in the input.
  for (const ch of value) {
    if (ch !== "1") break;
    out.unshift(0);
  }
  if (out.length !== 32) {
    throw new Error(
      `decoded hash must be 32 bytes, got ${out.length} (value ${value})`
    );
  }
  return Uint8Array.from(out);
}

function isAllZero(b: Buffer): boolean {
  for (let i = 0; i < b.length; i++) if (b[i] !== 0) return false;
  return true;
}

function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
