// =============================================================================
// helixor-sdk/src/advance_epoch.ts — AW-02 client helpers for the
// M-of-N-attested epoch-advance flow.
//
// The on-chain `advance_epoch` instruction (health-oracle program) now
// requires a cluster supermajority of Ed25519 precompile signatures over the
// canonical advance digest. Cluster operators compute the digest off-chain
// IDENTICALLY to the on-chain `advance_payload_digest` function and sign
// with their cluster key. This module exposes that digest so off-chain
// signers stay bit-for-bit compatible with the on-chain verifier.
//
// SHAPE NOTE
// ----------
// We deliberately do NOT export a "build full advance_epoch transaction"
// helper here — cluster operators have wildly different signer setups
// (KMS, Squads, raw keypairs, HSMs, ...) and bundling that choice into
// the SDK would force unwanted couplings. What every signer DOES share
// is: "compute the canonical digest, sign it, attach a standard Ed25519
// program instruction to the tx, then call advance_epoch in the same tx".
// The first step is what this module standardises.
//
// The Ed25519-instruction shape itself is the standard Solana
// `Ed25519Program.createInstructionWithPrivateKey` (web3.js) or the
// equivalent HSM-friendly variants — the byte layout is fixed by Solana,
// not by Helixor, so we do not redefine it.
// =============================================================================

import { createHash } from "node:crypto";

/**
 * Domain-separation tag for the advance-epoch digest. Must match the on-chain
 * `ADVANCE_EPOCH_DOMAIN_TAG` constant byte-for-byte.
 *
 * Distinct from the cert-signing tag (`helixor-cert-v1`) and the challenge
 * tag (`helixor-aw01-ext-challenge`) — this prevents an honest cluster
 * signature on any other protocol payload from being lifted into an
 * advance-epoch attestation.
 */
export const ADVANCE_EPOCH_DOMAIN_TAG: Buffer = Buffer.from(
  "helixor-epoch-advance",
  "utf-8",
);

/**
 * Compute the 32-byte canonical advance-epoch digest. Bit-for-bit identical
 * to the on-chain `advance_payload_digest` function in
 * `programs/health-oracle/src/instructions/advance_epoch.rs`.
 *
 * Layout (fixed, public):
 *   "helixor-epoch-advance"   (21 bytes) — domain separator
 *   current_epoch              (8 bytes, LE)
 *   target_epoch               (8 bytes, LE) — always current_epoch + 1
 *   last_advanced_at           (8 bytes, LE) — EpochState snapshot
 *
 * `last_advanced_at` is folded in so a stash of cluster sigs for advance
 * N→N+1 at time T1 cannot be re-used for the same numeric advance at a
 * later T2 — the value at the moment of the previous tick uniquely
 * identifies the transition.
 *
 * @param currentEpoch    The epoch BEFORE the advance (snapshot from EpochState).
 * @param targetEpoch     The epoch AFTER the advance (currentEpoch + 1).
 * @param lastAdvancedAt  Unix seconds the epoch last ticked (from EpochState).
 * @returns 32-byte SHA-256 digest the cluster signs over.
 */
export function advancePayloadDigest(
  currentEpoch: number | bigint,
  targetEpoch: number | bigint,
  lastAdvancedAt: number | bigint,
): Buffer {
  const buf = Buffer.alloc(
    ADVANCE_EPOCH_DOMAIN_TAG.length + 8 + 8 + 8,
  );
  let o = 0;
  ADVANCE_EPOCH_DOMAIN_TAG.copy(buf, o);
  o += ADVANCE_EPOCH_DOMAIN_TAG.length;
  buf.writeBigUInt64LE(BigInt(currentEpoch), o); o += 8;
  buf.writeBigUInt64LE(BigInt(targetEpoch), o); o += 8;
  buf.writeBigInt64LE(BigInt(lastAdvancedAt), o); o += 8;

  return createHash("sha256").update(buf).digest();
}
