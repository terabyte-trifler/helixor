// =============================================================================
// helixor-sdk/src/verified_consumer.ts — DBP-2 client surface.
//
// DBP-2 introduces the on-chain "Verified Integrator" badge: a per-partner
// PDA on the certificate-issuer program that cryptographically anchors the
// partner's DBP-1 manifest hash. Downstream lending contracts gate access
// to cert-derived parameters on the existence + Active state of this PDA.
//
// This module gives consumers three things:
//
//   1. `verifiedConsumerPda` — derive the per-partner PDA address from the
//      certificate-issuer program ID + partner_wallet.
//   2. `decodeVerifiedConsumer` — parse the raw account bytes (mirrors the
//      Rust `VerifiedConsumer` #[account] layout exactly).
//   3. `fetchVerifiedConsumer` — convenience wrapper that does both.
//   4. `registrationAttestationDigest` — recompute the canonical 32-byte
//      digest the partner_wallet binds against. Mirrors
//      `state::verified_consumer::registration_attestation_digest` on chain.
//      A consumer who wants to re-verify the cryptographic binding off-chain
//      hashes the same bytes.
//
// SAFETY INVARIANT
// ----------------
// A downstream lending contract MUST gate on
// `decoded.state === VerifiedConsumerState.Active`. PRESENCE alone is NOT
// sufficient: a revoked badge persists on chain (the account is never
// closed) so downstream contracts can distinguish "had a badge, lost it"
// from "never had a badge." `isActive()` below is the canonical helper.
// =============================================================================

import { Connection, PublicKey } from "@solana/web3.js";
import { Buffer } from "buffer";
import { createHash } from "crypto";

// -----------------------------------------------------------------------------
// PDA derivation
// -----------------------------------------------------------------------------

const SEED_PREFIX = Buffer.from("verified_consumer", "utf-8");

/**
 * Derive the VerifiedConsumer PDA for a partner on the certificate-issuer
 * program.
 *
 *   seeds = ["verified_consumer", partner_wallet]
 *
 * Mirrors `state::verified_consumer::VerifiedConsumer::SEED_PREFIX` on the
 * on-chain program.
 */
export function verifiedConsumerPda(
  certificateIssuer: PublicKey,
  partnerWallet: PublicKey
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [SEED_PREFIX, partnerWallet.toBuffer()],
    certificateIssuer
  )[0];
}

// -----------------------------------------------------------------------------
// State + reason enums (mirror Rust)
// -----------------------------------------------------------------------------

/** Mirrors `state::verified_consumer::VerifiedConsumerState`. */
export enum VerifiedConsumerState {
  Active = 0,
  Revoked = 1,
}

/** Mirrors `state::verified_consumer::RevokeReason`. */
export enum RevokeReason {
  NotRevoked = 0,
  PartnerSelfRevoke = 1,
  AdminBadFaith = 2,
  AdminTerminated = 3,
}

// -----------------------------------------------------------------------------
// Decoded account
// -----------------------------------------------------------------------------

export interface DecodedVerifiedConsumer {
  partnerWallet: Uint8Array; // 32 bytes
  integrationHash: Uint8Array; // 32 bytes
  registeredAtSlot: bigint;
  registeredAtUnix: bigint;
  /** Raw byte. Use `state === VerifiedConsumerState.Active` to gate access. */
  state: number;
  revokedAtUnix: bigint;
  revokedBy: Uint8Array; // 32 bytes — `Pubkey::default()` (all zeros) while Active
  /** Raw byte. Decode with `RevokeReason`. */
  revokeReason: number;
  layoutVersion: number;
  bump: number;
}

const DISCRIMINATOR_LEN = 8;

/**
 * Decode a VerifiedConsumer account.
 *
 * LAYOUT (after the 8-byte discriminator, total 140 bytes):
 *   partner_wallet     32
 *   integration_hash   32
 *   registered_at_slot  8
 *   registered_at_unix  8
 *   state               1
 *   revoked_at_unix     8
 *   revoked_by         32
 *   revoke_reason       1
 *   layout_version      1
 *   bump                1
 *   _reserved          16
 *   ───────────────────
 *   =140  +8 discriminator =148 total
 */
export function decodeVerifiedConsumer(
  data: Buffer | Uint8Array
): DecodedVerifiedConsumer {
  const buf = Buffer.from(data);
  let o = DISCRIMINATOR_LEN;

  const partnerWallet = buf.subarray(o, o + 32); o += 32;
  const integrationHash = buf.subarray(o, o + 32); o += 32;
  const registeredAtSlot = buf.readBigUInt64LE(o); o += 8;
  const registeredAtUnix = buf.readBigInt64LE(o); o += 8;
  const state = buf.readUInt8(o); o += 1;
  const revokedAtUnix = buf.readBigInt64LE(o); o += 8;
  const revokedBy = buf.subarray(o, o + 32); o += 32;
  const revokeReason = buf.readUInt8(o); o += 1;
  const layoutVersion = buf.readUInt8(o); o += 1;
  const bump = buf.readUInt8(o); o += 1;
  // _reserved [16] follows.

  return {
    partnerWallet,
    integrationHash,
    registeredAtSlot,
    registeredAtUnix,
    state,
    revokedAtUnix,
    revokedBy,
    revokeReason,
    layoutVersion,
    bump,
  };
}

/** True iff the decoded badge is in the Active state. THIS is the gate. */
export function isActive(decoded: DecodedVerifiedConsumer): boolean {
  return decoded.state === VerifiedConsumerState.Active;
}

// -----------------------------------------------------------------------------
// Fetch helper
// -----------------------------------------------------------------------------

/**
 * Fetch + decode a partner's VerifiedConsumer PDA. Returns `null` if the
 * account does not exist (the partner has not registered).
 *
 * REMEMBER: a returned (non-null) record may be REVOKED. Downstream callers
 * must gate on `isActive(record)` rather than just `record !== null`.
 */
export async function fetchVerifiedConsumer(
  connection: Connection,
  certificateIssuer: PublicKey,
  partnerWallet: PublicKey
): Promise<DecodedVerifiedConsumer | null> {
  const pda = verifiedConsumerPda(certificateIssuer, partnerWallet);
  const account = await connection.getAccountInfo(pda);
  if (account === null) {
    return null;
  }
  return decodeVerifiedConsumer(account.data);
}

// -----------------------------------------------------------------------------
// Canonical attestation digest
// -----------------------------------------------------------------------------

/**
 * Domain-separation tag on the DBP-2 registration attestation digest.
 *
 * MUST match the Rust constant `VerifiedConsumer::DOMAIN_TAG` byte-for-byte
 * — a drift here invalidates every off-chain signature recompute.
 */
export const REGISTRATION_DOMAIN_TAG = "helixor-dbp2-verified-consumer";

/**
 * Recompute the canonical 32-byte registration attestation digest.
 *
 *   sha256( "helixor-dbp2-verified-consumer" || partner_wallet || integration_hash )
 *
 * Mirrors `state::verified_consumer::registration_attestation_digest` on
 * chain. v1 DBP-2 does not check a detached signature over this digest
 * (the partner_wallet IS the tx Signer), but the digest is still
 * load-bearing for any future delegated-submission path and for off-chain
 * auditors who want to re-verify the binding.
 */
export function registrationAttestationDigest(
  partnerWallet: PublicKey,
  integrationHash: Uint8Array
): Uint8Array {
  if (integrationHash.length !== 32) {
    throw new Error(
      `integrationHash must be 32 bytes, got ${integrationHash.length}`
    );
  }
  const hasher = createHash("sha256");
  hasher.update(Buffer.from(REGISTRATION_DOMAIN_TAG, "utf-8"));
  hasher.update(partnerWallet.toBuffer());
  hasher.update(Buffer.from(integrationHash));
  return new Uint8Array(hasher.digest());
}
