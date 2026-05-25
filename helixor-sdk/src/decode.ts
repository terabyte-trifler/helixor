// =============================================================================
// helixor-sdk/src/decode.ts — on-chain account decoders.
//
// Decodes the fixed byte layouts of the Helixor accounts. The offsets here
// MIRROR the Rust #[account] structs exactly:
//
//   HealthCertificate  (certificate-issuer/src/state/health_certificate.rs)
//   EpochState         (health-oracle/src/state/epoch_state.rs)
//
// Every account starts with the 8-byte Anchor discriminator, which the
// decoders skip. The layouts are byte-for-byte the order the Rust structs
// declare their fields (Anchor/Borsh serialises in declaration order).
//
// Decoding by hand (rather than via the Anchor IDL coder) keeps the SDK
// dependency-light and makes the layout contract explicit and reviewable.
// =============================================================================

/** Bytes of the Anchor account discriminator that prefixes every account. */
const DISCRIMINATOR_LEN = 8;

// =============================================================================
// HealthCertificate
// =============================================================================

export interface DecodedHealthCertificate {
  agentWallet: Uint8Array; // 32 bytes
  epoch: number;
  score: number;
  alertTier: number;
  flags: number;
  issuedAt: number;
  issuer: Uint8Array; // 32 bytes
  baselineHash: Uint8Array; // 32 bytes
  immediateRed: boolean;
  bump: number;
  layoutVersion: number;
  /** How many distinct cluster keys signed this certificate (v2+). */
  signerCount: number;
}

/**
 * Decode a HealthCertificate account.
 *
 * LAYOUT (after the 8-byte discriminator):
 *   agent_wallet    32   epoch          8   score          2
 *   alert_tier       1   flags          4   issued_at      8
 *   issuer          32   baseline_hash 32   immediate_red  1
 *   bump             1   layout_version 1   signer_count   1   _reserved 47
 *
 * v2 note: signer_count was added at layout_version 2. It occupies what was
 * the first byte of _reserved, so total account size is unchanged (178 bytes).
 * Reading signer_count from a v1 account returns 0 (the byte was zeroed
 * reserved padding), which is a safe sentinel meaning "pre-v2 cert".
 */
export function decodeHealthCertificate(
  data: Buffer | Uint8Array
): DecodedHealthCertificate {
  const buf = Buffer.from(data);
  let o = DISCRIMINATOR_LEN;

  const agentWallet = buf.subarray(o, o + 32); o += 32;
  const epoch = Number(buf.readBigUInt64LE(o)); o += 8;
  const score = buf.readUInt16LE(o); o += 2;
  const alertTier = buf.readUInt8(o); o += 1;
  const flags = buf.readUInt32LE(o); o += 4;
  const issuedAt = Number(buf.readBigInt64LE(o)); o += 8;
  const issuer = buf.subarray(o, o + 32); o += 32;
  const baselineHash = buf.subarray(o, o + 32); o += 32;
  const immediateRed = buf.readUInt8(o) !== 0; o += 1;
  const bump = buf.readUInt8(o); o += 1;
  const layoutVersion = buf.readUInt8(o); o += 1;
  const signerCount = buf.readUInt8(o); o += 1;
  // _reserved [47] follows — not decoded.

  return {
    agentWallet,
    epoch,
    score,
    alertTier,
    flags,
    issuedAt,
    issuer,
    baselineHash,
    immediateRed,
    bump,
    layoutVersion,
    signerCount,
  };
}

// =============================================================================
// EpochState
// =============================================================================

export interface DecodedEpochState {
  currentEpoch: number;
  lastAdvancedAt: number;
  epochDurationSeconds: number;
  advanceAuthority: Uint8Array; // 32 bytes
  bump: number;
}

/**
 * Decode an EpochState account.
 *
 * LAYOUT (after the 8-byte discriminator):
 *   current_epoch 8   last_advanced_at 8   epoch_duration_seconds 8
 *   advance_authority 32   bump 1   _reserved 32
 */
export function decodeEpochState(
  data: Buffer | Uint8Array
): DecodedEpochState {
  const buf = Buffer.from(data);
  let o = DISCRIMINATOR_LEN;

  const currentEpoch = Number(buf.readBigUInt64LE(o)); o += 8;
  const lastAdvancedAt = Number(buf.readBigInt64LE(o)); o += 8;
  const epochDurationSeconds = Number(buf.readBigInt64LE(o)); o += 8;
  const advanceAuthority = buf.subarray(o, o + 32); o += 32;
  const bump = buf.readUInt8(o); o += 1;
  // _reserved [32] follows.

  return {
    currentEpoch,
    lastAdvancedAt,
    epochDurationSeconds,
    advanceAuthority,
    bump,
  };
}
