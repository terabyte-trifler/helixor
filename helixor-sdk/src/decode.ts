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
  /**
   * AW-01 cluster-majority input-provenance commitment (v3+).
   * 32-byte SHA-256 over the canonical input transactions + windows. On a
   * pre-v3 certificate this is all zeros (the bytes were zeroed reserved
   * padding), which is the safe pre-v3 sentinel.
   */
  inputCommitment: Uint8Array; // 32 bytes
  /**
   * AW-01-EXT Solana slot the cluster pinned at scoring time (v4+). On a
   * pre-v4 certificate this is 0 — the zero sentinel meaning "no anchor
   * was bound when this cert was issued".
   */
  slotAnchorSlot: bigint;
  /**
   * AW-01-EXT Solana block hash for `slotAnchorSlot` (v4+). On a pre-v4
   * certificate this is all zeros (the bytes were zeroed reserved padding).
   * Together with `slotAnchorSlot` this is verifiable against
   * `connection.getSlotHashes()` — defends against coordinated upstream
   * poisoning where every cluster node reads from the same compromised
   * RPC fleet.
   */
  slotAnchorHash: Uint8Array; // 32 bytes
  /**
   * AW-01-EXT.6 lifecycle state of any filed challenge against this cert
   * (v5+). Values: 0 = None (never challenged), 1 = Upheld (REPUDIATED),
   * 2 = Rejected (challenge filed but frivolous). On a pre-v5 certificate
   * the byte is zeroed reserved padding, which decodes as `None` —
   * indistinguishable from an unchallenged v5 cert and SAFE because the
   * challenge ix only existed from v5 onward.
   */
  challengeState: number;
}

/** AW-01-EXT.6: human-readable names for the `challengeState` byte. */
export const CHALLENGE_STATE_NONE = 0;
export const CHALLENGE_STATE_UPHELD = 1;
export const CHALLENGE_STATE_REJECTED = 2;

/**
 * Decode a HealthCertificate account.
 *
 * LAYOUT (after the 8-byte discriminator, total 210 bytes for v4/v5):
 *   agent_wallet      32   epoch              8   score              2
 *   alert_tier         1   flags              4   issued_at          8
 *   issuer            32   baseline_hash     32   immediate_red      1
 *   bump               1   layout_version     1   signer_count       1
 *   input_commitment  32   slot_anchor_slot   8   slot_anchor_hash  32
 *   challenge_state    1   _reserved         14
 *
 * Layout history:
 *   v1: pre-signer_count, pre-input_commitment, pre-slot_anchor; 170+8.
 *   v2: signer_count occupies what was the first byte of _reserved; 170+8.
 *   v3: input_commitment occupies 32 bytes of reserved padding (AW-01); 170+8.
 *   v4: slot_anchor_slot + slot_anchor_hash appended after input_commitment
 *       (AW-01-EXT). 40 bytes added — account grows to 210+8.
 *   v5: challenge_state (1 byte) consumes the first byte of _reserved
 *       (AW-01-EXT.6). Account size UNCHANGED at 210+8.
 *
 * Decoding a SHORT (pre-v4) buffer returns the zero sentinel for the new
 * fields; the caller can detect this via `layoutVersion < 4`. A pre-v5
 * buffer (length 210, layoutVersion == 4) reads the reserved byte as 0,
 * which equals `CHALLENGE_STATE_NONE` — safe (the byte was always zero).
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
  const inputCommitment = buf.subarray(o, o + 32); o += 32;

  // AW-01-EXT fields (v4+). A pre-v4 buffer is shorter — fall back to
  // the zero sentinel rather than overrun the buffer.
  let slotAnchorSlot: bigint = 0n;
  let slotAnchorHash: Uint8Array = new Uint8Array(32);
  if (buf.length >= o + 8 + 32) {
    slotAnchorSlot = buf.readBigUInt64LE(o); o += 8;
    slotAnchorHash = buf.subarray(o, o + 32); o += 32;
  }

  // AW-01-EXT.6 challenge_state (v5+). Pre-v5 (or buffer too short)
  // collapses to CHALLENGE_STATE_NONE — exactly what reserved-byte zero
  // would decode to anyway, so the legacy path is consistent.
  let challengeState: number = CHALLENGE_STATE_NONE;
  if (buf.length >= o + 1) {
    challengeState = buf.readUInt8(o);
    // o += 1; // (not used; _reserved [14] follows and is not decoded)
  }

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
    inputCommitment,
    slotAnchorSlot,
    slotAnchorHash,
    challengeState,
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
