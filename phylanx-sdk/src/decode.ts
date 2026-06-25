// =============================================================================
// phylanx-sdk/src/decode.ts — on-chain account decoders.
//
// Decodes the fixed byte layouts of the Phylanx accounts. The offsets here
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
  /**
   * AW-03 `AgentRegistration.commit_nonce` the baseline used to produce
   * this cert's `baseline_hash` (v6+). Together with `agentWallet` this
   * uniquely identifies the on-chain `BaselineDataAccount`. On a pre-v6
   * certificate the bytes are zero (the bytes were zeroed reserved
   * padding) — the sentinel meaning "no DA account exists for this
   * cert's baseline; only the hash commitment is available".
   */
  baselineCommitNonce: bigint;
  /**
   * AW-04: SHA-256 over the canonical scoring kernel source bytes plus
   * the algo + weights version labels (v7+). See
   * `oracle/scoring/bundle_hash.py::compute_scoring_bundle_hash` for the
   * canonical form. Folded into the cert-payload digest the cluster
   * signed, so the threshold signatures cryptographically attest to the
   * EXACT source bytes that produced this score. A consumer running
   * `verifyScoringCodeHash` clones the phylanx repo at the published tag,
   * recomputes the bundle hash, and refuses the cert if it disagrees with
   * this field — closing the gap where a cluster ships patched scoring
   * code while claiming the published algo version. On a pre-v7
   * certificate (length 218 total, layoutVersion < 7) the bytes do not
   * exist; the decoder returns the zero sentinel.
   */
  scoringCodeHash: Uint8Array; // 32 bytes
  /**
   * M-05 (v8+): the `IssuerConfig.config_version` snapshot active when
   * the cluster signed this cert. Folded into the cert-payload digest so
   * the threshold signatures cryptographically attest to the config
   * snapshot — a post-issuance config rotation cannot retroactively
   * change which signing-key set validates a historical cert. Legacy
   * pre-v8 certs decode this as 0 (the sentinel meaning "issued before
   * the immutability tag existed").
   */
  issuerConfigVersion: number;
  /**
   * Day 38 (v9+): failure-mode taxonomy schema version. Off-chain
   * consumers decode `failureModeBitmask` + `remediationCodes` against
   * the schema named by this byte. Legacy pre-v9 certs decode this as 0
   * — the sentinel meaning "no taxonomy binding".
   */
  taxonomyVersion: number;
  /**
   * Day 38 (v9+): u64 cluster-majority per-bit failure-mode bitmask.
   * The low 32 bits equal `BigInt(flags)` by an ix-level invariant
   * (`failure_mode_bitmask & 0xFFFF_FFFF == flags`) — so every v1..v8
   * consumer that reads only `flags` continues to see consistent data.
   * Legacy pre-v9 certs decode this as 0n (no diagnostic bitmask was
   * published).
   */
  failureModeBitmask: bigint;
  /**
   * Day 38 (v9+): u32 bit-set of remediation codes the cluster
   * recommends for the failure modes in `failureModeBitmask`. Legacy
   * pre-v9 certs decode this as 0.
   */
  remediationCodes: number;
  /**
   * Day 38 (v9+): SHA-256 over the canonical-JSON cluster-diagnosis
   * payload the cluster reached consensus on (the payload itself lives
   * off-chain via the diagnosis DA layer). Folded into the cert-payload
   * digest so the threshold signatures attest to the diagnosis. Legacy
   * pre-v9 certs decode this as the all-zero sentinel (no diagnosis
   * payload was published with this cert).
   */
  diagnosisPayloadHash: Uint8Array; // 32 bytes
}

/** AW-01-EXT.6: human-readable names for the `challengeState` byte. */
export const CHALLENGE_STATE_NONE = 0;
export const CHALLENGE_STATE_UPHELD = 1;
export const CHALLENGE_STATE_REJECTED = 2;

/**
 * Decode a HealthCertificate account.
 *
 * LAYOUT (after the 8-byte discriminator, total 286 bytes for v9):
 *   agent_wallet           32   epoch                  8   score              2
 *   alert_tier              1   flags                  4   issued_at          8
 *   issuer                 32   baseline_hash         32   immediate_red      1
 *   bump                    1   layout_version         1   signer_count       1
 *   input_commitment       32   slot_anchor_slot       8   slot_anchor_hash  32
 *   challenge_state         1   baseline_commit_nonce  8   scoring_code_hash 32
 *   issuer_config_version   4   taxonomy_version       1   failure_mode_bm    8
 *   remediation_codes       4   diagnosis_payload_hash 32  _reserved          1
 *
 * Layout history:
 *   v1: pre-signer_count, pre-input_commitment, pre-slot_anchor; 170+8.
 *   v2: signer_count occupies what was the first byte of _reserved; 170+8.
 *   v3: input_commitment occupies 32 bytes of reserved padding (AW-01); 170+8.
 *   v4: slot_anchor_slot + slot_anchor_hash appended after input_commitment
 *       (AW-01-EXT). 40 bytes added — account grows to 210+8.
 *   v5: challenge_state (1 byte) consumes the first byte of _reserved
 *       (AW-01-EXT.6). Account size UNCHANGED at 210+8.
 *   v6: baseline_commit_nonce (8 bytes, u64 LE) consumes the next 8
 *       bytes of _reserved (AW-03). Account size UNCHANGED at 210+8.
 *   v7: scoring_code_hash ([u8;32]) APPENDED (AW-04). The previous
 *       _reserved was only 6 bytes, so the 32-byte hash forces a realloc:
 *       account grows from 210+8 to 242+8.
 *   v8: issuer_config_version (4 bytes, u32 LE) CARVED from the v7
 *       _reserved [6 -> 2] (M-05). Account size UNCHANGED at 242+8.
 *   v9: taxonomy_version (u8) CARVED from the v8 _reserved [2 -> 1]
 *       AND failure_mode_bitmask (u64), remediation_codes (u32),
 *       diagnosis_payload_hash ([u8;32]) APPENDED (Day 38). Account
 *       grows from 242+8 to 286+8 (+44 bytes).
 *
 * Decoding a SHORT (pre-v4) buffer returns the zero sentinel for the new
 * fields; the caller can detect this via `layoutVersion < 4`. Pre-v5/v6
 * buffers similarly fall back to the zero sentinel for their respective
 * fields. A pre-v7 buffer is 32 bytes shorter; `scoringCodeHash` is the
 * zero sentinel. A pre-v8 buffer has 4 bytes of trailing reserved
 * padding; `issuerConfigVersion` decodes those bytes as 0. A pre-v9
 * buffer is 44 bytes shorter than v9; `taxonomyVersion`,
 * `failureModeBitmask`, `remediationCodes`, `diagnosisPayloadHash` fall
 * back to their zero sentinels — meaning "no diagnostic certificate was
 * published with this cert".
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
    o += 1;
  }

  // AW-03 baseline_commit_nonce (v6+). Pre-v6 (or buffer too short)
  // collapses to 0 — the sentinel "no DA account exists for this cert's
  // baseline". The bytes were reserved padding in v5, so a pre-v6 buffer
  // reads them as zeros, which equals 0n here.
  let baselineCommitNonce: bigint = 0n;
  if (buf.length >= o + 8) {
    baselineCommitNonce = buf.readBigUInt64LE(o);
    o += 8;
  }

  // AW-04 scoring_code_hash (v7+). APPENDED (NOT carved from _reserved)
  // — pre-v7 buffers are 32 bytes shorter and have no scoring_code_hash
  // bytes to read. Fall back to the zero sentinel; the caller can detect
  // this via `layoutVersion < 7` and skip the scoring-bundle check.
  let scoringCodeHash: Uint8Array = new Uint8Array(32);
  if (buf.length >= o + 32) {
    scoringCodeHash = buf.subarray(o, o + 32);
    o += 32;
  }

  // M-05 issuer_config_version (v8+). CARVED from _reserved — pre-v8
  // buffers have these 4 bytes as zeroed reserved padding, which decodes
  // as 0 (the sentinel "issued before the immutability tag existed").
  let issuerConfigVersion = 0;
  if (buf.length >= o + 4) {
    issuerConfigVersion = buf.readUInt32LE(o);
    o += 4;
  }

  // Day 38 taxonomy_version (v9+). CARVED from the v8 _reserved [2] →
  // pre-v9 buffers either have this byte as zeroed reserved padding OR
  // are 44 bytes shorter (pre-v9 size = 250, v9 size = 294). Both decode
  // as 0 — the sentinel meaning "no taxonomy binding".
  let taxonomyVersion = 0;
  if (buf.length >= o + 1) {
    taxonomyVersion = buf.readUInt8(o);
    o += 1;
  }

  // Day 38 failure_mode_bitmask (v9+, APPENDED). Pre-v9 buffers do not
  // have these 8 bytes; fall back to 0n (no diagnostic bitmask was
  // published with this cert).
  let failureModeBitmask: bigint = 0n;
  if (buf.length >= o + 8) {
    failureModeBitmask = buf.readBigUInt64LE(o);
    o += 8;
  }

  // Day 38 remediation_codes (v9+, APPENDED).
  let remediationCodes = 0;
  if (buf.length >= o + 4) {
    remediationCodes = buf.readUInt32LE(o);
    o += 4;
  }

  // Day 38 diagnosis_payload_hash (v9+, APPENDED).
  let diagnosisPayloadHash: Uint8Array = new Uint8Array(32);
  if (buf.length >= o + 32) {
    diagnosisPayloadHash = buf.subarray(o, o + 32);
    // o += 32; // (not used; _reserved [1] follows and is not decoded)
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
    baselineCommitNonce,
    scoringCodeHash,
    issuerConfigVersion,
    taxonomyVersion,
    failureModeBitmask,
    remediationCodes,
    diagnosisPayloadHash,
  };
}

// =============================================================================
// BaselineDataAccount (AW-03)
// =============================================================================

export interface DecodedBaselineDataAccount {
  /** The agent this baseline belongs to. */
  agentWallet: Uint8Array; // 32 bytes
  /** Strictly-monotonic commit_nonce — pins this account to ONE rotation. */
  commitNonce: bigint;
  /** SHA-256(payload). Equal to AgentRegistration.baseline_hash by construction. */
  baselineHash: Uint8Array; // 32 bytes
  /** Algorithm version that produced the payload + hash. */
  baselineAlgoVersion: number;
  /** Unix seconds when this baseline was committed (Clock::get()). */
  committedAt: bigint;
  /** Signer that wrote this baseline. */
  committer: Uint8Array; // 32 bytes
  /** Canonical-JSON payload bytes — `sha256(payload) === baselineHash`. */
  payload: Uint8Array;
  /** Canonical PDA bump. */
  bump: number;
  /** Account-layout version (v1 = AW-03 initial). */
  layoutVersion: number;
}

/**
 * Decode a `BaselineDataAccount` (the AW-03 on-chain data-availability
 * account). The payload is the canonical-JSON bytes produced by the
 * off-chain Python serializer; its SHA-256 MUST equal `baselineHash`,
 * which is the on-chain hash binding enforced at write time.
 *
 * LAYOUT (after the 8-byte discriminator, total 135 + N bytes):
 *   agent_wallet           32   commit_nonce                8
 *   baseline_hash          32   baseline_algo_version       1
 *   committed_at            8   committer                  32
 *   payload_len             4   payload                     N
 *   bump                    1   layout_version              1
 *   _reserved              16
 */
export function decodeBaselineDataAccount(
  data: Buffer | Uint8Array
): DecodedBaselineDataAccount {
  const buf = Buffer.from(data);
  let o = DISCRIMINATOR_LEN;

  if (buf.length < o + 32 + 8 + 32 + 1 + 8 + 32 + 4) {
    throw new Error(
      `BaselineDataAccount buffer too short: ${buf.length} bytes`
    );
  }

  const agentWallet = buf.subarray(o, o + 32); o += 32;
  const commitNonce = buf.readBigUInt64LE(o); o += 8;
  const baselineHash = buf.subarray(o, o + 32); o += 32;
  const baselineAlgoVersion = buf.readUInt8(o); o += 1;
  const committedAt = buf.readBigInt64LE(o); o += 8;
  const committer = buf.subarray(o, o + 32); o += 32;

  const payloadLen = buf.readUInt32LE(o); o += 4;
  if (buf.length < o + payloadLen + 1 + 1 + 16) {
    throw new Error(
      `BaselineDataAccount truncated: claims payload_len=${payloadLen} but only ` +
      `${buf.length - o} bytes remain (need ${payloadLen + 18})`
    );
  }
  const payload = buf.subarray(o, o + payloadLen); o += payloadLen;

  const bump = buf.readUInt8(o); o += 1;
  const layoutVersion = buf.readUInt8(o); o += 1;
  // _reserved [16] follows.

  return {
    agentWallet,
    commitNonce,
    baselineHash,
    baselineAlgoVersion,
    committedAt,
    committer,
    payload,
    bump,
    layoutVersion,
  };
}

// =============================================================================
// ScoreComponentsAccount (AW-04)
// =============================================================================

export interface DecodedScoreComponentsAccount {
  /** The agent this components payload belongs to. Mirrors paired cert. */
  agentWallet: Uint8Array; // 32 bytes
  /** The epoch this components payload covers. Mirrors paired cert. */
  epoch: bigint;
  /** sha256(payload). Enforced by the on-chain handler at write time. */
  componentsHash: Uint8Array; // 32 bytes
  /** Unix seconds when this components account was written. */
  computedAt: bigint;
  /** Canonical-JSON payload bytes — `sha256(payload) === componentsHash`. */
  payload: Uint8Array;
  /** Canonical PDA bump. */
  bump: number;
  /** Account-layout version (v1 = AW-04 initial). */
  layoutVersion: number;
}

/**
 * Decode a `ScoreComponentsAccount` (the AW-04 on-chain components DA).
 *
 * LAYOUT (after the 8-byte discriminator, total 102 + N bytes):
 *   agent_wallet            32   epoch              8
 *   components_hash         32   computed_at        8
 *   payload_len              4   payload            N
 *   bump                     1   layout_version     1
 *   _reserved               16
 *
 * The payload is the canonical-JSON bytes produced by the off-chain
 * Python serializer (`oracle/score_components.py`); its SHA-256 MUST
 * equal `componentsHash`, which the on-chain handler enforces at write
 * time.
 */
export function decodeScoreComponentsAccount(
  data: Buffer | Uint8Array
): DecodedScoreComponentsAccount {
  const buf = Buffer.from(data);
  let o = DISCRIMINATOR_LEN;

  if (buf.length < o + 32 + 8 + 32 + 8 + 4) {
    throw new Error(
      `ScoreComponentsAccount buffer too short: ${buf.length} bytes`
    );
  }

  const agentWallet = buf.subarray(o, o + 32); o += 32;
  const epoch = buf.readBigUInt64LE(o); o += 8;
  const componentsHash = buf.subarray(o, o + 32); o += 32;
  const computedAt = buf.readBigInt64LE(o); o += 8;

  const payloadLen = buf.readUInt32LE(o); o += 4;
  if (buf.length < o + payloadLen + 1 + 1 + 16) {
    throw new Error(
      `ScoreComponentsAccount truncated: claims payload_len=${payloadLen} ` +
      `but only ${buf.length - o} bytes remain (need ${payloadLen + 18})`
    );
  }
  const payload = buf.subarray(o, o + payloadLen); o += payloadLen;

  const bump = buf.readUInt8(o); o += 1;
  const layoutVersion = buf.readUInt8(o); o += 1;
  // _reserved [16] follows.

  return {
    agentWallet,
    epoch,
    componentsHash,
    computedAt,
    payload,
    bump,
    layoutVersion,
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
