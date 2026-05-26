// =============================================================================
// programs/health-oracle/src/state/baseline_data.rs
//
// AW-03 — BaselineDataAccount
//
// THE AUDIT FINDING
// -----------------
// `baseline_hash` on `AgentRegistration` is a 32-byte SHA-256 commitment over
// statistical summaries (feature_means, stds, txtype distribution, action
// entropy, success rate, daily success series). The hash itself proves NOTHING
// about provenance — a third party (a DeFi protocol reading a cert) cannot
// verify the bytes-behind-the-hash. A compromised oracle DB could substitute
// any 32-byte value at commit time and the on-chain record would happily
// store it.
//
// THE FIX
// -------
// Publish the canonical baseline-payload bytes ON CHAIN, in a dedicated
// account whose seeds include `commit_nonce` so each rotation produces a NEW
// account (the old one stays around — permanent audit trail). At init time
// the program enforces `sha256(payload) == baseline_hash`, so the on-chain
// hash and the on-chain bytes can never disagree by construction.
//
// SEEDS
//   ["baseline_data", agent_wallet, commit_nonce_le]
//
// EVERY commit_baseline produces a UNIQUE PDA (commit_nonce is strictly
// monotonic). The previous baseline-data account remains immutable on chain
// after a rotation, giving consumers a full history of every baseline ever
// committed.
//
// ON-CHAIN INVARIANT
// ------------------
//   sha256(self.payload) == agent_registration.baseline_hash
//
// Enforced at write time in commit_baseline. Since the account is write-once
// (`init`), the invariant is permanent.
//
// DATA AVAILABILITY GUARANTEE
// ---------------------------
// Solana itself is the DA layer — no Arweave, IPFS, or Celestia involved.
// Trust domain unchanged from the rest of helixor; consumers fetch the
// account via the same RPC they use for the cert. The cluster cannot
// substitute a different baseline without the on-chain hash diverging from
// the stored bytes — and the on-chain hash is what the threshold-signed
// certificate digest binds to.
//
// PAYLOAD CONTENT
// ---------------
// The exact canonical JSON bytes produced by
// `baseline.hashing.build_hash_payload` + `json.dumps(sort_keys=True,
// separators=(",", ":"))`. That is the SAME bytes the off-chain cluster
// hashes to produce `baseline_hash`. Storing those bytes verbatim means
// any consumer can `sha256(account.payload)` and verify == `baseline_hash`
// with no extra parsing — just one hash.
//
// LAYOUT (after the 8-byte Anchor discriminator):
//   agent_wallet            32   (Pubkey)
//   commit_nonce             8   (u64 — links to AgentRegistration)
//   baseline_hash           32   ([u8; 32] — sha256(payload), invariant)
//   baseline_algo_version    1   (u8)
//   committed_at             8   (i64 — unix seconds)
//   committer               32   (Pubkey — who wrote it)
//   payload_len              4   (u32 — borsh Vec<u8> length prefix)
//   payload                  N   (Vec<u8> — N bytes of canonical payload)
//   bump                     1   (u8)
//   layout_version           1   (u8)
//   _reserved               16   (zero cushion for small future fields)
//   TOTAL (without discriminator): 135 + N bytes
//
// The 16-byte reserve is small because the payload itself is the bulky
// field — future expansions of the on-chain DA scheme would more naturally
// go through `layout_version` + a fresh account.
// =============================================================================

use anchor_lang::prelude::*;

/// The maximum canonical-payload length accepted by `commit_baseline`. Sized
/// for a 30-day baseline with the v3 algorithm (100 feature means + 100 stds
/// + 5 txtype + ~30 daily series, each rendered as a fixed-precision string).
/// Real payloads run ~3 KB; the 8 KB cap is the safety ceiling. Anything
/// larger means the off-chain serializer drifted from the canonical form
/// and the writer should be refused so the issue surfaces.
pub const MAX_BASELINE_PAYLOAD_LEN: usize = 8192;

#[account]
#[derive(Debug)]
pub struct BaselineDataAccount {
    /// The agent this baseline belongs to. Mirrors AgentRegistration.agent_wallet.
    pub agent_wallet:           Pubkey,
    /// The commit_nonce at which this baseline was committed. The PDA seed
    /// pins this account to a specific commit_nonce, so a rotation cannot
    /// overwrite history; each baseline lives in its own account forever.
    pub commit_nonce:           u64,
    /// SHA-256 commitment of `payload`. Equal to AgentRegistration.baseline_hash
    /// at write time. Stored here too so a consumer with ONLY this account
    /// can verify `sha256(payload) == baseline_hash` without a cross-account
    /// read.
    pub baseline_hash:          [u8; 32],
    /// Algorithm version that produced the payload + hash.
    pub baseline_algo_version:  u8,
    /// Unix seconds when this baseline was committed (Clock::get()).
    pub committed_at:           i64,
    /// The signer that wrote this baseline (oracle node or agent owner).
    pub committer:              Pubkey,
    /// The canonical payload bytes. Exactly the bytes that
    /// `baseline.hashing.build_hash_payload` + `json.dumps(sort_keys=True,
    /// separators=(",", ":"))` produces off chain. `sha256(payload) ==
    /// baseline_hash` is enforced at write time.
    pub payload:                Vec<u8>,
    /// Canonical PDA bump.
    pub bump:                   u8,
    /// Account-layout version.
    pub layout_version:         u8,
    /// Zero-padded reserve.
    pub _reserved:              [u8; 16],
}

impl BaselineDataAccount {
    /// The current layout version. v1 is the AW-03 initial layout.
    pub const CURRENT_LAYOUT_VERSION: u8 = 1;

    /// The PDA seed prefix.
    pub const SEED_PREFIX: &'static [u8] = b"baseline_data";

    /// Size of the fixed-width fields ONLY (everything except the payload's
    /// Vec<u8> contents). Used to compute the per-instruction `space` from
    /// the actual payload length at init time.
    ///
    ///   32 agent_wallet
    /// +  8 commit_nonce
    /// + 32 baseline_hash
    /// +  1 baseline_algo_version
    /// +  8 committed_at
    /// + 32 committer
    /// +  4 payload_len (borsh Vec<u8> prefix)
    /// +  1 bump
    /// +  1 layout_version
    /// + 16 _reserved
    ///  = 135
    pub const FIXED_FIELDS_LEN: usize = 32 + 8 + 32 + 1 + 8 + 32 + 4 + 1 + 1 + 16;

    /// Total account space for a payload of `payload_len` bytes, INCLUDING
    /// the 8-byte Anchor discriminator.
    pub const fn space_for(payload_len: usize) -> usize {
        8 + Self::FIXED_FIELDS_LEN + payload_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Catch any accidental layout drift — the fixed-fields constant is the
    /// foundation of every `space = ...` computation in commit_baseline.
    #[test]
    fn fixed_fields_len_matches_field_byte_count() {
        // 32 + 8 + 32 + 1 + 8 + 32 + 4 + 1 + 1 + 16 = 135
        assert_eq!(BaselineDataAccount::FIXED_FIELDS_LEN, 135);
    }

    #[test]
    fn space_for_includes_discriminator_and_payload() {
        // 8 (disc) + 135 (fixed) + 1234 (payload) = 1377
        assert_eq!(BaselineDataAccount::space_for(1234), 8 + 135 + 1234);
    }

    #[test]
    fn max_payload_constant_is_8k() {
        assert_eq!(MAX_BASELINE_PAYLOAD_LEN, 8192);
    }
}
