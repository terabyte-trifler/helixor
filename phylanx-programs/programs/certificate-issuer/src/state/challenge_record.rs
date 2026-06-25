// =============================================================================
// programs/certificate-issuer/src/state/challenge_record.rs
//
// ChallengeRecord — the AW-01-EXT.6 PDA recording a challenge filed against
// a specific HealthCertificate's slot anchor.
//
// PDA SEED
//     ["challenge", certificate_pubkey]
//
// One-per-cert. Anchor `init` guarantees init-once, so a cert cannot be
// challenged twice: a record is created at challenge time and persists
// (Upheld or Rejected) forever. This is the audit trail.
//
// LIFECYCLE
//   1. challenge_certificate ix runs
//   2. If the M-of-N attester signatures over `(slot, true_block_hash)`
//      verify AND `true_block_hash != cert.slot_anchor_hash`:
//        - record.state = Upheld
//        - cert.challenge_state = Upheld
//        - CertificateRepudiated event emitted
//   3. If signatures verify but hash EQUALS the cert anchor:
//        - record.state = Rejected (frivolous)
//        - cert.challenge_state = Rejected
//        - challenger's `lamports_at_stake` stays consumed (sunk to PDA)
//        - ChallengeRejected event emitted
//
// Cf. `launch/design/aw01_ext_discrepancy_challenge.md`.
// =============================================================================

use anchor_lang::prelude::*;

use crate::state::health_certificate::ChallengeState;

#[account]
#[derive(Debug)]
pub struct ChallengeRecord {
    /// The certificate this challenge targets — for off-chain lookup,
    /// redundant with the PDA seed.
    pub certificate:        Pubkey,
    /// The agent the cert covers — denormalised for cheap indexing.
    pub agent_wallet:       Pubkey,
    /// The epoch the cert covers — denormalised.
    pub epoch:              u64,
    /// The keypair that paid rent + stake and signed this challenge.
    pub challenger:         Pubkey,
    /// Unix seconds at filing time.
    pub filed_at:           i64,
    /// The challenger's claimed true block hash for the cert's
    /// `slot_anchor_slot`. Stored regardless of Upheld/Rejected — for
    /// Upheld this is the new ground truth; for Rejected this is the
    /// rejected claim and equals `cert.slot_anchor_hash`.
    pub true_block_hash:    [u8; 32],
    /// Number of distinct attester-cluster keys whose signatures the
    /// handler counted. Always >= challenge_threshold (a lower count is
    /// rejected before this record is written).
    pub attester_count:     u8,
    /// The outcome — Upheld (cert repudiated) or Rejected (frivolous).
    /// Stored as a u8 for cheap external decoding.
    pub state:              u8,
    /// Account-layout version, for future migrations.
    pub layout_version:     u8,
    /// Canonical PDA bump.
    pub bump:               u8,
    /// Reserved cushion for small future fields without a realloc.
    pub _reserved:          [u8; 16],
}

impl ChallengeRecord {
    /// Layout v1 — initial.
    pub const CURRENT_LAYOUT_VERSION: u8 = 1;

    /// The PDA seed prefix.
    pub const SEED_PREFIX: &'static [u8] = b"challenge";

    /// Data size WITHOUT the 8-byte Anchor discriminator.
    ///   32 + 32 + 8 + 32 + 8 + 32 + 1 + 1 + 1 + 1 + 16 = 164
    pub const SIZE_WITHOUT_DISCRIMINATOR: usize =
        32 + 32 + 8 + 32 + 8 + 32 + 1 + 1 + 1 + 1 + 16;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    pub const SPACE: usize = 8 + Self::SIZE_WITHOUT_DISCRIMINATOR;

    /// Decode the `state` byte. Convenience for tests and external
    /// decoders that want the strongly-typed value.
    pub fn decoded_state(&self) -> Option<ChallengeState> {
        ChallengeState::from_u8(self.state)
    }
}
