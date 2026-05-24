// =============================================================================
// programs/certificate-issuer/src/state/health_certificate.rs
//
// HealthCertificate — the on-chain trust certificate for one agent, for one
// epoch.
//
// THE DOC-2 CHANGE: the MVP kept ONE certificate per agent and overwrote it
// each epoch — the on-chain record had no history. V2 keys the certificate
// by epoch:
//
//     seeds = ["cert", agent_pubkey, epoch]
//
// so every epoch gets its OWN account. epoch-1's certificate is still on
// chain, immutable, after epoch-2 is issued. The full scoring history is
// on-chain and auditable, not just the latest snapshot.
//
// LAYOUT (after the 8-byte Anchor discriminator):
//   agent_wallet            32   (Pubkey)
//   epoch                    8   (u64)
//   score                    2   (u16   — 0..1000 composite trust score)
//   alert_tier               1   (u8    — AlertTier: 0 GREEN, 1 YELLOW, 2 RED)
//   flags                    4   (u32   — aggregated detection flag bits)
//   issued_at                8   (i64   — unix seconds at issuance)
//   issuer                  32   (Pubkey — the oracle authority that issued)
//   baseline_hash           32   ([u8;32] — the baseline this score derives from)
//   immediate_red            1   (bool  — was the IMMEDIATE_RED fast-path tripped)
//   bump                     1   (u8)
//   layout_version           1   (u8)
//   _reserved               48   (zeroed cushion for future fields)
//   TOTAL (without discriminator): 170 bytes
//
// A certificate is WRITE-ONCE: once issued for (agent, epoch) the account
// exists and is never mutated. A re-issue attempt fails at account `init`
// (the PDA already exists). That immutability is the point — a certificate
// is a permanent record of what the oracle attested for that epoch.
// =============================================================================

use anchor_lang::prelude::*;

/// AlertTier on-chain encoding. Mirrors the off-chain scoring.AlertTier.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlertTier {
    Green  = 0,
    Yellow = 1,
    Red    = 2,
}

impl AlertTier {
    /// Decode a raw u8 into an AlertTier. Used by the instruction to
    /// validate caller-supplied input before it is stored.
    pub fn from_u8(value: u8) -> Option<AlertTier> {
        match value {
            0 => Some(AlertTier::Green),
            1 => Some(AlertTier::Yellow),
            2 => Some(AlertTier::Red),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[account]
#[derive(Debug)]
pub struct HealthCertificate {
    /// The agent this certificate attests to.
    pub agent_wallet:   Pubkey,
    /// The scoring epoch this certificate covers. Part of the PDA seed —
    /// every epoch gets its own immutable certificate account.
    pub epoch:          u64,
    /// The composite trust score, 0..=1000.
    pub score:          u16,
    /// The alert tier (GREEN / YELLOW / RED) stored as its u8 code.
    pub alert_tier:     u8,
    /// The aggregated detection flag bits at issuance.
    pub flags:          u32,
    /// Unix seconds when the certificate was issued (on-chain Clock).
    pub issued_at:      i64,
    /// The oracle authority that issued this certificate.
    pub issuer:         Pubkey,
    /// The baseline-hash the score was derived from — links the certificate
    /// to the committed baseline on the health-oracle program.
    pub baseline_hash:  [u8; 32],
    /// True iff the IMMEDIATE_RED security fast-path was tripped this epoch.
    pub immediate_red:  bool,
    /// Canonical PDA bump.
    pub bump:           u8,
    /// Account-layout version, for future migrations.
    pub layout_version: u8,
    /// Zero-padded reserve for small future fields without a realloc.
    pub _reserved:      [u8; 48],
}

impl HealthCertificate {
    /// The current layout version.
    pub const CURRENT_LAYOUT_VERSION: u8 = 1;

    /// The highest valid composite score. Mirrors the off-chain 0..1000 range.
    pub const MAX_SCORE: u16 = 1000;

    /// Data size in bytes, WITHOUT the 8-byte Anchor discriminator.
    ///   32 + 8 + 2 + 1 + 4 + 8 + 32 + 32 + 1 + 1 + 1  = 122
    /// + 48 reserved                                    =  48
    /// = 170
    pub const SIZE_WITHOUT_DISCRIMINATOR: usize =
        32 + 8 + 2 + 1 + 4 + 8 + 32 + 32 + 1 + 1 + 1 + 48;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    pub const SPACE: usize = 8 + Self::SIZE_WITHOUT_DISCRIMINATOR;

    /// The PDA seed prefix for a certificate.
    pub const SEED_PREFIX: &'static [u8] = b"cert";
}
