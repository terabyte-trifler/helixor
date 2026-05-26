// =============================================================================
// programs/certificate-issuer/src/state/baseline_stats.rs
//
// BaselineStats — the per-agent baseline record the certificate-issuer
// program holds.
//
//     seeds = ["baseline", agent_pubkey]
//
// ONE account per agent (no epoch in the seed) — the baseline rotates in
// place, unlike the per-epoch certificate.
//
// WHY THE CERT PROGRAM HAS ITS OWN BASELINE ACCOUNT
// -------------------------------------------------
// The health-oracle program already stores a baseline COMMITMENT (the
// 32-byte hash) on AgentRegistration. That hash is the cryptographic
// anchor. This BaselineStats account is the certificate-issuer's own
// local copy of the fields it stamps into each HealthCertificate —
// principally the baseline_hash and the algo version — so issuing a
// certificate needs no cross-program read of the health-oracle account.
//
// Doc 2 splits certificate-writing into its own program; this account is
// part of that split — the cert program owns the state it needs.
//
// LAYOUT (after the 8-byte Anchor discriminator):
//   agent_wallet            32   (Pubkey)
//   baseline_hash           32   ([u8;32])
//   baseline_algo_version    1   (u8)
//   recorded_at              8   (i64 — unix seconds the baseline was recorded)
//   recorder                32   (Pubkey — oracle authority that recorded it)
//   epoch_recorded           8   (u64 — the epoch this baseline became active)
//   bump                     1   (u8)
//   layout_version           1   (u8)
//   --- AW-03 (carved from _reserved, layout-compatible) ----
//   baseline_commit_nonce    8   (u64 — links to AgentRegistration.commit_nonce)
//   _reserved               24   (zeroed cushion; was 32 pre-AW-03)
//   TOTAL (without discriminator): 147 bytes (UNCHANGED)
//
// AW-03 BACKWARDS COMPATIBILITY
// -----------------------------
// `baseline_commit_nonce` was carved out of the existing 32-byte reserve.
// Total account size unchanged. Legacy accounts (recorded pre-AW-03)
// decode this field as 0 (the bytes were zeroed reserve), which is the
// sentinel meaning "no commit_nonce was tracked". The next
// `record_baseline` after the upgrade writes the real nonce, and from then
// on `issue_certificate` stamps it onto every cert it writes.
// =============================================================================

use anchor_lang::prelude::*;

#[account]
#[derive(Default, Debug)]
pub struct BaselineStats {
    /// The agent this baseline belongs to.
    pub agent_wallet:          Pubkey,
    /// SHA-256 commitment of the canonical baseline.
    pub baseline_hash:         [u8; 32],
    /// Algorithm version that produced the baseline.
    pub baseline_algo_version: u8,
    /// Unix seconds when this baseline was recorded with the cert program.
    pub recorded_at:           i64,
    /// The oracle authority that recorded it.
    pub recorder:              Pubkey,
    /// The epoch at which this baseline became the active one.
    pub epoch_recorded:        u64,
    /// Canonical PDA bump.
    pub bump:                  u8,
    /// Account-layout version.
    pub layout_version:        u8,
    /// AW-03: the `AgentRegistration.commit_nonce` this baseline-hash was
    /// committed at on health-oracle. Carved from `_reserved`; legacy
    /// accounts decode this as 0 (the sentinel for "pre-AW-03"). When
    /// non-zero, consumers compute the on-chain `BaselineDataAccount` PDA
    /// from `["baseline_data", agent_wallet, baseline_commit_nonce_le]`,
    /// fetch the account, and verify `sha256(payload) == baseline_hash`.
    pub baseline_commit_nonce: u64,
    /// Zero-padded reserve (was 32 bytes pre-AW-03; 8 bytes are now
    /// `baseline_commit_nonce`).
    pub _reserved:             [u8; 24],
}

impl BaselineStats {
    pub const CURRENT_LAYOUT_VERSION: u8 = 1;

    /// Data size WITHOUT the 8-byte Anchor discriminator.
    ///   32 + 32 + 1 + 8 + 32 + 8 + 1 + 1 = 115
    /// +  8 baseline_commit_nonce         =   8   (AW-03)
    /// + 24 reserved                      =  24   (was 32 pre-AW-03)
    ///   = 147 (unchanged)
    pub const SIZE_WITHOUT_DISCRIMINATOR: usize =
        32 + 32 + 1 + 8 + 32 + 8 + 1 + 1 + 8 + 24;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    pub const SPACE: usize = 8 + Self::SIZE_WITHOUT_DISCRIMINATOR;

    /// The PDA seed prefix.
    pub const SEED_PREFIX: &'static [u8] = b"baseline";
}
