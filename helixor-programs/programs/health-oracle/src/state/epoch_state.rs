// =============================================================================
// programs/health-oracle/src/state/epoch_state.rs
//
// EpochState — the singleton epoch counter.
//
//     seeds = ["epoch_state"]
//
// Helixor scores agents once per 24h epoch. The epoch number is what keys
// each HealthCertificate PDA (["cert", agent, epoch]) on the
// certificate-issuer program — so a single, authoritative, monotonic epoch
// counter has to live on chain.
//
// WHY A DEDICATED ACCOUNT (not a field on OracleConfig)
// -----------------------------------------------------
// OracleConfig is already deployed. Adding a field would change its size
// and force a realloc-migration of an existing account. EpochState is a
// fresh account — no migration — and gives epoch management its own clear
// home. The same reasoning the codebase used for keeping reserved cushions
// on the larger accounts.
//
// LAYOUT (after the 8-byte Anchor discriminator):
//   current_epoch            8   (u64 — the epoch currently being scored)
//   last_advanced_at         8   (i64 — unix seconds the epoch last ticked)
//   epoch_duration_seconds   8   (i64 — nominal cycle length, 86_400)
//   advance_authority       32   (Pubkey — who may tick the epoch; the oracle)
//   bump                     1   (u8)
//   _reserved               32   (zeroed cushion)
//   TOTAL (without discriminator): 89 bytes
// =============================================================================

use anchor_lang::prelude::*;

#[account]
#[derive(Default, Debug)]
pub struct EpochState {
    /// The epoch currently being scored. Epochs are 1-indexed: the account
    /// is initialised with current_epoch = 1.
    pub current_epoch:          u64,
    /// Unix seconds when the epoch was last advanced.
    pub last_advanced_at:       i64,
    /// The nominal epoch length in seconds (86_400 = 24h). Carried on-chain
    /// so the advance instruction can enforce "not too early".
    pub epoch_duration_seconds: i64,
    /// The authority permitted to advance the epoch — the oracle node.
    pub advance_authority:      Pubkey,
    /// Canonical PDA bump.
    pub bump:                   u8,
    /// Zero-padded reserve.
    pub _reserved:              [u8; 32],
}

impl EpochState {
    /// The first epoch. Epochs are 1-indexed — epoch 0 is "never scored".
    pub const FIRST_EPOCH: u64 = 1;

    /// The default epoch duration: 24 hours.
    pub const DEFAULT_DURATION_SECONDS: i64 = 86_400;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    ///   8 + 8 + 8 + 32 + 1 + 32 = 89
    pub const SPACE: usize = 8 + 8 + 8 + 8 + 32 + 1 + 32;

    /// The PDA seed.
    pub const SEED: &'static [u8] = b"epoch_state";

    /// Whether enough time has elapsed for the epoch to advance.
    ///
    /// Pure — extracted so it is unit-testable without a runtime. A small
    /// grace margin is NOT applied here; the caller decides whether to
    /// allow early advance (e.g. an admin override).
    pub fn may_advance(&self, now: i64) -> bool {
        now - self.last_advanced_at >= self.epoch_duration_seconds
    }
}
