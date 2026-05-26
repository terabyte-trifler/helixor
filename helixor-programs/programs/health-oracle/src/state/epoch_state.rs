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
//   advance_authority       32   (Pubkey — see AW-02 note below; DEPRECATED
//                                          as a sole-signer authority)
//   bump                     1   (u8)
//   _reserved               32   (zeroed cushion)
//   TOTAL (without discriminator): 89 bytes
//
// AW-02 — `advance_authority` is NO LONGER A SOLE-SIGNER AUTHORITY
// ----------------------------------------------------------------
// The MVP and VULN-02-era code used `advance_authority` as the single key
// gating Tier-1 epoch advancement. The AW-02 audit flagged that as the
// only consensus-critical op NOT covered by the cluster's M-of-N threshold
// mechanism. AW-02 rewrites the Tier-1 path to require
// `consensus_threshold(OracleConfig.oracle_keys)` Ed25519 attestations
// over the canonical advance digest (see `advance_epoch.rs`).
//
// The field is RETAINED in the account layout for two reasons:
//   1. Account size is fixed; removing the field would force a
//      realloc-migration of the deployed singleton. Not worth the risk.
//   2. Operational forensics: ops teams may still want a "primary
//      advance-key" hint for monitoring (e.g. "did the expected node
//      participate in this tick?"). `rotate_advance_authority` remains
//      so the field can be kept current, but it no longer affects who
//      can advance.
//
// A stale or zero `advance_authority` no longer blocks epoch progression.
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
    /// HISTORICAL primary-advancer hint.
    ///
    /// AW-02: NO LONGER a sole-signer authority. Retained for layout
    /// compatibility and operational forensics. Tier-1 advance now
    /// requires M-of-N cluster Ed25519 attestations (see
    /// `advance_epoch.rs`). Tier-2 liveness fallback gates on cluster
    /// membership, NOT on this field.
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
        now.saturating_sub(self.last_advanced_at) >= self.epoch_duration_seconds
    }

    /// Whether the liveness-fallback window is open.
    ///
    /// The fallback allows ANY cluster oracle key to advance the epoch when
    /// `advance_authority` has been unavailable for at least 2× the epoch
    /// duration. This prevents a single lost or compromised key from
    /// permanently halting epoch progression and cert issuance.
    ///
    /// Invariant: `liveness_fallback_elapsed` ⟹ `may_advance`.
    /// (Two durations elapsed always implies one duration elapsed.)
    pub fn liveness_fallback_elapsed(&self, now: i64) -> bool {
        let double = self.epoch_duration_seconds.saturating_mul(2);
        now.saturating_sub(self.last_advanced_at) >= double
    }
}
