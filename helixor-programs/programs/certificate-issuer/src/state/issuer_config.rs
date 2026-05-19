// =============================================================================
// programs/certificate-issuer/src/state/issuer_config.rs
//
// IssuerConfig — the singleton PDA holding the certificate-issuer authority.
//
//     seeds = ["issuer_config"]
//
// Mirrors the health-oracle program's OracleConfig pattern: the authority
// that may issue certificates is read from this account, never hard-coded,
// so rotating the key (or, in Phase 4, swapping it for a threshold
// authority) is one config write — no program redeploy.
// =============================================================================

use anchor_lang::prelude::*;

#[account]
#[derive(Default, Debug)]
pub struct IssuerConfig {
    /// Admin authority — the key that may update this config.
    pub authority:     Pubkey,
    /// The oracle authority permitted to issue certificates and record
    /// baselines. In Phase 4 this becomes a threshold authority.
    pub issuer_node:   Pubkey,
    /// Canonical PDA bump.
    pub bump:          u8,
}

impl IssuerConfig {
    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    pub const SPACE: usize = 8 + 32 + 32 + 1;

    /// The PDA seed.
    pub const SEED: &'static [u8] = b"issuer_config";
}
