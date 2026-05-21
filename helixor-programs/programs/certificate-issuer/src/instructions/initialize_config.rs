// =============================================================================
// programs/certificate-issuer/src/instructions/initialize_config.rs
//
// initialize_config -- one-time creation of the IssuerConfig singleton.
//
// DAY-27 EXTENSION: the config now carries the cluster's signing keys and
// the threshold required for cert writes. The 1-key deployment is the
// degenerate single-issuer case; 3..=5 keys is the BFT cluster.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::CertificateError;
use crate::state::IssuerConfig;

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    /// The IssuerConfig singleton, created here.
    #[account(
        init,
        payer = admin,
        space = IssuerConfig::SPACE,
        seeds = [IssuerConfig::SEED],
        bump,
    )]
    pub issuer_config: Account<'info, IssuerConfig>,

    /// The admin -- pays rent and becomes the config's update authority.
    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:          Context<InitializeConfig>,
    issuer_node:  Pubkey,
    cluster_keys: Vec<Pubkey>,
    threshold:    u8,
) -> Result<()> {
    // ── Validate the cluster ────────────────────────────────────────────────
    require!(
        !cluster_keys.is_empty()
            && cluster_keys.len() <= IssuerConfig::MAX_CLUSTER_KEYS,
        CertificateError::InvalidClusterSize,
    );
    // A 2-key cluster has no meaningful threshold; reject it.
    require!(
        cluster_keys.len() != 2,
        CertificateError::InvalidClusterSize,
    );
    // No duplicate keys.
    for i in 0..cluster_keys.len() {
        for j in (i + 1)..cluster_keys.len() { // audit: loop index over Vec.len(), no overflow possible
            require!(
                cluster_keys[i] != cluster_keys[j],
                CertificateError::DuplicateClusterKey,
            );
        }
    }
    // Threshold must be in 1..=cluster_keys.len(). For a BFT cluster a
    // STRICT MAJORITY is required (e.g. 3 of 5); a 1-key deployment uses
    // threshold = 1.
    let n = cluster_keys.len() as u8;
    require!(
        threshold >= 1 && threshold <= n,
        CertificateError::InvalidThreshold,
    );
    if n >= 3 {
        // For an actual cluster, the threshold must be a strict majority.
        require!(
            threshold as usize >= (cluster_keys.len() / 2 + 1),
            CertificateError::InvalidThreshold,
        );
    }

    let config = &mut ctx.accounts.issuer_config;
    config.authority    = ctx.accounts.admin.key();
    config.issuer_node  = issuer_node;
    config.cluster_keys = cluster_keys;
    config.threshold    = threshold;
    config.bump         = ctx.bumps.issuer_config;

    msg!(
        "certificate-issuer config initialised: {}-key cluster, threshold {}-of-{}",
        config.cluster_keys.len(), config.threshold, config.cluster_keys.len(),
    );
    Ok(())
}
