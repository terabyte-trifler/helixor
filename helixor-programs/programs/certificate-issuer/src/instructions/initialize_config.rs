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
    ctx:                       Context<InitializeConfig>,
    issuer_node:               Pubkey,
    cluster_keys:              Vec<Pubkey>,
    threshold:                 u8,
    // VULN-16: the canonical health-oracle program ID — the only OTHER
    // program permitted to CPI into `issue_certificate`. Pass
    // `Pubkey::default()` only if the deployment never uses the CPI
    // submit-score path (the safe default refuses every CPI from any
    // program other than ourselves).
    health_oracle_program_id:  Pubkey,
    // AW-01-EXT.6: the challenge-attester cluster (third-party
    // validators whose signatures count toward `challenge_certificate`).
    // Pass an empty Vec + threshold 0 to leave the challenge ix
    // disabled at deploy time; rotate in via a future
    // `rotate_challenge_attesters` ix (gated on the admin key). MUST be
    // DISJOINT from `cluster_keys` — the architecture requires
    // independent re-checkers.
    challenge_attester_keys:   Vec<Pubkey>,
    challenge_threshold:       u8,
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

    // ── AW-01-EXT.6: validate the challenge-attester cluster ────────────────
    // Empty + threshold-0 is allowed (challenge ix disabled at deploy
    // time). Otherwise apply the same shape rules as cluster_keys.
    let challenge_enabled =
        !challenge_attester_keys.is_empty() || challenge_threshold != 0;
    if challenge_enabled {
        require!(
            !challenge_attester_keys.is_empty()
                && challenge_attester_keys.len()
                    <= IssuerConfig::MAX_CHALLENGE_ATTESTER_KEYS,
            CertificateError::InvalidAttesterClusterSize,
        );
        // No duplicates among attester keys.
        for i in 0..challenge_attester_keys.len() {
            for j in (i + 1)..challenge_attester_keys.len() { // audit: bounded by Vec.len()
                require!(
                    challenge_attester_keys[i] != challenge_attester_keys[j],
                    CertificateError::DuplicateAttesterKey,
                );
            }
        }
        // DISJOINT from cluster_keys — the architectural requirement that
        // an attester is an INDEPENDENT third party, not one of the
        // signers being challenged.
        for ak in &challenge_attester_keys {
            require!(
                !cluster_keys.contains(ak),
                CertificateError::AttesterOverlapsCluster,
            );
        }
        require!(
            challenge_threshold >= 1
                && challenge_threshold as usize <= challenge_attester_keys.len(),
            CertificateError::InvalidChallengeThreshold,
        );
    }

    let config = &mut ctx.accounts.issuer_config;
    config.authority                = ctx.accounts.admin.key();
    config.issuer_node              = issuer_node;
    config.cluster_keys             = cluster_keys;
    config.threshold                = threshold;
    config.bump                     = ctx.bumps.issuer_config;
    config.health_oracle_program_id = health_oracle_program_id;
    config.challenge_attester_keys  = challenge_attester_keys;
    config.challenge_threshold      = challenge_threshold;

    msg!(
        "certificate-issuer config initialised: {}-key cluster, threshold {}-of-{}, \
         CPI allow-list {}, challenge cluster {}",
        config.cluster_keys.len(),
        config.threshold,
        config.cluster_keys.len(),
        if config.has_health_oracle_program() {
            "enabled"
        } else {
            "DISABLED (no CPI caller permitted)"
        },
        if config.challenge_enabled() {
            "enabled"
        } else {
            "DISABLED"
        },
    );
    Ok(())
}
