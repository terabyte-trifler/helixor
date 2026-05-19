// =============================================================================
// programs/certificate-issuer/src/instructions/record_baseline.rs
//
// record_baseline — create or update the per-agent BaselineStats PDA.
//
//     seeds = ["baseline", agent_pubkey]
//
// The certificate-issuer needs the agent's baseline_hash on hand to stamp
// into each HealthCertificate. This instruction records it. `init_if_needed`
// is deliberate: a baseline ROTATES (every ~30 days), so the same PDA is
// created on the first call and updated on subsequent ones.
//
// AUTHORITY: only the configured issuer_node may record a baseline — the
// IssuerConfig is the source of truth, never a hard-coded key.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::CertificateError;
use crate::events::BaselineRecorded;
use crate::state::{BaselineStats, IssuerConfig};

#[derive(Accounts)]
#[instruction(agent_wallet: Pubkey)]
pub struct RecordBaseline<'info> {
    /// The per-agent baseline record. Created on first call, updated after.
    #[account(
        init_if_needed,
        payer = issuer,
        space = BaselineStats::SPACE,
        seeds = [BaselineStats::SEED_PREFIX, agent_wallet.as_ref()],
        bump,
    )]
    pub baseline_stats: Account<'info, BaselineStats>,

    /// IssuerConfig — read to verify the signer is the configured issuer.
    #[account(
        seeds = [IssuerConfig::SEED],
        bump  = issuer_config.bump,
    )]
    pub issuer_config: Account<'info, IssuerConfig>,

    /// The signer. Must equal issuer_config.issuer_node.
    #[account(
        mut,
        constraint = issuer.key() == issuer_config.issuer_node
            @ CertificateError::NotIssuerAuthority,
    )]
    pub issuer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:                   Context<RecordBaseline>,
    agent_wallet:          Pubkey,
    baseline_hash:         [u8; 32],
    baseline_algo_version: u8,
    epoch:                 u64,
) -> Result<()> {
    // ── Validate ────────────────────────────────────────────────────────────
    require!(
        baseline_hash != [0u8; 32],
        CertificateError::ZeroBaselineHash,
    );

    let clock = Clock::get()?;
    let stats = &mut ctx.accounts.baseline_stats;

    // ── Write ───────────────────────────────────────────────────────────────
    // On the first call this is a fresh account (all zero); on a rotation
    // it overwrites in place. agent_wallet + bump are idempotent to set.
    stats.agent_wallet          = agent_wallet;
    stats.baseline_hash         = baseline_hash;
    stats.baseline_algo_version = baseline_algo_version;
    stats.recorded_at           = clock.unix_timestamp;
    stats.recorder              = ctx.accounts.issuer.key();
    stats.epoch_recorded        = epoch;
    stats.bump                  = ctx.bumps.baseline_stats;
    stats.layout_version        = BaselineStats::CURRENT_LAYOUT_VERSION;

    emit!(BaselineRecorded {
        agent_wallet,
        baseline_algo_version,
        epoch_recorded: epoch,
        recorder:       ctx.accounts.issuer.key(),
        recorded_at:    clock.unix_timestamp,
    });

    msg!(
        "baseline recorded for agent {} at epoch {} (algo v{})",
        agent_wallet, epoch, baseline_algo_version,
    );
    Ok(())
}
