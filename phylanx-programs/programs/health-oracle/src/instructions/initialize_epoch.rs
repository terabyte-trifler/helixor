// =============================================================================
// programs/health-oracle/src/instructions/initialize_epoch.rs
//
// initialize_epoch — one-time creation of the EpochState singleton.
//
// Run once after deployment. Sets current_epoch = 1 (epochs are 1-indexed)
// and records the nominal 24h cycle length.
//
// AW-02 NOTE: `advance_authority` is initialised to the OracleConfig's
// `oracle_node` for layout/back-compat, but it is no longer a sole-signer
// authority on the Tier-1 advance path. Tier 1 requires M-of-N cluster
// Ed25519 attestations (see `advance_epoch.rs`). This field is now a
// non-authoritative HINT.
// =============================================================================

use anchor_lang::prelude::*;

use crate::state::{EpochState, OracleConfig};

#[derive(Accounts)]
pub struct InitializeEpoch<'info> {
    /// The EpochState singleton, created here.
    #[account(
        init,
        payer = admin,
        space = EpochState::SPACE,
        seeds = [EpochState::SEED],
        bump,
    )]
    pub epoch_state: Account<'info, EpochState>,

    /// OracleConfig — read to set the advance authority to the oracle node.
    #[account(
        seeds = [b"oracle_config"],
        bump  = oracle_config.bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,

    /// The admin — pays rent. Must be the OracleConfig admin authority.
    #[account(
        mut,
        constraint = admin.key() == oracle_config.authority,
    )]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<InitializeEpoch>) -> Result<()> {
    let clock = Clock::get()?;
    let epoch_state = &mut ctx.accounts.epoch_state;

    epoch_state.current_epoch          = EpochState::FIRST_EPOCH;
    epoch_state.last_advanced_at       = clock.unix_timestamp;
    epoch_state.epoch_duration_seconds = EpochState::DEFAULT_DURATION_SECONDS;
    epoch_state.advance_authority      = ctx.accounts.oracle_config.oracle_node;
    epoch_state.bump                   = ctx.bumps.epoch_state;

    msg!(
        "epoch state initialised: current_epoch={}, duration={}s",
        epoch_state.current_epoch, epoch_state.epoch_duration_seconds,
    );
    Ok(())
}
