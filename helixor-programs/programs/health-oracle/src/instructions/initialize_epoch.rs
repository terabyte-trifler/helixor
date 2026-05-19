// =============================================================================
// programs/health-oracle/src/instructions/initialize_epoch.rs
//
// initialize_epoch — one-time creation of the EpochState singleton.
//
// Run once after deployment. Sets current_epoch = 1 (epochs are 1-indexed)
// and records the advance authority + the nominal 24h cycle length.
// =============================================================================

use anchor_lang::prelude::*;

use crate::{
    errors::HelixorError,
    state::{EpochState, OracleConfig},
};

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
        constraint = admin.key() == oracle_config.admin_key,
    )]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<InitializeEpoch>, epoch_duration_seconds: i64) -> Result<()> {
    let clock = Clock::get()?;
    let epoch_state = &mut ctx.accounts.epoch_state;
    let duration = if epoch_duration_seconds == 0 {
        EpochState::DEFAULT_DURATION_SECONDS
    } else {
        require!(epoch_duration_seconds > 0, HelixorError::EpochNotElapsed);
        epoch_duration_seconds
    };

    epoch_state.current_epoch = EpochState::FIRST_EPOCH;
    epoch_state.last_advanced_at = clock.unix_timestamp;
    epoch_state.epoch_duration_seconds = duration;
    epoch_state.advance_authority = ctx.accounts.oracle_config.oracle_key;
    epoch_state.bump = ctx.bumps.epoch_state;

    msg!(
        "epoch state initialised: current_epoch={}, duration={}s",
        epoch_state.current_epoch,
        epoch_state.epoch_duration_seconds,
    );
    Ok(())
}
