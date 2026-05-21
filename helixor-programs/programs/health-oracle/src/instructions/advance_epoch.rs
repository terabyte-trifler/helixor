// =============================================================================
// programs/health-oracle/src/instructions/advance_epoch.rs
//
// advance_epoch — tick the epoch counter at the end of a 24h cycle.
//
// The oracle calls this once per cycle. It increments current_epoch, so the
// next round of certificates is issued under a fresh epoch number — a fresh
// set of ["cert", agent, epoch] PDAs. The previous epoch's certificates are
// untouched: epoch history accumulates on chain.
//
// GUARD: the epoch cannot advance before its duration has elapsed
// (EpochState::may_advance). This stops a misbehaving or compromised oracle
// from racing the epoch forward and minting certificates out of cadence.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::HelixorError;
use crate::events::EpochAdvanced;
use crate::state::EpochState;

#[derive(Accounts)]
pub struct AdvanceEpoch<'info> {
    /// The epoch counter.
    #[account(
        mut,
        seeds = [EpochState::SEED],
        bump  = epoch_state.bump,
    )]
    pub epoch_state: Account<'info, EpochState>,

    /// The signer. Must be the epoch advance authority (the oracle node).
    #[account(
        constraint = advancer.key() == epoch_state.advance_authority
            @ HelixorError::NotOracleAuthority,
    )]
    pub advancer: Signer<'info>,
}

pub fn handler(ctx: Context<AdvanceEpoch>) -> Result<()> {
    let clock = Clock::get()?;
    let epoch_state = &mut ctx.accounts.epoch_state;

    // The epoch may only advance once its duration has elapsed.
    require!(
        epoch_state.may_advance(clock.unix_timestamp),
        HelixorError::EpochNotElapsed,
    );

    let from = epoch_state.current_epoch;
    epoch_state.current_epoch    = from
        .checked_add(1)
        .ok_or(HelixorError::EpochCounterOverflow)?;
    epoch_state.last_advanced_at = clock.unix_timestamp;

    emit!(EpochAdvanced {
        from_epoch:  from,
        to_epoch:    epoch_state.current_epoch,
        advanced_at: clock.unix_timestamp,
    });

    msg!("epoch advanced: {} -> {}", from, epoch_state.current_epoch);
    Ok(())
}
