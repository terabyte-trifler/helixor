// =============================================================================
// programs/slash-authority/src/instructions/pause_settlements.rs
//
// pause_settlements / unpause_settlements — the VULN-04 emergency kill
// switch. Only the configured `pause_authority` may toggle it.
//
// While `slash_config.paused == true`, the program refuses:
//   - execute_slash
//   - resolve_appeal
//   - settle_slash
//
// The pause CANNOT move funds, mint new slashes or alter records. It
// only halts the slash pipeline so governance has time to react if both
// slash_executor AND appeal_resolver appear compromised. A separate
// pause role keeps this lever out of the hands of the keys that could
// abuse it (the executor + resolver) — see SlashConfig docs for the full
// authority split.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::events::SlashPaused;
use crate::state::SlashConfig;

#[derive(Accounts)]
pub struct PauseSettlements<'info> {
    /// SlashConfig — the pause flag lives here.
    #[account(
        mut,
        seeds = [SlashConfig::SEED],
        bump  = slash_config.bump,
    )]
    pub slash_config: Account<'info, SlashConfig>,

    /// The pause authority — the only key permitted to toggle the pause.
    #[account(
        constraint = pause_authority.key() == slash_config.pause_authority
            @ SlashError::NotPauseAuthority,
    )]
    pub pause_authority: Signer<'info>,
}

pub fn pause_handler(ctx: Context<PauseSettlements>) -> Result<()> {
    let clock = Clock::get()?;
    let config = &mut ctx.accounts.slash_config;
    require!(!config.paused, SlashError::AlreadyPaused);
    config.paused    = true;
    config.paused_at = clock.unix_timestamp;
    emit!(SlashPaused {
        paused:    true,
        at:        clock.unix_timestamp,
        authority: ctx.accounts.pause_authority.key(),
    });
    msg!("slash-authority PAUSED by {}", ctx.accounts.pause_authority.key());
    Ok(())
}

pub fn unpause_handler(ctx: Context<PauseSettlements>) -> Result<()> {
    let clock = Clock::get()?;
    let config = &mut ctx.accounts.slash_config;
    require!(config.paused, SlashError::NotPaused);
    config.paused    = false;
    config.paused_at = 0;
    emit!(SlashPaused {
        paused:    false,
        at:        clock.unix_timestamp,
        authority: ctx.accounts.pause_authority.key(),
    });
    msg!("slash-authority UNPAUSED by {}", ctx.accounts.pause_authority.key());
    Ok(())
}
