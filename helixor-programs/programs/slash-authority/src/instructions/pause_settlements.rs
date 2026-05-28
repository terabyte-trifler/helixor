// =============================================================================
// programs/slash-authority/src/instructions/pause_settlements.rs
//
// pause_settlements / unpause_settlements — the VULN-04 emergency kill
// switch. Only the configured `pause_authority` may toggle it.
//
// While `slash_config.is_paused_now(now) == true`, the program refuses:
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
//
// H-04: BOUNDED PAUSE WITH HARD CAP
// ---------------------------------
// pause_settlements takes a `duration_seconds: i64` (1..=MAX_PAUSE_SECONDS;
// 7 days). The handler writes `paused_until = now + duration_seconds`. The
// gating reads `is_paused_now(now)` — an expired pause is functionally
// lifted without an unpause tx. A compromised pause_authority cannot
// freeze settlement indefinitely; it must re-pause every 7 days, which
// is observable on chain and gives SPOF-#2 authority rotation (2-of-3
// + 48h timelock) time to replace the compromised key.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::events::SlashPaused;
use crate::state::{SlashConfig, MAX_PAUSE_SECONDS};

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

pub fn pause_handler(
    ctx:              Context<PauseSettlements>,
    duration_seconds: i64,
) -> Result<()> {
    // H-04: duration must be strictly positive and within the hard cap.
    // A zero/negative duration is rejected (no-op pauses leak nothing
    // but also serve no purpose; we want every pause tx to clearly
    // declare its window). The 7-day cap is the audit's hard limit.
    require!(
        duration_seconds > 0 && duration_seconds <= MAX_PAUSE_SECONDS,
        SlashError::PauseDurationInvalid,
    );

    let clock = Clock::get()?;
    let now   = clock.unix_timestamp;
    let config = &mut ctx.accounts.slash_config;

    // Refuse to re-pause while an existing pause is STILL IN EFFECT — the
    // pause_authority must wait for the current window to expire (or
    // explicitly unpause) before re-arming. This forces the compromised
    // path to be a SEQUENCE of paused/expired/paused/expired ... cycles
    // that governance can watch in the event stream.
    require!(
        !config.is_paused_now(now),
        SlashError::AlreadyPaused,
    );

    let paused_until = now
        .checked_add(duration_seconds)
        .ok_or(SlashError::MathOverflow)?;

    config.paused       = true;
    config.paused_at    = now;
    config.paused_until = paused_until;

    emit!(SlashPaused {
        paused:    true,
        at:        now,
        authority: ctx.accounts.pause_authority.key(),
    });
    msg!(
        "slash-authority PAUSED by {} for {}s (until {})",
        ctx.accounts.pause_authority.key(),
        duration_seconds,
        paused_until,
    );
    Ok(())
}

pub fn unpause_handler(ctx: Context<PauseSettlements>) -> Result<()> {
    let clock = Clock::get()?;
    let now   = clock.unix_timestamp;
    let config = &mut ctx.accounts.slash_config;
    // Allow explicit unpause both while the timer is still active and
    // (idempotently) when it has expired but the flag is stuck high —
    // the gate is `is_paused_now`, but the explicit reset keeps the
    // queried state tidy.
    require!(config.paused, SlashError::NotPaused);
    config.paused       = false;
    config.paused_at    = 0;
    config.paused_until = 0;
    emit!(SlashPaused {
        paused:    false,
        at:        now,
        authority: ctx.accounts.pause_authority.key(),
    });
    msg!("slash-authority UNPAUSED by {}", ctx.accounts.pause_authority.key());
    Ok(())
}
