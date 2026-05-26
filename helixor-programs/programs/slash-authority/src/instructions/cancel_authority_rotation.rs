// =============================================================================
// programs/slash-authority/src/instructions/cancel_authority_rotation.rs
//
// SPOF-#2 STEP 4 — veto an open authority-rotation proposal. Admin OR
// any current role key (executor, resolver, pauser) may cancel. A single
// honest role-key holder is enough to block a hostile proposal during
// the 48h review window.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::events::AuthorityRotationCancelled;
use crate::state::{PendingAuthorityRotation, SlashConfig};

#[derive(Accounts)]
pub struct CancelAuthorityRotation<'info> {
    /// SlashConfig — read-only. Source of truth for "is the signer
    /// admin or a current role key?".
    #[account(
        seeds = [SlashConfig::SEED],
        bump  = slash_config.bump,
    )]
    pub slash_config: Account<'info, SlashConfig>,

    /// The pending rotation. Closed; rent refunded to proposer.
    #[account(
        mut,
        seeds = [PendingAuthorityRotation::SEED],
        bump  = pending_rotation.bump,
        has_one = proposer,
        close   = proposer,
    )]
    pub pending_rotation: Account<'info, PendingAuthorityRotation>,

    /// CHECK: rent-refund target. Constrained to equal
    /// `pending_rotation.proposer` via the `has_one` above.
    #[account(mut)]
    pub proposer: SystemAccount<'info>,

    /// The canceller. Must be admin OR a current role key.
    pub canceller: Signer<'info>,
}

pub fn handler(ctx: Context<CancelAuthorityRotation>) -> Result<()> {
    let cfg       = &ctx.accounts.slash_config;
    let canceller = ctx.accounts.canceller.key();

    let is_admin = canceller == cfg.admin;
    let is_role  = canceller == cfg.slash_executor
        || canceller == cfg.appeal_resolver
        || canceller == cfg.pause_authority;
    require!(is_admin || is_role, SlashError::NotRotationCanceller);

    emit!(AuthorityRotationCancelled {
        canceller,
        cancelled_at: Clock::get()?.unix_timestamp,
    });

    msg!(
        "slash-authority rotation CANCELLED by {} — proposal closed",
        canceller,
    );
    Ok(())
}
