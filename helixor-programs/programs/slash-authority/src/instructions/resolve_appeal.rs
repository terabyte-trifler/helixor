// =============================================================================
// programs/slash-authority/src/instructions/resolve_appeal.rs
//
// resolve_appeal — the slash authority resolves an Appealed slash.
//
//   resolve_appeal(ctx, uphold: bool)
//
// Two outcomes:
//
//   uphold = false  -> the appeal SUCCEEDS. The slash is OVERTURNED: the
//                      encumbered lamports are released back into the
//                      vault's free `staked_lamports`. The agent loses
//                      nothing. The record is terminal (Overturned).
//
//   uphold = true   -> the appeal FAILS. The slash stands. The record
//                      returns to Pending with its appeal window
//                      RE-CLOSED (appeal_deadline set to now), so it
//                      becomes immediately settleable via settle_slash.
//
// AUTHORITY: only the slash authority (the Phase-4 multisig stand-in) may
// resolve an appeal — the same authority that executes slashes. In Phase 4
// this becomes the threshold authority, making resolution a multi-party
// decision rather than one key.
//
// No lamports leave the vault here. An overturn just RE-LABELS encumbered
// funds back to free; an upheld appeal leaves them encumbered for
// settle_slash to move. "Funds held, not burned" holds throughout.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::events::AppealResolved;
use crate::state::{EscrowVault, SlashConfig, SlashRecord, SlashStatus};

#[derive(Accounts)]
pub struct ResolveAppeal<'info> {
    /// The agent's escrow vault.
    #[account(
        mut,
        seeds = [EscrowVault::SEED_PREFIX, escrow_vault.agent_wallet.as_ref()],
        bump  = escrow_vault.bump,
    )]
    pub escrow_vault: Account<'info, EscrowVault>,

    /// The slash record under appeal. Must belong to this vault and be
    /// in the Appealed state.
    #[account(
        mut,
        seeds = [
            SlashRecord::SEED_PREFIX,
            escrow_vault.agent_wallet.as_ref(),
            &slash_record.index.to_le_bytes(),
        ],
        bump = slash_record.bump,
        constraint = slash_record.agent_wallet == escrow_vault.agent_wallet
            @ SlashError::RecordVaultMismatch,
    )]
    pub slash_record: Account<'info, SlashRecord>,

    /// SlashConfig — verifies the resolver is the slash authority.
    #[account(
        seeds = [SlashConfig::SEED],
        bump  = slash_config.bump,
    )]
    pub slash_config: Account<'info, SlashConfig>,

    /// The slash authority — resolves the appeal.
    #[account(
        constraint = slash_authority.key() == slash_config.slash_authority
            @ SlashError::NotSlashAuthority,
    )]
    pub slash_authority: Signer<'info>,
}

pub fn handler(ctx: Context<ResolveAppeal>, uphold: bool) -> Result<()> {
    let clock = Clock::get()?;

    // ── Lifecycle: the slash must be Appealed ───────────────────────────────
    let status = SlashStatus::from_u8(ctx.accounts.slash_record.status)
        .ok_or(SlashError::WrongSlashStatus)?;
    require!(
        status == SlashStatus::Appealed,
        SlashError::WrongSlashStatus,
    );

    let amount = ctx.accounts.slash_record.slashed_lamports;

    if uphold {
        // ── Appeal FAILS — the slash stands ─────────────────────────────────
        // Return the record to Pending, but with the appeal window already
        // closed, so settle_slash can finalise it immediately. The funds
        // stay encumbered until then.
        let record = &mut ctx.accounts.slash_record;
        record.status          = SlashStatus::Pending.as_u8();
        record.appeal_deadline = clock.unix_timestamp; // window closed now
    } else {
        // ── Appeal SUCCEEDS — the slash is OVERTURNED ───────────────────────
        // Release the encumbered lamports back to free stake. No lamports
        // move in or out of the vault account — the funds were never gone,
        // only re-labelled; we re-label them back.
        let vault = &mut ctx.accounts.escrow_vault;
        vault.encumbered_lamports = vault.encumbered_lamports
            .checked_sub(amount)
            .ok_or(SlashError::MathOverflow)?;
        vault.staked_lamports = vault.staked_lamports
            .checked_add(amount)
            .ok_or(SlashError::MathOverflow)?;

        let record = &mut ctx.accounts.slash_record;
        record.status = SlashStatus::Overturned.as_u8();
    }

    emit!(AppealResolved {
        agent_wallet: ctx.accounts.slash_record.agent_wallet,
        index:        ctx.accounts.slash_record.index,
        upheld:       uphold,
        released_lamports: if uphold { 0 } else { amount },
        resolved_at:  clock.unix_timestamp,
    });

    msg!(
        "appeal resolved: agent={} index={} upheld={}",
        ctx.accounts.slash_record.agent_wallet,
        ctx.accounts.slash_record.index,
        uphold,
    );
    Ok(())
}
