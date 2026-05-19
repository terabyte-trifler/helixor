// =============================================================================
// programs/slash-authority/src/instructions/settle_slash.rs
//
// settle_slash — finalise a Pending slash after its appeal window closes.
//
// This is the second half of the slash lifecycle that Day 21 split out of
// Day 20's execute_slash. execute_slash ENCUMBERED the funds (held them in
// the vault); settle_slash MOVES them — to the treasury for a Minor/Major
// penalty, or to the incinerator (burned) for a Compromise.
//
// PRECONDITIONS
//   - the SlashRecord is still Pending (an Appealed slash must be resolved
//     first; an Overturned/Settled slash is terminal),
//   - the appeal window has CLOSED — `now >= appeal_deadline`. A slash can
//     never be settled while the agent could still appeal it.
//
// HOW LAMPORTS LEAVE THE VAULT — same direct-mutation pattern as Day 20:
// the vault is program-owned, so we cannot System-transfer out of it; we
// debit the vault's lamports and credit the destination's directly. Only
// the `encumbered_lamports` for THIS slash is moved, and the vault stays
// at or above its rent-exempt minimum.
//
// A Compromise settlement also DEACTIVATES the vault — the terminal step
// Day 20 did inline, now deferred here so an appeal could have rescued it.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::events::SlashSettled;
use crate::state::{
    EscrowVault, OffenseTier, SlashConfig, SlashDestination, SlashRecord,
    SlashStatus,
};

#[derive(Accounts)]
pub struct SettleSlash<'info> {
    /// The agent's escrow vault — the encumbered funds leave it here.
    #[account(
        mut,
        seeds = [EscrowVault::SEED_PREFIX, escrow_vault.agent_wallet.as_ref()],
        bump  = escrow_vault.bump,
    )]
    pub escrow_vault: Account<'info, EscrowVault>,

    /// The slash record being settled. Must belong to this vault and be
    /// Pending.
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

    /// SlashConfig — verifies the signer and supplies the treasury key.
    #[account(
        seeds = [SlashConfig::SEED],
        bump  = slash_config.bump,
    )]
    pub slash_config: Account<'info, SlashConfig>,

    /// Where the slashed lamports go: the treasury for a Minor/Major slash,
    /// the incinerator for a Compromise. Validated against the record's
    /// tier in the handler.
    /// CHECK: only RECEIVES lamports; validated against the offense tier.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,

    /// The slash authority — settlement is an authority action.
    #[account(
        constraint = slash_authority.key() == slash_config.slash_authority
            @ SlashError::NotSlashAuthority,
    )]
    pub slash_authority: Signer<'info>,
}

pub fn handler(ctx: Context<SettleSlash>) -> Result<()> {
    let clock = Clock::get()?;

    // ── Lifecycle preconditions ─────────────────────────────────────────────
    let status = SlashStatus::from_u8(ctx.accounts.slash_record.status)
        .ok_or(SlashError::WrongSlashStatus)?;
    require!(
        status == SlashStatus::Pending,
        SlashError::WrongSlashStatus,
    );
    // The appeal window must have CLOSED.
    require!(
        !ctx.accounts.slash_record.appeal_window_open(clock.unix_timestamp),
        SlashError::AppealWindowStillOpen,
    );

    let tier = OffenseTier::from_u8(ctx.accounts.slash_record.offense_tier)
        .ok_or(SlashError::InvalidOffenseTier)?;
    let amount = ctx.accounts.slash_record.slashed_lamports;

    // ── Verify the destination matches the tier ─────────────────────────────
    let required_destination = tier.destination();
    let destination_key = ctx.accounts.destination.key();
    match required_destination {
        SlashDestination::Treasury => require!(
            destination_key == ctx.accounts.slash_config.treasury,
            SlashError::WrongDestination,
        ),
        SlashDestination::Burn => require!(
            destination_key == SlashConfig::INCINERATOR,
            SlashError::WrongDestination,
        ),
    }

    // ── Move the encumbered lamports OUT of the vault ───────────────────────
    // Direct lamport mutation — the vault is program-owned. Scoped so the
    // AccountInfo borrows release before the &mut field writes below.
    {
        let vault_ai = ctx.accounts.escrow_vault.to_account_info();
        let dest_ai  = ctx.accounts.destination.to_account_info();

        let rent = Rent::get()?;
        let rent_min = rent.minimum_balance(vault_ai.data_len());

        let vault_after = vault_ai
            .lamports()
            .checked_sub(amount)
            .ok_or(SlashError::MathOverflow)?;
        require!(vault_after >= rent_min, SlashError::RentViolation);

        **vault_ai.try_borrow_mut_lamports()? = vault_after;
        let dest_after = dest_ai
            .lamports()
            .checked_add(amount)
            .ok_or(SlashError::MathOverflow)?;
        **dest_ai.try_borrow_mut_lamports()? = dest_after;
    }

    // ── Update vault bookkeeping ────────────────────────────────────────────
    let vault = &mut ctx.accounts.escrow_vault;
    vault.encumbered_lamports = vault.encumbered_lamports
        .checked_sub(amount)
        .ok_or(SlashError::MathOverflow)?;
    vault.total_slashed_lamports = vault.total_slashed_lamports
        .checked_add(amount)
        .ok_or(SlashError::MathOverflow)?;
    // A Compromise settlement is the terminal step — deactivate the vault.
    if tier.is_terminal() {
        vault.active = false;
    }

    // ── Mark the record Settled ─────────────────────────────────────────────
    let record = &mut ctx.accounts.slash_record;
    record.status = SlashStatus::Settled.as_u8();

    emit!(SlashSettled {
        agent_wallet:    record.agent_wallet,
        index:           record.index,
        settled_lamports: amount,
        destination:     required_destination.as_u8(),
        terminal:        tier.is_terminal(),
        settled_at:      clock.unix_timestamp,
    });

    msg!(
        "slash settled: agent={} index={} amount={} destination={:?} terminal={}",
        record.agent_wallet, record.index, amount,
        required_destination, tier.is_terminal(),
    );
    Ok(())
}
