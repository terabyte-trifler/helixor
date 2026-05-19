// =============================================================================
// programs/slash-authority/src/instructions/execute_slash.rs
//
// execute_slash — record a tiered slash and ENCUMBER the collateral.
//
// DAY-21 REFINEMENT OF DAY 20
// ---------------------------
// Day 20's execute_slash moved lamports out of the vault IMMEDIATELY. Day
// 21 introduces appeals — and an appeal is meaningless if the funds (or,
// worse, a burn) already happened. So the lifecycle changes:
//
//   execute_slash  -> records a PENDING slash and ENCUMBERS the funds:
//                     they move from staked_lamports into
//                     encumbered_lamports, but stay PHYSICALLY in the vault
//                     account. Nothing is transferred out. Nothing is
//                     burned. The appeal window opens.
//
//   then either:
//     appeal_slash + resolve_appeal(overturned) -> encumbered funds are
//                     released back to staked_lamports. No loss.
//   or:
//     settle_slash (after the appeal window) -> the encumbered funds
//                     finally leave the vault (to treasury, or burned).
//
// So "funds held, not burned" is literally true: between execute_slash and
// settle_slash the lamports sit untouched in the vault, merely re-labelled.
//
// AUTHORITY: only the configured slash_authority (the Phase-4 multisig
// stand-in) may execute a slash.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::events::SlashExecuted;
use crate::state::{
    compute_slash_amount, EscrowVault, OffenseTier, SlashConfig,
    SlashRecord, SlashStatus, APPEAL_WINDOW_SECONDS,
};

#[derive(Accounts)]
#[instruction(index: u64)]
pub struct ExecuteSlash<'info> {
    /// The agent's escrow vault — its collateral is encumbered here.
    #[account(
        mut,
        seeds = [EscrowVault::SEED_PREFIX, escrow_vault.agent_wallet.as_ref()],
        bump  = escrow_vault.bump,
        constraint = escrow_vault.active @ SlashError::VaultInactive,
    )]
    pub escrow_vault: Account<'info, EscrowVault>,

    /// The SlashRecord for this slash — created here, write-once. `index`
    /// must equal the vault's current slash_count (checked in the handler).
    #[account(
        init,
        payer = slash_authority,
        space = SlashRecord::SPACE,
        seeds = [
            SlashRecord::SEED_PREFIX,
            escrow_vault.agent_wallet.as_ref(),
            &index.to_le_bytes(),
        ],
        bump,
    )]
    pub slash_record: Account<'info, SlashRecord>,

    /// SlashConfig — verifies the signer is the slash authority.
    #[account(
        seeds = [SlashConfig::SEED],
        bump  = slash_config.bump,
    )]
    pub slash_config: Account<'info, SlashConfig>,

    /// The slash authority — signs the slash and pays the SlashRecord rent.
    #[account(
        mut,
        constraint = slash_authority.key() == slash_config.slash_authority
            @ SlashError::NotSlashAuthority,
    )]
    pub slash_authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:           Context<ExecuteSlash>,
    index:         u64,
    offense_tier:  u8,
    evidence_hash: [u8; 32],
) -> Result<()> {
    // -- Validate inputs ----------------------------------------------------
    let tier = OffenseTier::from_u8(offense_tier)
        .ok_or(SlashError::InvalidOffenseTier)?;
    require!(evidence_hash != [0u8; 32], SlashError::ZeroEvidence);

    // The SlashRecord index must be the vault's NEXT slash index -- keeps
    // the ["slash", agent, count] history strictly append-only.
    require!(
        index == ctx.accounts.escrow_vault.slash_count,
        SlashError::SlashIndexMismatch,
    );

    let stake_before = ctx.accounts.escrow_vault.staked_lamports;
    require!(stake_before > 0, SlashError::NothingToSlash);

    // -- Compute the slash amount -------------------------------------------
    let slash_amount = compute_slash_amount(stake_before, tier);
    let stake_after = stake_before
        .checked_sub(slash_amount)
        .ok_or(SlashError::MathOverflow)?;

    // -- ENCUMBER the funds -- do NOT move them -----------------------------
    // The lamports stay physically in the vault account. We merely move the
    // bookkeeping figure from `staked_lamports` (free) to
    // `encumbered_lamports` (held, pending settlement). No transfer, no burn.
    let clock = Clock::get()?;
    let vault = &mut ctx.accounts.escrow_vault;
    vault.staked_lamports     = stake_after;
    vault.encumbered_lamports = vault.encumbered_lamports
        .checked_add(slash_amount)
        .ok_or(SlashError::MathOverflow)?;
    vault.slash_count         = vault.slash_count
        .checked_add(1)
        .ok_or(SlashError::MathOverflow)?;
    // NOTE: the vault is NOT deactivated here even for a Compromise -- that
    // happens at settlement, so an appeal can still rescue the agent.

    // -- Write the PENDING SlashRecord --------------------------------------
    let record = &mut ctx.accounts.slash_record;
    record.agent_wallet     = vault.agent_wallet;
    record.index            = index;
    record.offense_tier     = tier.as_u8();
    record.slashed_lamports = slash_amount;
    record.destination      = tier.destination().as_u8();
    record.evidence_hash    = evidence_hash;
    record.stake_before     = stake_before;
    record.stake_after      = stake_after;
    record.executed_at      = clock.unix_timestamp;
    record.executor         = ctx.accounts.slash_authority.key();
    record.bump             = ctx.bumps.slash_record;
    record.layout_version   = SlashRecord::CURRENT_LAYOUT_VERSION;
    // Day-21 lifecycle: the slash starts PENDING with an open appeal window.
    record.status           = SlashStatus::Pending.as_u8();
    record.appeal_deadline  = clock.unix_timestamp
        .checked_add(APPEAL_WINDOW_SECONDS)
        .ok_or(SlashError::MathOverflow)?;
    record.appeal_hash      = [0u8; 32];
    record.appealed_at      = 0;

    emit!(SlashExecuted {
        agent_wallet:     vault.agent_wallet,
        index,
        offense_tier:     tier.as_u8(),
        slashed_lamports: slash_amount,
        destination:      record.destination,
        stake_after,
        terminal:         tier.is_terminal(),
        executor:         ctx.accounts.slash_authority.key(),
        executed_at:      clock.unix_timestamp,
    });

    msg!(
        "slash recorded (PENDING): agent={} tier={:?} amount={} encumbered",
        vault.agent_wallet, tier, slash_amount,
    );
    Ok(())
}
