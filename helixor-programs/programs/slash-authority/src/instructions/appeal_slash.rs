// =============================================================================
// programs/slash-authority/src/instructions/appeal_slash.rs
//
// appeal_slash — an agent owner disputes a Pending slash.
//
//   appeal_slash(ctx, record_index, justification)
//
// The slash transitions Pending -> Appealed. The encumbered funds stay
// held in the vault (they were never moved — see execute_slash); now they
// also cannot be settled until the appeal is resolved. "Funds held, not
// burned" — literally.
//
// GUARDS
//   - signer is the AGENT OWNER (the agent_wallet itself signs). Only the
//     agent can appeal its own slash.
//   - the slash is still Pending (an already-appealed or terminal slash
//     cannot be re-appealed).
//   - the appeal window is still OPEN — an appeal filed after the deadline
//     is rejected; by then the slash is settleable.
//   - `justification` is a non-zero hash — an appeal must cite a reason
//     (the hash commits to off-chain appeal documentation).
//   - the APPEAL COOLDOWN has elapsed since the agent's last appeal — an
//     agent cannot spam appeals across its slash history.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::events::SlashAppealed;
use crate::state::{EscrowVault, SlashRecord, SlashStatus};

/// The minimum interval, in seconds, between two appeals by the same agent.
/// 24h — an agent with several Pending slashes must space its appeals out,
/// which throttles griefing of the resolution authority.
pub const APPEAL_COOLDOWN_SECONDS: i64 = 24 * 3_600;

#[derive(Accounts)]
pub struct AppealSlash<'info> {
    /// The agent's escrow vault — its last_appeal_at is updated here.
    #[account(
        mut,
        seeds = [EscrowVault::SEED_PREFIX, escrow_vault.agent_wallet.as_ref()],
        bump  = escrow_vault.bump,
    )]
    pub escrow_vault: Account<'info, EscrowVault>,

    /// The slash record being appealed. Must belong to this vault.
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

    /// The agent owner — must be the agent_wallet itself. Only the agent
    /// may appeal its own slash.
    #[account(
        constraint = agent_owner.key() == escrow_vault.agent_wallet
            @ SlashError::NotAgentOwner,
    )]
    pub agent_owner: Signer<'info>,
}

pub fn handler(
    ctx:           Context<AppealSlash>,
    justification: [u8; 32],
) -> Result<()> {
    // ── Evidence requirement ────────────────────────────────────────────────
    require!(justification != [0u8; 32], SlashError::ZeroJustification);

    let clock = Clock::get()?;

    // ── Lifecycle: the slash must still be Pending ──────────────────────────
    let status = SlashStatus::from_u8(ctx.accounts.slash_record.status)
        .ok_or(SlashError::WrongSlashStatus)?;
    require!(
        status == SlashStatus::Pending,
        SlashError::WrongSlashStatus,
    );

    // ── The appeal window must still be open ────────────────────────────────
    require!(
        ctx.accounts.slash_record.appeal_window_open(clock.unix_timestamp),
        SlashError::AppealWindowClosed,
    );

    // ── Appeal cooldown ─────────────────────────────────────────────────────
    // An agent that has appealed before must wait out the cooldown. The
    // first-ever appeal (last_appeal_at == 0) is always allowed.
    let last = ctx.accounts.escrow_vault.last_appeal_at;
    if last != 0 {
        require!(
            clock.unix_timestamp.saturating_sub(last) >= APPEAL_COOLDOWN_SECONDS,
            SlashError::AppealCooldownActive,
        );
    }

    // ── Transition Pending -> Appealed ──────────────────────────────────────
    let record = &mut ctx.accounts.slash_record;
    record.status      = SlashStatus::Appealed.as_u8();
    record.appeal_hash = justification;
    record.appealed_at = clock.unix_timestamp;

    ctx.accounts.escrow_vault.last_appeal_at = clock.unix_timestamp;

    emit!(SlashAppealed {
        agent_wallet: record.agent_wallet,
        index:        record.index,
        appeal_hash:  justification,
        appealed_at:  clock.unix_timestamp,
    });

    msg!(
        "slash appealed: agent={} index={} — entering review, funds held",
        record.agent_wallet, record.index,
    );
    Ok(())
}
