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
//   - M-01: this vault must have NO other Appealed slash in flight. The
//     pre-existing 24h `last_appeal_at` cooldown only paced filings; it
//     did not cap how many appeals could be open at once. An agent with
//     N pending slashes could sequentially appeal each within the 72h
//     appeal window (1 per cooldown cycle) and stall N settlements in
//     parallel. The new HARD gate is `appeals_in_flight == 0`. Only one
//     appeal per vault may be open at a time; the agent must wait for
//     resolve_appeal on the existing appeal before filing another.
//   - the APPEAL COOLDOWN has elapsed since the agent's last appeal —
//     soft anti-spam, retained as defence in depth on top of M-01.
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
    ///
    /// H-02: a terminal Compromise settlement deactivates the vault
    /// (`settle_slash` sets `vault.active = false`). A vault can carry
    /// multiple slash records, so a Pending sibling could otherwise be
    /// appealed on an already-deactivated vault, drifting the
    /// state-machine (an inactive vault carrying "Appealed" records that
    /// contradict its zeroed lamport status). The same constraint that
    /// guards `execute_slash` belongs here.
    #[account(
        mut,
        seeds = [EscrowVault::SEED_PREFIX, escrow_vault.agent_wallet.as_ref()],
        bump  = escrow_vault.bump,
        constraint = escrow_vault.active @ SlashError::VaultInactive,
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

    // ── M-01: per-vault in-flight cap ───────────────────────────────────────
    // Hard gate: at most one Appealed slash per vault at a time. This
    // strictly bounds how many settlements a single agent can stall in
    // parallel, regardless of how many Pending slashes exist or how the
    // 24h cooldown spaces filings.
    require!(
        ctx.accounts.escrow_vault.appeals_in_flight
            < EscrowVault::MAX_APPEALS_IN_FLIGHT,
        SlashError::AppealAlreadyInFlight,
    );

    // ── Appeal cooldown ─────────────────────────────────────────────────────
    // Soft anti-spam: an agent that has appealed before must wait out
    // the 24h cooldown. With M-01 in place the cap of one in-flight
    // appeal already makes back-to-back filings impossible until the
    // current appeal resolves; the cooldown is retained as defence in
    // depth in case a resolver auto-resolves appeals very quickly. The
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

    let vault = &mut ctx.accounts.escrow_vault;
    vault.last_appeal_at    = clock.unix_timestamp;
    vault.appeals_in_flight = vault.appeals_in_flight
        .checked_add(1)
        .ok_or(SlashError::MathOverflow)?;

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
