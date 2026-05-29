// =============================================================================
// programs/slash-authority/src/instructions/resolve_appeal.rs
//
// resolve_appeal — the APPEAL_RESOLVER (not the slash_executor) resolves
// an Appealed slash.
//
//   resolve_appeal(ctx, uphold: bool)
//
// VULN-04 — INDEPENDENT REVIEW + POST-UPHOLD TIMELOCK
// ---------------------------------------------------
// Pre-VULN-04 the same `slash_authority` key that executed a slash also
// resolved its appeal. A compromised or malicious holder could slash an
// agent, then immediately uphold its own slash, then settle the funds.
// We now require two independent gates:
//
//   AUTHORITY      : signer must be `slash_config.appeal_resolver`,
//                    which is enforced to differ from `slash_executor`
//                    at config init/update time (`AuthoritiesMustDiffer`).
//                    The handler ADDITIONALLY refuses if the signer is
//                    the executor of THIS specific slash record — an
//                    operational defence in depth for the rare race
//                    where roles were rotated mid-flight.
//
//   POST-UPHOLD    : an upheld appeal no longer immediately re-closes
//   TIMELOCK         the window. The slash record's
//                    `settlement_unlock_at` is set to
//                    `now + slash_config.settlement_timelock_seconds`
//                    (>= 72h). settle_slash refuses until that elapses,
//                    giving governance / the pause_authority time to
//                    intervene if both executor AND resolver are
//                    compromised.
//
// Two outcomes:
//
//   uphold = false  -> the appeal SUCCEEDS. The slash is OVERTURNED:
//                      the encumbered lamports are released back into
//                      the vault's free `staked_lamports`. The agent
//                      loses nothing. The record is terminal (Overturned).
//
//   uphold = true   -> the appeal FAILS. The record returns to Pending
//                      with `appeal_deadline = now` (so the appeal
//                      window doesn't artificially block settlement)
//                      but `settlement_unlock_at = now + timelock` —
//                      settle_slash is gated on BOTH being satisfied.
//
// `appeal_resolved_by` is recorded in either case for the audit trail.
//
// No lamports leave the vault here. An overturn re-labels encumbered
// funds back to free; an upheld appeal leaves them encumbered for
// settle_slash to move AFTER the timelock. "Funds held, not burned"
// holds throughout.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::events::AppealResolved;
use crate::state::{EscrowVault, SlashConfig, SlashRecord, SlashStatus};

#[derive(Accounts)]
pub struct ResolveAppeal<'info> {
    /// The agent's escrow vault.
    ///
    /// H-02: a terminal Compromise settlement on a sibling slash
    /// deactivates the vault (`settle_slash` sets `vault.active = false`).
    /// Without this constraint, an Appealed sibling could otherwise be
    /// resolved on an already-inactive vault, leaving the audit trail
    /// carrying "Overturned" records that contradict the vault's zeroed
    /// lamport state. Matches the guard on `execute_slash`.
    #[account(
        mut,
        seeds = [EscrowVault::SEED_PREFIX, escrow_vault.agent_wallet.as_ref()],
        bump  = escrow_vault.bump,
        constraint = escrow_vault.active @ SlashError::VaultInactive,
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

    /// SlashConfig — verifies the resolver and supplies the timelock.
    #[account(
        seeds = [SlashConfig::SEED],
        bump  = slash_config.bump,
    )]
    pub slash_config: Account<'info, SlashConfig>,

    /// The appeal resolver — distinct from `slash_executor` (enforced at
    /// config init/update) AND distinct from the executor of this
    /// specific slash record (enforced in the handler).
    #[account(
        constraint = appeal_resolver.key() == slash_config.appeal_resolver
            @ SlashError::NotAppealResolver,
    )]
    pub appeal_resolver: Signer<'info>,
}

pub fn handler(ctx: Context<ResolveAppeal>, uphold: bool) -> Result<()> {
    let clock = Clock::get()?;

    // ── Refuse while paused ─────────────────────────────────────────────────
    // H-04: time-aware check — an expired pause does not block resolution.
    require!(
        !ctx.accounts.slash_config.is_paused_now(clock.unix_timestamp),
        SlashError::SettlementsPaused,
    );

    // ── Lifecycle: the slash must be Appealed ───────────────────────────────
    let status = SlashStatus::from_u8(ctx.accounts.slash_record.status)
        .ok_or(SlashError::WrongSlashStatus)?;
    require!(
        status == SlashStatus::Appealed,
        SlashError::WrongSlashStatus,
    );

    // ── VULN-04 defence in depth: the resolver may NOT be the executor
    //    of this specific slash. Belt-and-braces on top of the config-
    //    level separation, in case role keys were rotated mid-lifecycle.
    require!(
        ctx.accounts.appeal_resolver.key() != ctx.accounts.slash_record.executor,
        SlashError::ResolverIsExecutor,
    );

    let amount = ctx.accounts.slash_record.slashed_lamports;
    let timelock = ctx.accounts.slash_config.settlement_timelock_seconds;
    let resolver_key = ctx.accounts.appeal_resolver.key();

    if uphold {
        // ── Appeal FAILS — the slash stands ─────────────────────────────────
        // Return the record to Pending with the appeal window already
        // closed, BUT block settlement for at least `timelock` seconds
        // (VULN-04). settle_slash must wait until BOTH appeal_deadline
        // and settlement_unlock_at have passed. The funds stay
        // encumbered the entire time.
        let unlock_at = clock.unix_timestamp
            .checked_add(timelock)
            .ok_or(SlashError::MathOverflow)?;
        let record = &mut ctx.accounts.slash_record;
        record.status               = SlashStatus::Pending.as_u8();
        record.appeal_deadline      = clock.unix_timestamp;
        record.settlement_unlock_at = unlock_at;
        record.appeal_resolved_by   = resolver_key;

        // M-01: release the in-flight slot — the slash is no longer
        // Appealed, so it no longer counts against the per-vault cap.
        let vault = &mut ctx.accounts.escrow_vault;
        vault.appeals_in_flight = vault.appeals_in_flight
            .checked_sub(1)
            .ok_or(SlashError::MathOverflow)?;
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
        // M-01: release the in-flight slot — same as the uphold path,
        // the slash is leaving the Appealed state.
        vault.appeals_in_flight = vault.appeals_in_flight
            .checked_sub(1)
            .ok_or(SlashError::MathOverflow)?;

        let record = &mut ctx.accounts.slash_record;
        record.status             = SlashStatus::Overturned.as_u8();
        record.appeal_resolved_by = resolver_key;
        // Overturned records have no settlement timelock — they cannot
        // be settled at all.
        record.settlement_unlock_at = 0;
    }

    emit!(AppealResolved {
        agent_wallet: ctx.accounts.slash_record.agent_wallet,
        index:        ctx.accounts.slash_record.index,
        upheld:       uphold,
        released_lamports: if uphold { 0 } else { amount },
        resolved_at:  clock.unix_timestamp,
    });

    msg!(
        "appeal resolved: agent={} index={} upheld={} resolver={}",
        ctx.accounts.slash_record.agent_wallet,
        ctx.accounts.slash_record.index,
        uphold,
        resolver_key,
    );
    Ok(())
}
