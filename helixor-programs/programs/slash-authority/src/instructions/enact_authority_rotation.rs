// =============================================================================
// programs/slash-authority/src/instructions/enact_authority_rotation.rs
//
// SPOF-#2 STEP 3 — enact a fully-vetted PendingAuthorityRotation. Anyone
// may call once both gates hold:
//   1. timelock elapsed                     (`now >= enact_after`)
//   2. 2-of-3 role keys have attested       (`attestations >= 2`)
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::events::AuthorityRotationEnacted;
use crate::state::{
    validate_authority_separation, AuthoritySeparationError,
    PendingAuthorityRotation, SlashConfig, MIN_SETTLEMENT_TIMELOCK_SECONDS,
};

#[derive(Accounts)]
pub struct EnactAuthorityRotation<'info> {
    /// SlashConfig — mutated to install the new role set + treasury.
    #[account(
        mut,
        seeds = [SlashConfig::SEED],
        bump  = slash_config.bump,
    )]
    pub slash_config: Account<'info, SlashConfig>,

    /// The pending rotation. Closed on success; rent refunded to proposer.
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

    /// Anyone may finalise a ratified proposal.
    pub enactor: Signer<'info>,
}

pub fn handler(ctx: Context<EnactAuthorityRotation>) -> Result<()> {
    let clock = Clock::get()?;
    let now   = clock.unix_timestamp;

    // Snapshot the proposal BEFORE we mutate SlashConfig. The pending
    // PDA closes at end-of-instruction via `close = proposer`, so we
    // copy out everything we need first.
    let pending = &ctx.accounts.pending_rotation;
    let new_slash_executor              = pending.new_slash_executor;
    let new_appeal_resolver             = pending.new_appeal_resolver;
    let new_pause_authority             = pending.new_pause_authority;
    let new_treasury                    = pending.new_treasury;
    let new_settlement_timelock_seconds = pending.new_settlement_timelock_seconds;
    let enact_after                     = pending.enact_after;
    let attestation_count               = pending.attestations.len();

    // ── Gate 1: timelock ───────────────────────────────────────────────────
    require!(now >= enact_after, SlashError::RotationTimelockNotElapsed);

    // ── Gate 2: 2-of-3 attestations ────────────────────────────────────────
    require!(
        pending.is_enactable(now),
        SlashError::InsufficientAuthorityAttestations,
    );

    // ── Defence-in-depth re-validation ─────────────────────────────────────
    // The propose handler already enforced these; re-checking here means a
    // malformed PendingAuthorityRotation (somehow written by a future
    // buggy instruction) cannot land an invalid role set.
    match validate_authority_separation(
        &new_slash_executor,
        &new_appeal_resolver,
        &new_pause_authority,
    ) {
        Ok(()) => {}
        Err(AuthoritySeparationError::DefaultPubkey) => {
            return err!(SlashError::DefaultPubkey);
        }
        Err(AuthoritySeparationError::NotDistinct) => {
            return err!(SlashError::AuthoritiesMustDiffer);
        }
    }
    require!(
        new_treasury != Pubkey::default(),
        SlashError::DefaultPubkey,
    );
    require!(
        new_settlement_timelock_seconds >= MIN_SETTLEMENT_TIMELOCK_SECONDS,
        SlashError::SettlementTimelockTooShort,
    );

    // ── Apply ──────────────────────────────────────────────────────────────
    let cfg = &mut ctx.accounts.slash_config;
    let old_slash_executor              = cfg.slash_executor;
    let old_appeal_resolver             = cfg.appeal_resolver;
    let old_pause_authority             = cfg.pause_authority;
    let old_treasury                    = cfg.treasury;
    let old_settlement_timelock_seconds = cfg.settlement_timelock_seconds;

    cfg.slash_executor              = new_slash_executor;
    cfg.appeal_resolver             = new_appeal_resolver;
    cfg.pause_authority             = new_pause_authority;
    cfg.treasury                    = new_treasury;
    cfg.settlement_timelock_seconds = new_settlement_timelock_seconds;

    emit!(AuthorityRotationEnacted {
        enactor: ctx.accounts.enactor.key(),
        old_slash_executor,
        new_slash_executor,
        old_appeal_resolver,
        new_appeal_resolver,
        old_pause_authority,
        new_pause_authority,
        old_treasury,
        new_treasury,
        old_settlement_timelock_seconds,
        new_settlement_timelock_seconds,
        attestation_count: attestation_count as u8,
        enacted_at:        now,
    });

    msg!(
        "slash-authority rotation ENACTED by {} — attestations={}",
        ctx.accounts.enactor.key(), attestation_count,
    );
    Ok(())
}
