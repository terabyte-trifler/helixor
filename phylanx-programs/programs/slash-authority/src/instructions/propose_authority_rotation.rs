// =============================================================================
// programs/slash-authority/src/instructions/propose_authority_rotation.rs
//
// SPOF-#2 STEP 1 — propose a slash-authority rotation. Mirrors VULN-13's
// propose_oracle_key_rotation in the health-oracle program.
//
// Authorisation: admin OR any current role key (executor, resolver, pauser).
// Cluster members who propose are auto-attested (their proposal IS their vote).
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::events::AuthorityRotationProposed;
use crate::state::{
    validate_authority_separation, AuthoritySeparationError, PendingAuthorityRotation,
    SlashConfig, MIN_SETTLEMENT_TIMELOCK_SECONDS,
};

#[derive(Accounts)]
pub struct ProposeAuthorityRotation<'info> {
    /// SlashConfig — read-only here. Supplies admin + the live role-key
    /// set against which `proposer` is authorised.
    #[account(
        seeds = [SlashConfig::SEED],
        bump  = slash_config.bump,
    )]
    pub slash_config: Account<'info, SlashConfig>,

    /// The new pending-rotation PDA. Singleton: Anchor's `init` fails if
    /// a previous proposal is still open.
    #[account(
        init,
        payer = proposer,
        space = PendingAuthorityRotation::SPACE,
        seeds = [PendingAuthorityRotation::SEED],
        bump,
    )]
    pub pending_rotation: Account<'info, PendingAuthorityRotation>,

    /// The proposer. Pays rent, becomes rent-refund target on enact / cancel.
    #[account(mut)]
    pub proposer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:                                 Context<ProposeAuthorityRotation>,
    new_slash_executor:                  Pubkey,
    new_appeal_resolver:                 Pubkey,
    new_pause_authority:                 Pubkey,
    new_treasury:                        Pubkey,
    new_settlement_timelock_seconds:     i64,
    timelock_seconds:                    i64,
) -> Result<()> {
    let cfg      = &ctx.accounts.slash_config;
    let proposer = ctx.accounts.proposer.key();

    // ── Authorisation: admin OR current role key ───────────────────────────
    // SPOF-#2 design: admin and role keys may BOTH propose, but admin
    // alone cannot enact. A role-key proposer is also auto-attested.
    let is_admin = proposer == cfg.admin;
    let is_role  = proposer == cfg.slash_executor
        || proposer == cfg.appeal_resolver
        || proposer == cfg.pause_authority;
    require!(is_admin || is_role, SlashError::NotRotationProposer);

    // ── Validate proposed authority set ────────────────────────────────────
    // Re-runs validate_authority_separation so a malformed proposal is
    // rejected at PROPOSE time (operators reviewing the open proposal
    // in the 48h window can trust that what would land is well-formed).
    // M-3: the proposed role set must also be distinct from the (unchanged)
    // admin — a rotation must not install a role key equal to admin.
    match validate_authority_separation(
        &cfg.admin,
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
        Err(AuthoritySeparationError::AdminCollidesWithRole) => {
            return err!(SlashError::AdminMustDifferFromRoles);
        }
    }

    // Treasury must be non-default. May equal current treasury.
    require!(
        new_treasury != Pubkey::default(),
        SlashError::DefaultPubkey,
    );

    // Settlement timelock floor. May only increase or stay at current.
    require!(
        new_settlement_timelock_seconds >= MIN_SETTLEMENT_TIMELOCK_SECONDS,
        SlashError::SettlementTimelockTooShort,
    );

    // ── Reject no-op rotations ─────────────────────────────────────────────
    let same_set = new_slash_executor  == cfg.slash_executor
        && new_appeal_resolver  == cfg.appeal_resolver
        && new_pause_authority  == cfg.pause_authority
        && new_treasury         == cfg.treasury
        && new_settlement_timelock_seconds == cfg.settlement_timelock_seconds;
    require!(!same_set, SlashError::NoopAuthorityRotation);

    // ── Timelock floor: 48h review window ──────────────────────────────────
    require!(
        timelock_seconds >= PendingAuthorityRotation::MIN_TIMELOCK_SECONDS,
        SlashError::RotationTimelockTooShort,
    );

    let clock = Clock::get()?;
    let enact_after = clock.unix_timestamp.saturating_add(timelock_seconds);

    let pending = &mut ctx.accounts.pending_rotation;
    pending.proposer                        = proposer;
    pending.new_slash_executor              = new_slash_executor;
    pending.new_appeal_resolver             = new_appeal_resolver;
    pending.new_pause_authority             = new_pause_authority;
    pending.new_treasury                    = new_treasury;
    pending.new_settlement_timelock_seconds = new_settlement_timelock_seconds;
    pending.enact_after                     = enact_after;
    pending.proposed_at                     = clock.unix_timestamp;
    pending.bump                            = ctx.bumps.pending_rotation;
    pending.attestations                    = Vec::new();

    // Role-key proposers self-attest. Admin is NOT auto-attested by
    // design — admin cannot count toward the cluster's consent.
    if is_role {
        pending.attestations.push(proposer);
    }

    emit!(AuthorityRotationProposed {
        proposer,
        new_slash_executor,
        new_appeal_resolver,
        new_pause_authority,
        new_treasury,
        new_settlement_timelock_seconds,
        enact_after,
        proposed_at: clock.unix_timestamp,
    });

    msg!(
        "slash-authority rotation PROPOSED by {} — enact_after={}, \
         pre-attestations={}",
        proposer, enact_after, pending.attestations.len(),
    );
    Ok(())
}
