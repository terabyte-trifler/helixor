// =============================================================================
// programs/slash-authority/src/instructions/attest_authority_rotation.rs
//
// SPOF-#2 STEP 2 — attest to a pending authority rotation. Only the LIVE
// role keys (executor, resolver, pauser) at attest-time count. Admin
// cannot attest. Double-attestation is rejected.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::events::AuthorityRotationAttested;
use crate::state::{PendingAuthorityRotation, SlashConfig};

#[derive(Accounts)]
pub struct AttestAuthorityRotation<'info> {
    /// SlashConfig — read-only. Source of truth for "is the signer a
    /// current role key?".
    #[account(
        seeds = [SlashConfig::SEED],
        bump  = slash_config.bump,
    )]
    pub slash_config: Account<'info, SlashConfig>,

    /// The pending rotation. Mutated to push a new attestation.
    #[account(
        mut,
        seeds = [PendingAuthorityRotation::SEED],
        bump  = pending_rotation.bump,
    )]
    pub pending_rotation: Account<'info, PendingAuthorityRotation>,

    /// The attester — must be a current role key. Admin cannot attest.
    pub attester: Signer<'info>,
}

pub fn handler(ctx: Context<AttestAuthorityRotation>) -> Result<()> {
    let cfg      = &ctx.accounts.slash_config;
    let attester = ctx.accounts.attester.key();

    // ── Authorisation: live role key only ──────────────────────────────────
    // Locking attestation to the LIVE role-key set (NOT the proposed
    // set) is the core defence. A compromised admin who proposes
    // attacker-controlled new keys cannot then "self-attest" with
    // those new keys: only the existing executor, resolver, pauser
    // count.
    let is_role = attester == cfg.slash_executor
        || attester == cfg.appeal_resolver
        || attester == cfg.pause_authority;
    require!(is_role, SlashError::NotRoleKeyAttester);

    let pending = &mut ctx.accounts.pending_rotation;

    // Reject double-attestation — each role key counts once.
    require!(
        !pending.has_attestation(&attester),
        SlashError::DuplicateAuthorityAttestation,
    );

    pending.attestations.push(attester);

    let clock = Clock::get()?;
    let total    = pending.attestations.len() as u8;
    let required = PendingAuthorityRotation::CONSENSUS_THRESHOLD as u8;

    emit!(AuthorityRotationAttested {
        attester,
        total_attestations:    total,
        required_attestations: required,
        attested_at:           clock.unix_timestamp,
    });

    msg!(
        "slash-authority rotation ATTESTED by {} — {}/{} attestations",
        attester, total, required,
    );
    Ok(())
}
