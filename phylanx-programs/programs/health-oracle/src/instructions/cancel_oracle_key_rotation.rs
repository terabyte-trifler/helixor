// =============================================================================
// programs/health-oracle/src/instructions/cancel_oracle_key_rotation.rs
//
// VULN-13 — STEP 4 of the time-locked, N-of-M-attested key rotation ceremony.
// The veto path. Open to admin OR any current cluster member at any time
// before enactment.
//
// WHAT THIS DOES
// --------------
// Closes the open `PendingOracleRotation` PDA and refunds rent to the
// original proposer. Emits `OracleRotationCancelled`.
//
// WHY OPEN TO ANY CLUSTER MEMBER
// ------------------------------
// Defence in depth: if a compromised admin (or a compromised cluster
// member) proposes a hostile rotation, any one of the OTHER cluster
// members can shoot it down unilaterally. The 48h timelock combined with
// any-cluster-member cancel means a single honest node is enough to
// block a hostile proposal — much stronger than requiring a counter-quorum.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::PhylanxError;
use crate::events::OracleRotationCancelled;
use crate::state::{OracleConfig, PendingOracleRotation};

#[derive(Accounts)]
pub struct CancelOracleKeyRotation<'info> {
    /// OracleConfig — read-only. Source of truth for "is the signer admin
    /// or a current cluster member?".
    #[account(
        seeds = [OracleConfig::SEED],
        bump  = oracle_config.bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,

    /// The pending rotation, closed on success; rent returned to proposer.
    #[account(
        mut,
        seeds = [PendingOracleRotation::SEED],
        bump  = pending_rotation.bump,
        has_one = proposer,
        close   = proposer,
    )]
    pub pending_rotation: Account<'info, PendingOracleRotation>,

    /// CHECK: the rent-refund target. Constrained to equal
    /// `pending_rotation.proposer` via the `has_one` above.
    #[account(mut)]
    pub proposer: SystemAccount<'info>,

    /// The canceller. Admin OR a current cluster member.
    pub canceller: Signer<'info>,
}

pub fn handler(ctx: Context<CancelOracleKeyRotation>) -> Result<()> {
    let oracle_config = &ctx.accounts.oracle_config;
    let canceller     = ctx.accounts.canceller.key();

    // ── Authorisation: admin OR live cluster member ────────────────────────
    // (Reuses NotRotationProposer for code economy — the two roles are
    // exactly the same as those who may PROPOSE. The audit-meaningful gate
    // is the same: who is trusted to participate in cluster governance.)
    let is_admin  = canceller == oracle_config.authority;
    let is_member = oracle_config.is_cluster_member(&canceller);
    require!(is_admin || is_member, PhylanxError::NotRotationProposer);

    let clock = Clock::get()?;
    emit!(OracleRotationCancelled {
        cancelled_by: canceller,
        proposer:     ctx.accounts.pending_rotation.proposer,
        cancelled_at: clock.unix_timestamp,
    });

    msg!(
        "oracle key rotation CANCELLED by {} — rent refunded to {}",
        canceller, ctx.accounts.pending_rotation.proposer,
    );
    Ok(())
}
