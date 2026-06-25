// =============================================================================
// programs/health-oracle/src/instructions/enact_oracle_key_rotation.rs
//
// VULN-13 — STEP 3 of the time-locked, N-of-M-attested key rotation ceremony.
//
// WHAT THIS DOES
// --------------
// Applies a fully-vetted `PendingOracleRotation` to the live `OracleConfig`
// and closes the proposal PDA (refunding rent to the original proposer).
//
// GATES (all must hold)
//   1. `now >= pending.enact_after`   — the 48h+ timelock has elapsed.
//   2. `pending.attestations.len() >= consensus_threshold(current_cluster)`
//                                     — a strict majority of the LIVE
//                                       cluster has attested.
//   3. The proposed `new_keys` still pass the structural validation
//      (size, no duplicates, valid min_confidence). Redundant against
//      the propose-time check, but DEFENCE IN DEPTH — never trust state
//      that another instruction wrote.
//
// WHO CAN CALL
// ------------
// ANY signer. By the time both gates hold the proposal is fully ratified,
// and we want the lowest-friction path possible for an honest cluster
// member or a third-party watcher to land it. The economic actor is the
// proposer (rent refunded to them); the signer just pays the transaction.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::PhylanxError;
use crate::events::OracleRotationEnacted;
use crate::state::{OracleConfig, PendingOracleRotation};

#[derive(Accounts)]
pub struct EnactOracleKeyRotation<'info> {
    /// OracleConfig — mutated to install the new cluster.
    #[account(
        mut,
        seeds = [OracleConfig::SEED],
        bump  = oracle_config.bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,

    /// The pending rotation. Closed on success; rent refunded to `proposer`.
    /// `close = proposer` requires that the account we pass as `proposer`
    /// is exactly the pubkey recorded inside `pending_rotation.proposer`.
    /// We enforce that match via an explicit `has_one` constraint, which
    /// also serves as a typed-error surface if a caller passes the wrong
    /// account.
    #[account(
        mut,
        seeds = [PendingOracleRotation::SEED],
        bump  = pending_rotation.bump,
        has_one = proposer,
        close   = proposer,
    )]
    pub pending_rotation: Account<'info, PendingOracleRotation>,

    /// CHECK: the rent-refund target. Constrained to equal
    /// `pending_rotation.proposer` via the `has_one` above. No further
    /// validation required (this is a pure SOL recipient).
    #[account(mut)]
    pub proposer: SystemAccount<'info>,

    /// Anyone may finalise a ratified proposal.
    pub enactor: Signer<'info>,
}

pub fn handler(ctx: Context<EnactOracleKeyRotation>) -> Result<()> {
    let clock = Clock::get()?;
    let now   = clock.unix_timestamp;

    let cluster_len = ctx.accounts.oracle_config.oracle_keys.len();

    // Snapshot the proposal fields BEFORE we start mutating OracleConfig.
    // `pending_rotation` will be closed at end-of-instruction via the
    // `close = proposer` constraint, so we copy out the values we need.
    let pending = &ctx.accounts.pending_rotation;
    let new_keys           = pending.new_keys.clone();
    let new_min_confidence = pending.new_min_confidence;
    let enact_after        = pending.enact_after;
    let attestation_count  = pending.attestations.len();

    // ── Gate 1: timelock ───────────────────────────────────────────────────
    require!(now >= enact_after, PhylanxError::TimelockNotElapsed);

    // ── Gate 2: N-of-M attestations against LIVE cluster ───────────────────
    require!(
        pending.is_enactable(now, cluster_len),
        PhylanxError::InsufficientAttestations,
    );

    // ── Defence-in-depth: re-validate the proposed cluster structure ───────
    // The propose handler already enforced these, but state on chain can
    // be reasoned about only by the program that owns it; re-checking
    // here ensures a malformed PendingOracleRotation (somehow written by
    // a future buggy instruction) cannot land an invalid cluster.
    require!(
        !new_keys.is_empty()
            && new_keys.len() <= OracleConfig::MAX_ORACLE_KEYS,
        PhylanxError::InvalidClusterSize,
    );
    require!(new_keys.len() != 2, PhylanxError::InvalidClusterSize);
    for i in 0..new_keys.len() {
        for j in (i + 1)..new_keys.len() {
            require!(
                new_keys[i] != new_keys[j],
                PhylanxError::DuplicateOracleKey,
            );
        }
    }
    require!(
        new_min_confidence <= 1000,
        PhylanxError::InvalidMinConfidence,
    );

    // ── Apply ──────────────────────────────────────────────────────────────
    let oracle_config = &mut ctx.accounts.oracle_config;
    let old_keys           = oracle_config.oracle_keys.clone();
    let old_min_confidence = oracle_config.min_confidence;

    oracle_config.oracle_keys    = new_keys.clone();
    oracle_config.oracle_node    = new_keys[0];         // primary
    oracle_config.min_confidence = new_min_confidence;

    emit!(OracleRotationEnacted {
        enactor:            ctx.accounts.enactor.key(),
        old_keys,
        new_keys,
        old_min_confidence,
        new_min_confidence,
        enacted_at:         now,
    });

    msg!(
        "oracle key rotation ENACTED by {} — {}-key cluster, primary={}, \
         min_confidence={}, attestations={}",
        ctx.accounts.enactor.key(),
        oracle_config.oracle_keys.len(),
        oracle_config.oracle_node,
        new_min_confidence,
        attestation_count,
    );
    Ok(())
}
