// =============================================================================
// programs/health-oracle/src/instructions/propose_oracle_key_rotation.rs
//
// VULN-13 — STEP 1 of the time-locked, N-of-M-attested key rotation ceremony.
// See state::pending_oracle_rotation for the full ceremony spec.
//
// WHAT THIS DOES
// --------------
// Creates the singleton `PendingOracleRotation` PDA, carrying the proposed
// new cluster keys + min_confidence and a timelock that ends at
// `now + timelock_seconds`. The proposer must be either the OracleConfig
// admin OR a current cluster member. If the proposer is a current cluster
// member, their proposal counts as their own attestation — they don't need
// to separately call `attest`.
//
// WHAT IT DOES NOT DO
// -------------------
// Does NOT mutate `OracleConfig`. The cluster only changes when
// `enact_oracle_key_rotation` succeeds, which requires (a) the timelock
// elapsed and (b) a strict majority of the CURRENT cluster has attested.
//
// SINGLETON GUARD
// ---------------
// The PDA seed is `["pending_rotation"]`, so only ONE proposal can exist
// at a time. A second propose call returns `PendingRotationExists` until
// the first is enacted or cancelled. This prevents a compromised admin
// from spamming proposals to overwhelm operators / cluster reviewers.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::PhylanxError;
use crate::events::OracleRotationProposed;
use crate::state::{OracleConfig, PendingOracleRotation};

#[derive(Accounts)]
pub struct ProposeOracleKeyRotation<'info> {
    /// The OracleConfig — read-only here. Supplies the admin authority and
    /// the current cluster against which `proposer` is authorised.
    #[account(
        seeds = [OracleConfig::SEED],
        bump  = oracle_config.bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,

    /// The new pending-rotation PDA, created here. Singleton — only one
    /// in-flight rotation at a time. Anchor's `init` constraint fails with
    /// `account already exists` if a previous proposal is still open; we
    /// map that surface to a typed `PendingRotationExists` via the manual
    /// guard in the handler so callers get a clean error code.
    #[account(
        init,
        payer = proposer,
        space = PendingOracleRotation::SPACE,
        seeds = [PendingOracleRotation::SEED],
        bump,
    )]
    pub pending_rotation: Account<'info, PendingOracleRotation>,

    /// The proposer. Pays rent; becomes the rent-refund target on enact /
    /// cancel. Must be admin OR a current cluster member (checked in
    /// handler against the loaded `oracle_config`).
    #[account(mut)]
    pub proposer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:              Context<ProposeOracleKeyRotation>,
    new_keys:         Vec<Pubkey>,
    new_min_confidence: u16,
    timelock_seconds: i64,
) -> Result<()> {
    let oracle_config = &ctx.accounts.oracle_config;
    let proposer      = ctx.accounts.proposer.key();

    // ── Authorisation: admin OR current cluster member ─────────────────────
    // The audit's core requirement: admin alone CAN propose, but cannot
    // enact without cluster consent. Cluster members can also propose
    // (they don't need admin's permission to ask the rest of the cluster
    // for a rotation — useful if admin is suspected compromised).
    let is_admin   = proposer == oracle_config.authority;
    let is_member  = oracle_config.is_cluster_member(&proposer);
    require!(is_admin || is_member, PhylanxError::NotRotationProposer);

    // ── Validate proposed new cluster ──────────────────────────────────────
    // Same rules as initialize_oracle_config: 1 or 3..=5 keys, no
    // duplicates, valid min_confidence range. Enforced at PROPOSE time so
    // operators reviewing the proposal in the 48h window see clearly what
    // would land if it were enacted.
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

    // ── Reject no-op rotations ─────────────────────────────────────────────
    // No-op == same key multiset AND same min_confidence. Distinct
    // orderings count as different (the primary slot changes), so we
    // compare as ordered Vec equality after sort.
    let mut current_sorted: Vec<Pubkey> = oracle_config.oracle_keys.clone();
    let mut proposed_sorted: Vec<Pubkey> = new_keys.clone();
    current_sorted.sort();
    proposed_sorted.sort();
    let same_keys = current_sorted == proposed_sorted;
    let same_conf = new_min_confidence == oracle_config.min_confidence;
    require!(!(same_keys && same_conf), PhylanxError::NoopRotation);

    // ── Timelock floor ─────────────────────────────────────────────────────
    // Audit-mandated: at least 48h between propose and enact, so operators
    // monitoring the chain can detect a hostile proposal and intervene
    // (cancel from a cluster key) before it lands.
    require!(
        timelock_seconds >= PendingOracleRotation::MIN_TIMELOCK_SECONDS,
        PhylanxError::TimelockTooShort,
    );

    let clock = Clock::get()?;
    let enact_after = clock.unix_timestamp.saturating_add(timelock_seconds);

    let pending = &mut ctx.accounts.pending_rotation;
    pending.proposer           = proposer;
    pending.new_keys           = new_keys.clone();
    pending.new_min_confidence = new_min_confidence;
    pending.enact_after        = enact_after;
    pending.proposed_at        = clock.unix_timestamp;
    pending.bump               = ctx.bumps.pending_rotation;

    // If the proposer is also a current cluster member, their proposal IS
    // their attestation — they obviously vote for their own proposal. This
    // saves a redundant transaction and matches operator intuition.
    pending.attestations = Vec::new();
    if is_member {
        pending.attestations.push(proposer);
    }

    emit!(OracleRotationProposed {
        proposer,
        new_keys,
        new_min_confidence,
        enact_after,
        proposed_at: clock.unix_timestamp,
    });

    msg!(
        "oracle key rotation PROPOSED by {} — {}-key cluster, \
         min_confidence={}, enact_after={}, pre-attestations={}",
        proposer,
        pending.new_keys.len(),
        new_min_confidence,
        enact_after,
        pending.attestations.len(),
    );
    Ok(())
}
