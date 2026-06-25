// =============================================================================
// programs/health-oracle/src/instructions/attest_oracle_key_rotation.rs
//
// VULN-13 — STEP 2 of the time-locked, N-of-M-attested key rotation ceremony.
//
// WHAT THIS DOES
// --------------
// Records the signer's attestation on the open `PendingOracleRotation`.
// Only members of the CURRENT `OracleConfig.oracle_keys` may attest;
// proposed-but-not-yet-current keys cannot. Double-attestation by the
// same key is rejected — each cluster member counts once.
//
// WHY ONLY CURRENT CLUSTER MEMBERS COUNT
// --------------------------------------
// The audit requirement is N-of-M of EXISTING oracle nodes signing. If
// attestation were open to proposed-future-keys, an attacker who
// compromised admin could (a) propose attacker-controlled new keys and
// then (b) "self-attest" with those same keys, bypassing the cluster's
// consent. Locking attestation to the LIVE cluster blocks that path.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::PhylanxError;
use crate::events::OracleRotationAttested;
use crate::state::{OracleConfig, PendingOracleRotation};

#[derive(Accounts)]
pub struct AttestOracleKeyRotation<'info> {
    /// OracleConfig — read-only. Source of truth for "is the signer in the
    /// current cluster?".
    #[account(
        seeds = [OracleConfig::SEED],
        bump  = oracle_config.bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,

    /// The pending rotation. Mutated to push a new attestation.
    #[account(
        mut,
        seeds = [PendingOracleRotation::SEED],
        bump  = pending_rotation.bump,
    )]
    pub pending_rotation: Account<'info, PendingOracleRotation>,

    /// The attester. Must be a current cluster member.
    pub attester: Signer<'info>,
}

pub fn handler(ctx: Context<AttestOracleKeyRotation>) -> Result<()> {
    let oracle_config = &ctx.accounts.oracle_config;
    let attester      = ctx.accounts.attester.key();

    // ── Authorisation: live cluster member only ────────────────────────────
    require!(
        oracle_config.is_cluster_member(&attester),
        PhylanxError::NotClusterMemberAttester,
    );

    let pending = &mut ctx.accounts.pending_rotation;

    // ── Reject double-attestation ──────────────────────────────────────────
    require!(
        !pending.has_attestation(&attester),
        PhylanxError::DuplicateAttestation,
    );

    pending.attestations.push(attester);

    let clock = Clock::get()?;
    let total    = pending.attestations.len() as u8;
    let required = (oracle_config.consensus_threshold()) as u8;

    emit!(OracleRotationAttested {
        attester,
        total_attestations:    total,
        required_attestations: required,
        attested_at:           clock.unix_timestamp,
    });

    msg!(
        "oracle key rotation ATTESTED by {} — {}/{} attestations",
        attester, total, required,
    );
    Ok(())
}
