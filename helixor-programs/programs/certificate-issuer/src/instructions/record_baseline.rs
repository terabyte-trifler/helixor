// =============================================================================
// programs/certificate-issuer/src/instructions/record_baseline.rs
//
// record_baseline — create or update the per-agent BaselineStats PDA.
//
//     seeds = ["baseline", agent_pubkey]
//
// The certificate-issuer needs the agent's baseline_hash on hand to stamp
// into each HealthCertificate. This instruction records it. `init_if_needed`
// is deliberate: a baseline ROTATES (every ~30 days), so the same PDA is
// created on the first call and updated on subsequent ones.
//
// VULN-06 — AUTHORITY MODEL (DAY-?? HARDENING)
// ---------------------------------------------
// Before this fix, the only writer was `issuer_config.issuer_node` — a
// single key. A single-key gate is a single point of compromise: lose that
// key and every agent's baseline can be silently rotated to anything. The
// audit's three mitigations are applied here:
//
//   1. BROADENED AUTHORITY — the signer must be EITHER
//        a) the agent itself (`signer == agent_wallet`), OR
//        b) one of the cluster signing keys (`is_cluster_key(signer)`).
//      The agent always retains the right to set its own baseline; a
//      compromise of the previous `issuer_node` alone is no longer
//      sufficient.
//
//   2. APPEND-ONLY EPOCH MONOTONICITY — once a baseline is recorded at
//      epoch E, a rotation MUST carry `epoch > E`. A second write in the
//      SAME epoch is refused (`BaselineRotationTooSoon`); a write at an
//      EARLIER epoch is refused (`BaselineEpochNotMonotonic`). An attacker
//      who briefly controls a cluster key cannot grind multiple rotations
//      through a single epoch.
//
//   3. NON-ZERO EPOCH — epoch=0 was previously unvalidated here. It is
//      now rejected, so the `epoch_recorded == 0` sentinel reliably means
//      "never recorded" and the first-record vs. rotation branch is safe.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::CertificateError;
use crate::events::BaselineRecorded;
use crate::state::{BaselineStats, IssuerConfig};

#[derive(Accounts)]
#[instruction(agent_wallet: Pubkey)]
pub struct RecordBaseline<'info> {
    /// The per-agent baseline record. Created on first call, updated after.
    #[account(
        init_if_needed,
        payer = issuer,
        space = BaselineStats::SPACE,
        seeds = [BaselineStats::SEED_PREFIX, agent_wallet.as_ref()],
        bump,
    )]
    pub baseline_stats: Account<'info, BaselineStats>,

    /// IssuerConfig — read to verify the signer is an authorised writer.
    /// (`is_cluster_key` matches against `cluster_keys`; checked in the
    /// handler because the "agent OR cluster member" rule cannot be
    /// expressed as a single Anchor constraint.)
    #[account(
        seeds = [IssuerConfig::SEED],
        bump  = issuer_config.bump,
    )]
    pub issuer_config: Account<'info, IssuerConfig>,

    /// The signer. Authorisation is enforced in the handler — see the
    /// "VULN-06" notes above.
    #[account(mut)]
    pub issuer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:                   Context<RecordBaseline>,
    agent_wallet:          Pubkey,
    baseline_hash:         [u8; 32],
    baseline_algo_version: u8,
    epoch:                 u64,
) -> Result<()> {
    // ── Validate inputs ─────────────────────────────────────────────────────
    require!(
        baseline_hash != [0u8; 32],
        CertificateError::ZeroBaselineHash,
    );
    require!(epoch >= 1, CertificateError::ZeroEpoch);

    // ── VULN-06 (1): authorisation — agent itself OR cluster member ────────
    let signer = ctx.accounts.issuer.key();
    require!(
        is_authorised_baseline_writer(
            &signer,
            &agent_wallet,
            &ctx.accounts.issuer_config,
        ),
        CertificateError::UnauthorizedBaselineWriter,
    );

    let clock = Clock::get()?;
    let stats = &mut ctx.accounts.baseline_stats;

    // ── VULN-06 (2): append-only epoch monotonicity ────────────────────────
    check_baseline_epoch_monotonic(stats.epoch_recorded, epoch)?;

    // ── Write ───────────────────────────────────────────────────────────────
    // On the first call this is a fresh account (all zero); on a rotation
    // it overwrites in place. agent_wallet + bump are idempotent to set.
    stats.agent_wallet          = agent_wallet;
    stats.baseline_hash         = baseline_hash;
    stats.baseline_algo_version = baseline_algo_version;
    stats.recorded_at           = clock.unix_timestamp;
    stats.recorder              = signer;
    stats.epoch_recorded        = epoch;
    stats.bump                  = ctx.bumps.baseline_stats;
    stats.layout_version        = BaselineStats::CURRENT_LAYOUT_VERSION;

    emit!(BaselineRecorded {
        agent_wallet,
        baseline_algo_version,
        epoch_recorded: epoch,
        recorder:       signer,
        recorded_at:    clock.unix_timestamp,
    });

    msg!(
        "baseline recorded for agent {} at epoch {} (algo v{})",
        agent_wallet, epoch, baseline_algo_version,
    );
    Ok(())
}

/// VULN-06 — pure authorisation predicate for `record_baseline`.
///
/// Returns true iff `signer` may write the baseline for `agent_wallet`
/// under `cfg`. Split from the handler so it is unit-testable without an
/// Anchor `Context`.
pub fn is_authorised_baseline_writer(
    signer:       &Pubkey,
    agent_wallet: &Pubkey,
    cfg:          &IssuerConfig,
) -> bool {
    signer == agent_wallet || cfg.is_cluster_key(signer)
}

/// VULN-06 — pure append-only / monotonic-epoch check.
///
/// `stored_epoch == 0` means "never recorded" (the BaselineStats account
/// is zero-initialised). The first record is always permitted; subsequent
/// rotations must carry a STRICTLY GREATER epoch than the stored one — a
/// same-epoch rotation maps to `BaselineRotationTooSoon`, an earlier one
/// to `BaselineEpochNotMonotonic`.
pub fn check_baseline_epoch_monotonic(
    stored_epoch: u64,
    new_epoch:    u64,
) -> Result<()> {
    if stored_epoch != 0 {
        require!(
            new_epoch != stored_epoch,
            CertificateError::BaselineRotationTooSoon,
        );
        require!(
            new_epoch > stored_epoch,
            CertificateError::BaselineEpochNotMonotonic,
        );
    }
    Ok(())
}
