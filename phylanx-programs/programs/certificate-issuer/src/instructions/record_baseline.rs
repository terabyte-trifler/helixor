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
//
// AW-03 — BASELINE COMMIT NONCE
// -----------------------------
// This handler now also takes `baseline_commit_nonce: u64` — the value of
// `AgentRegistration.commit_nonce` at which `baseline_hash` was committed
// on the health-oracle program. It is stored on the BaselineStats account
// and later stamped onto every HealthCertificate the cert-issuer writes,
// so a third-party verifier can derive the on-chain `BaselineDataAccount`
// PDA from `["baseline_data", agent, nonce_le]` and re-check
// `sha256(payload) == baseline_hash` without trusting the issuer cluster.
//
// The nonce is gated:
//   - must be non-zero (zero is the pre-AW-03 sentinel meaning
//     "no DA account exists"); refusing zero forces every fresh record
//     to carry a verifiable provenance pointer.
//   - must be STRICTLY GREATER than the previously-stored nonce — the
//     cluster cannot rewrite an old rotation's stats to point at a stale
//     DA account, mirroring the append-only epoch invariant.
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
    // AW-03: the AgentRegistration.commit_nonce the baseline_hash was
    // committed at on health-oracle. Stored on BaselineStats so the
    // certificate-issuer can stamp it onto every cert it writes, and a
    // third-party verifier can derive the BaselineDataAccount PDA from
    // `["baseline_data", agent, nonce_le]`.
    baseline_commit_nonce: u64,
) -> Result<()> {
    // ── Validate inputs ─────────────────────────────────────────────────────
    require!(
        baseline_hash != [0u8; 32],
        CertificateError::ZeroBaselineHash,
    );
    require!(epoch >= 1, CertificateError::ZeroEpoch);
    // AW-03: refuse a zero commit nonce — the on-chain DA account is keyed
    // by (agent, nonce), and `nonce == 0` is the pre-AW-03 sentinel meaning
    // "no DA account exists". Every fresh record must carry a verifiable
    // provenance pointer.
    require!(
        baseline_commit_nonce > 0,
        CertificateError::ZeroBaselineCommitNonce,
    );

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

    // ── AW-03: append-only commit_nonce monotonicity ───────────────────────
    // A same/lower nonce would let the cluster overwrite an old rotation's
    // stats with a stale DA pointer (the BaselineDataAccount at the old
    // PDA still exists on chain). Enforcing strict-> closes that drift.
    check_baseline_commit_nonce_monotonic(
        stats.baseline_commit_nonce,
        baseline_commit_nonce,
    )?;

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
    // AW-03: link this baseline record to its on-chain DA account.
    stats.baseline_commit_nonce = baseline_commit_nonce;
    // H-4: stamp the agent's FIRST-baseline timestamp exactly once, from the
    // tamper-proof on-chain Clock. On a rotation `first_recorded_at` is
    // already non-zero and is PRESERVED, so it remains a sound age anchor for
    // the NSS-3 GREEN-tier floor enforced in `issue_certificate`. (We cannot
    // anchor on `epoch`, which is caller-supplied and could be backdated.)
    if stats.first_recorded_at == 0 {
        stats.first_recorded_at = clock.unix_timestamp;
    }

    emit!(BaselineRecorded {
        agent_wallet,
        baseline_algo_version,
        epoch_recorded:        epoch,
        recorder:              signer,
        recorded_at:           clock.unix_timestamp,
        baseline_commit_nonce,
    });

    msg!(
        "baseline recorded for agent {} at epoch {} (algo v{}, commit_nonce {})",
        agent_wallet, epoch, baseline_algo_version, baseline_commit_nonce,
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

/// AW-03 — append-only / strict-monotonic check on `baseline_commit_nonce`.
///
/// `stored_nonce == 0` means "never recorded" or "pre-AW-03 legacy stats";
/// the first AW-03 record is always permitted. Subsequent records must
/// carry a STRICTLY GREATER nonce — equal or lower would let the cluster
/// overwrite the stats with a stale DA pointer (the BaselineDataAccount
/// at the lower nonce still exists on chain).
pub fn check_baseline_commit_nonce_monotonic(
    stored_nonce: u64,
    new_nonce:    u64,
) -> Result<()> {
    if stored_nonce != 0 {
        require!(
            new_nonce > stored_nonce,
            CertificateError::BaselineCommitNonceNotMonotonic,
        );
    }
    Ok(())
}
